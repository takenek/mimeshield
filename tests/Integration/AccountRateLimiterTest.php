<?php

declare(strict_types=1);

namespace MimeShield\Tests\Integration;

use MimeShield\RateLimiter;
use MimeShield\Storage\Database;
use MimeShield\Tests\TestPki;
use PHPUnit\Framework\TestCase;

/** F-08: reservations are committed and shared before work, including concurrent sessions. */
final class AccountRateLimiterTest extends TestCase
{
    private string $dir;
    private string $dsn;
    private Database $db;

    protected function setUp(): void
    {
        if (!MIMESHIELD_RC_LOADED || !extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('needs Roundcube and pdo_sqlite');
        }
        $this->dir = TestPki::tempDir();
        $this->dsn = 'sqlite:///' . $this->dir . '/rc.db?mode=0600';
        $raw = \rcube_db::factory($this->dsn);
        $raw->set_debug(false);
        $raw->db_connect('w');
        $this->db = new Database($raw);
        foreach ([1, 2] as $id) {
            $this->db->query('INSERT INTO users (user_id, username, mail_host, created) VALUES (?, ?, ?, ?)',
                $id, 'account' . $id, 'localhost', Database::now());
        }
    }

    protected function tearDown(): void
    {
        if (isset($this->db)) {
            $this->db->raw()->closeConnection();
        }
        if (isset($this->dir)) {
            foreach (glob($this->dir . '/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($this->dir);
        }
    }

    public function testFreshConnectionsShareCommittedQuotaAndAccountsAreIsolated(): void
    {
        foreach ([true, true, false] as $index => $expected) {
            $raw = \rcube_db::factory($this->dsn);
            try {
                self::assertSame($expected, RateLimiter::allowForUser(new Database($raw), 1, 'keyimport', 2, 60, 1000 + $index));
            } finally {
                $raw->closeConnection();
            }
        }
        self::assertTrue(RateLimiter::allowForUser($this->db, 2, 'keyimport', 2, 60, 1002));
        self::assertTrue(RateLimiter::allowForUser($this->db, 1, 'keyimport', 2, 60, 1061));
        self::assertFalse(RateLimiter::allowForUser($this->db, 99, 'keyimport', 2, 60, 1061));
    }

    public function testFailedStorageWriteRefusesAttemptAndRollsBackPreviousState(): void
    {
        self::assertTrue(RateLimiter::allowForUser($this->db, 1, 'keyimport', 2, 60, 1000));
        $before = $this->db->fetchOne('SELECT data FROM cache WHERE user_id = 1');
        $this->db->query("CREATE TRIGGER reject_quota BEFORE INSERT ON cache BEGIN SELECT RAISE(ABORT, 'test quota failure'); END");
        $this->db->raw()->set_option('ignore_errors', true);
        try {
            self::assertFalse(RateLimiter::allowForUser($this->db, 1, 'keyimport', 2, 60, 1001));
        } finally {
            $this->db->raw()->set_option('ignore_errors', false);
        }
        self::assertSame($before, $this->db->fetchOne('SELECT data FROM cache WHERE user_id = 1'));
    }

    public function testClockRollbackDoesNotDiscardAnExistingAccountReservation(): void
    {
        self::assertTrue(RateLimiter::allowForUser($this->db, 1, 'keyimport', 1, 60, 1001));
        self::assertFalse(RateLimiter::allowForUser($this->db, 1, 'keyimport', 1, 60, 1000));
        self::assertFalse(RateLimiter::allowForUser($this->db, 1, 'keyimport', 1, 60, 1060));
        self::assertTrue(RateLimiter::allowForUser($this->db, 1, 'keyimport', 1, 60, 1061));
    }

    public function testConcurrentSessionsCannotReserveTheSameLastSlot(): void
    {
        self::assertTrue($this->db->raw()->startTransaction());
        $this->db->query('UPDATE users SET user_id = user_id WHERE user_id = 1');
        $children = [];
        try {
            foreach ([1, 2] as $id) {
                $ready = $this->dir . '/ready' . $id;
                $script = $this->dir . '/request' . $id . '.php';
                file_put_contents($script, '<?php require ' . var_export(dirname(__DIR__) . '/bootstrap.php', true) . ';'
                    . '$db = new MimeShield\Storage\Database(rcube_db::factory(' . var_export($this->dsn, true) . '));'
                    . 'touch(' . var_export($ready, true) . ');'
                    . 'exit(MimeShield\RateLimiter::allowForUser($db, 1, "keyimport", 1, 60, 1000) ? 0 : 2);');
                $proc = proc_open([PHP_BINARY, $script], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null,
                    ['MIMESHIELD_RC' => (string) getenv('MIMESHIELD_RC')]);
                self::assertIsResource($proc);
                $children[] = [$proc, $pipes];
            }
            $until = microtime(true) + 3;
            while ((!is_file($this->dir . '/ready1') || !is_file($this->dir . '/ready2')) && microtime(true) < $until) {
                usleep(10000);
            }
            self::assertFileExists($this->dir . '/ready1');
            self::assertFileExists($this->dir . '/ready2');
        } finally {
            self::assertTrue($this->db->raw()->endTransaction());
        }
        $codes = [];
        foreach ($children as [$proc, $pipes]) {
            $output = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $codes[] = proc_close($proc);
            self::assertSame('', $output);
        }
        sort($codes);
        self::assertSame([0, 2], $codes, 'exactly one of two concurrent sessions reserves the last slot');
        self::assertFalse(RateLimiter::allowForUser($this->db, 1, 'keyimport', 1, 60, 1001));
    }
}
