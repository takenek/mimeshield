<?php

declare(strict_types=1);

namespace MimeShield\Tests\Integration;

use MimeShield\Config;
use MimeShield\Services;
use MimeShield\Storage\Database;
use MimeShield\Tests\TestPki;
use MimeShield\Ui\MessageUi;
use PHPUnit\Framework\TestCase;

/**
 * I-17: the action gate must run before touching IMAP or re-verifying the message; it limits the
 * session and (across sessions) the user account.
 */
final class MessageSaveCertLimitTest extends TestCase
{
    private string $dir;
    private Database $db;

    protected function setUp(): void
    {
        if (!MIMESHIELD_RC_LOADED || !extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('needs Roundcube and pdo_sqlite');
        }
        require_once dirname(__DIR__, 2) . '/mimeshield.php';
        $_POST = ['_uid' => '1', '_mbox' => 'INBOX'];
        $_SESSION = [];
        $this->dir = TestPki::tempDir();
        $raw = \rcube_db::factory('sqlite:///' . $this->dir . '/rc.db?mode=0600');
        $raw->set_debug(false);
        $raw->db_connect('w');
        $this->db = new Database($raw);
        $this->db->query('INSERT INTO users (user_id, username, mail_host, created) VALUES (?, ?, ?, ?)',
            1, 'account1', 'localhost', Database::now());
    }

    protected function tearDown(): void
    {
        $_POST = [];
        $_SESSION = [];
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

    public function testExhaustedWindowStopsBeforeStorageAndFreshWindowReachesStorage(): void
    {
        [$rc, $ui] = $this->build();

        $_SESSION['mimeshield_rl_savecert'] = array_fill(0, 20, time());
        $this->runAction($ui);
        self::assertSame(['mimeshield.ratelimited'], $rc->output->messages);
        self::assertSame(0, $rc->storage->calls);
        self::assertCount(20, $_SESSION['mimeshield_rl_savecert']);

        $_SESSION['mimeshield_rl_savecert'] = array_fill(0, 20, time() - 61);
        $this->runAction($ui);
        self::assertSame(1, $rc->storage->calls, 'the expired quota must not prevent normal requests');
        self::assertCount(1, $_SESSION['mimeshield_rl_savecert']);
    }

    public function testAccountLimitAppliesAcrossSessions(): void
    {
        [$rc, $ui] = $this->build();

        // 20 requests spread over fresh sessions: each session is far below its own limit
        for ($i = 0; $i < 20; $i++) {
            $_SESSION = [];
            $this->runAction($ui);
        }
        self::assertSame(20, $rc->storage->calls);
        self::assertNotContains('mimeshield.ratelimited', $rc->output->messages);

        // a new session does not reset the per-account quota
        $_SESSION = [];
        $rc->output->messages = [];
        $this->runAction($ui);
        self::assertSame(['mimeshield.ratelimited'], $rc->output->messages);
        self::assertSame(20, $rc->storage->calls, 'the account limit must stop before IMAP');
    }

    /**
     * @return array{0: \rcmail, 1: MessageUi}
     */
    private function build(): array
    {
        $rc = (new \ReflectionClass(\rcmail::class))->newInstanceWithoutConstructor();
        $rc->user = new class () {
            public int $ID = 1;

            /** @return array<string, mixed> */
            public function get_prefs(): array
            {
                return [];
            }
        };
        $rc->storage = new class () {
            public int $calls = 0;

            public function set_folder(string $folder): void
            {
                $this->calls++;
                throw new \RuntimeException('stop before IMAP');
            }
        };
        $rc->output = new class () {
            /** @var list<string> */
            public array $messages = [];

            public function show_message(string $message, string $type): void
            {
                $this->messages[] = $message;
            }

            public function send(): never
            {
                throw new \RuntimeException('response sent');
            }
        };
        $plugin = (new \ReflectionClass(\mimeshield::class))->newInstanceWithoutConstructor();
        (new \ReflectionProperty(\mimeshield::class, 'rc'))->setValue($plugin, $rc);
        $services = new Services($rc, new Config(new \rcube_config()));
        (new \ReflectionProperty(Services::class, 'db'))->setValue($services, $this->db);
        (new \ReflectionProperty(\mimeshield::class, 'services'))->setValue($plugin, $services);
        return [$rc, new MessageUi($plugin)];
    }

    private function runAction(MessageUi $ui): void
    {
        try {
            $ui->saveCertAction();
            self::fail('the action should send a response');
        } catch (\RuntimeException $e) {
            self::assertSame('response sent', $e->getMessage());
        }
    }
}
