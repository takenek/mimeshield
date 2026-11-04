<?php

declare(strict_types=1);

namespace MimeShield\Tests\Integration;

use MimeShield\Config;
use MimeShield\Services;
use MimeShield\Exception\StorageException;
use MimeShield\Storage\Database;
use MimeShield\Tests\TestPki;
use MimeShield\Trust\RevocationChecker;
use MimeShield\Trust\SharedCacheCrlNumberStore;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * cRLNumber high-water marks in Roundcube's shared cache (audit I-02) and the Services wiring of the
 * CRL policy (SHA-1 CRLs follow mimeshield_legacy_digests, audit I-09).
 */
final class SharedCacheCrlNumberStoreTest extends TestCase
{
    private string $dir;
    private \rcube_db $db;
    private mixed $previousDb = null;

    /** @var list<\rcube_db> */
    private array $connections = [];

    protected function setUp(): void
    {
        if (!MIMESHIELD_RC_LOADED || !extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('needs Roundcube and pdo_sqlite');
        }
        $GLOBALS['mimeshield_test_log'] = [];
        $this->dir = TestPki::tempDir();
        $this->db = \rcube_db::factory('sqlite:///' . $this->dir . '/rc.db?mode=0600');
        $this->db->set_debug(false);
        $this->db->db_connect('w');
        $this->previousDb = \rcube::get_instance()->db;
        \rcube::get_instance()->db = $this->db;
    }

    protected function tearDown(): void
    {
        foreach ($this->connections as $c) {
            $c->closeConnection();
        }
        $this->connections = [];
        if (isset($this->db)) {
            \rcube::get_instance()->db = $this->previousDb;
            $this->db->closeConnection();
        }
        if (isset($this->dir)) {
            foreach (glob($this->dir . '/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($this->dir);
        }
    }

    private function store(): SharedCacheCrlNumberStore
    {
        // a fresh connection per call, like a new request (or another server)
        $raw = \rcube_db::factory('sqlite:///' . $this->dir . '/rc.db?mode=0600');
        $raw->set_debug(false);
        $raw->db_connect('w');
        $this->connections[] = $raw;
        return new SharedCacheCrlNumberStore(new Database($raw));
    }

    /**
     * @return list<array<string, ?string>>
     */
    private function rows(string $key): array
    {
        return (new Database($this->db))->fetchAll('SELECT `expires`, `data` FROM ' . $this->db->table_name('cache_shared', true) . ' WHERE `cache_key` = ?',
            SharedCacheCrlNumberStore::PREFIX . '.' . $key);
    }

    private function insertRaw(string $key, string $data, int $expires): void
    {
        (new Database($this->db))->query('INSERT INTO ' . $this->db->table_name('cache_shared', true) . ' (`cache_key`, `expires`, `data`) VALUES (?, ?, ?)',
            SharedCacheCrlNumberStore::PREFIX . '.' . $key, Database::datetime($expires), $data);
    }

    public function testNumberIsWrittenToTheSharedTableImmediatelyAsJson(): void
    {
        self::assertNull($this->store()->get('k1'));
        $this->store()->put('k1', '0100');
        self::assertSame('0100', $this->store()->get('k1'));

        $rows = $this->rows('k1');
        self::assertCount(1, $rows);
        $v = json_decode((string) $rows[0]['data'], true);
        self::assertSame('0100', $v['n'], 'JSON, never serialize() (audit V-04)');
        self::assertEqualsWithDelta(time(), $v['t'], 5);
        $expires = strtotime($rows[0]['expires'] . ' UTC');
        self::assertEqualsWithDelta(time() + SharedCacheCrlNumberStore::TTL_SECONDS, $expires, 60);
    }

    public function testPutNeverLowersTheStoredNumber(): void
    {
        $this->store()->put('k', '0100');
        $this->store()->put('k', 'FF');     // lower
        self::assertSame('0100', $this->store()->get('k'));
        $this->store()->put('k', '0100');   // equal: no change
        self::assertSame('0100', $this->store()->get('k'));
        $this->store()->put('k', '0101');   // higher
        self::assertSame('0101', $this->store()->get('k'));
        self::assertCount(1, $this->rows('k'), 'updates in place');
    }

    /**
     * Audit V-02: the refresh of a mark read after a day renews the expiry only; a higher number written
     * by another request between that read and the refresh is never overwritten.
     */
    public function testRefreshNeverOverwritesAHigherNumber(): void
    {
        $this->insertRaw('k', json_encode(['n' => '10', 't' => time() - 2 * 86400]), time() + 86400);
        $other = $this->store();
        $other->put('k', '20');                       // another server raised the mark
        self::assertSame('20', $this->store()->get('k'));
        // a row holding the stale value no longer exists, so a stale reader can refresh nothing
        $rows = $this->rows('k');
        self::assertCount(1, $rows);
        self::assertSame('20', json_decode((string) $rows[0]['data'], true)['n']);
    }

    public function testEntryOlderThanADayIsRefreshedOnReadWithoutChangingTheNumber(): void
    {
        $this->insertRaw('k', json_encode(['n' => '10', 't' => time() - 2 * 86400]), time() + 86400);
        self::assertSame('10', $this->store()->get('k'));
        $rows = $this->rows('k');
        self::assertCount(1, $rows);
        $v = json_decode((string) $rows[0]['data'], true);
        self::assertSame('10', $v['n']);
        self::assertEqualsWithDelta(time(), $v['t'], 5, 'read refreshes the high-water mark of a rarely re-issued CRL');
        self::assertEqualsWithDelta(time() + SharedCacheCrlNumberStore::TTL_SECONDS, strtotime($rows[0]['expires'] . ' UTC'), 60);
    }

    public function testInvalidAndLegacyEntriesAreIgnored(): void
    {
        $this->insertRaw('a', 'FF', time() + 86400);
        $this->insertRaw('b', json_encode(['n' => 'not hex', 't' => time()]), time() + 86400);
        $this->insertRaw('c', json_encode(['n' => 17, 't' => time()]), time() + 86400);
        $this->insertRaw('d', json_encode(['n' => 'FF', 't' => 'x']), time() + 86400);
        $this->insertRaw('e', serialize(['n' => 'FF', 't' => time()]), time() + 86400);   // format of earlier plugin versions
        foreach (['a', 'b', 'c', 'd', 'e'] as $k) {
            self::assertNull($this->store()->get($k), $k);
        }
        // a legacy row does not block a new mark; the maximum over all rows of the key is used
        $this->store()->put('e', '0100');
        self::assertSame('0100', $this->store()->get('e'));
    }

    public function testOneRowPerKeyIsGuaranteedByTheSchemaAndARowOfAnotherWriterIsOnlyRaised(): void
    {
        // cache_key is the primary key of cache_shared in every Roundcube schema (sqlite, mysql,
        // postgres): the INSERT of the second of two concurrent first writers fails ...
        $this->insertRaw('k', json_encode(['n' => '0100', 't' => time()]), time() + 86400);
        try {
            $this->insertRaw('k', json_encode(['n' => 'FF', 't' => time()]), time() + 86400);
            self::fail('cache_key must be unique');
        } catch (StorageException) {
        }
        // ... and put() then works on the winner's row: a lower number leaves it, a higher one raises it
        $this->store()->put('k', '00FF');
        self::assertSame('0100', $this->store()->get('k'));
        self::assertCount(1, $this->rows('k'));
        $this->store()->put('k', '0101');
        self::assertSame('0101', $this->store()->get('k'));
        self::assertCount(1, $this->rows('k'));
    }

    /**
     * @return iterable<string, array{0: list<string>, 1: bool}>
     */
    public static function legacyDigestCases(): iterable
    {
        yield 'default (sha1 legacy)' => [['sha1'], true];
        yield 'sha1 removed' => [[], false];
    }

    /**
     * @param list<string> $legacy
     */
    #[DataProvider('legacyDigestCases')]
    public function testServicesWireTheCrlPolicy(array $legacy, bool $acceptSha1): void
    {
        $cfg = new \rcube_config();
        $cfg->set('mimeshield_revocation', 'crl');
        $cfg->set('mimeshield_legacy_digests', $legacy);
        $checker = (new Services(\rcube::get_instance(), new Config($cfg)))->revocation();
        self::assertSame($acceptSha1, (new \ReflectionProperty(RevocationChecker::class, 'acceptSha1'))->getValue($checker));
        self::assertInstanceOf(SharedCacheCrlNumberStore::class, (new \ReflectionProperty(RevocationChecker::class, 'crlNumbers'))->getValue($checker));
    }

    public function testNoNumberStoreWithoutRevocationChecking(): void
    {
        $checker = (new Services(\rcube::get_instance(), new Config(new \rcube_config())))->revocation();
        self::assertNull((new \ReflectionProperty(RevocationChecker::class, 'crlNumbers'))->getValue($checker));
    }
}
