<?php

declare(strict_types=1);

namespace MimeShield\Tests\Integration;

use MimeShield\Config;
use MimeShield\Services;
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

    private static function store(): SharedCacheCrlNumberStore
    {
        // a fresh cache object per call, like a new request (or another server)
        return new SharedCacheCrlNumberStore(\rcube_cache::factory('db', null, SharedCacheCrlNumberStore::PREFIX, SharedCacheCrlNumberStore::TTL));
    }

    public function testNumberIsWrittenToTheSharedTableImmediately(): void
    {
        self::assertNull(self::store()->get('k1'));
        self::store()->put('k1', '0100');
        self::assertSame('0100', self::store()->get('k1'));

        $row = $this->db->fetch_assoc($this->db->query('SELECT * FROM ' . $this->db->table_name('cache_shared', true) . ' WHERE cache_key = ?',
            SharedCacheCrlNumberStore::PREFIX . '.k1'));
        self::assertIsArray($row);
        // rcube_cache caps the TTL at 30 days
        $expires = strtotime($row['expires'] . ' UTC');
        self::assertGreaterThan(time() + 29 * 86400, $expires);
        self::assertLessThanOrEqual(time() + 30 * 86400 + 60, $expires);
    }

    public function testInvalidEntriesAreIgnored(): void
    {
        $cache = \rcube_cache::factory('db', null, SharedCacheCrlNumberStore::PREFIX, SharedCacheCrlNumberStore::TTL);
        $cache->set('a', 'FF');
        $cache->set('b', ['n' => 'not hex', 't' => time()]);
        $cache->set('c', ['n' => 17, 't' => time()]);
        $cache->close();
        foreach (['a', 'b', 'c'] as $k) {
            self::assertNull(self::store()->get($k), $k);
        }
    }

    public function testEntryOlderThanADayIsRewrittenOnRead(): void
    {
        $cache = \rcube_cache::factory('db', null, SharedCacheCrlNumberStore::PREFIX, SharedCacheCrlNumberStore::TTL);
        $cache->set('k', ['n' => '10', 't' => time() - 2 * 86400]);
        $cache->close();
        self::assertSame('10', self::store()->get('k'));

        $check = \rcube_cache::factory('db', null, SharedCacheCrlNumberStore::PREFIX, SharedCacheCrlNumberStore::TTL);
        $v = $check->get('k');
        self::assertSame('10', $v['n']);
        self::assertGreaterThanOrEqual(time() - 5, $v['t'], 'read refreshes the high-water mark of a rarely re-issued CRL');
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
