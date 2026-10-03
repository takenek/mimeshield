<?php

declare(strict_types=1);

namespace MimeShield\Tests\Integration;

use MimeShield\Cert\KeyImporter;
use MimeShield\Config;
use MimeShield\Exception\StorageException;
use MimeShield\KeyStore\KeyVault;
use MimeShield\KeyStore\MasterKeyProvider;
use MimeShield\Service\KeyService;
use MimeShield\Services;
use MimeShield\Storage\Database;
use MimeShield\Storage\KeyRepository;
use MimeShield\Tests\TestPki;
use MimeShield\Ui\SettingsUi;
use PHPUnit\Framework\TestCase;

/** I-04/I-10: exercise the actual settings handlers with local SQLite and Roundcube classes. */
final class SettingsActionsTest extends TestCase
{
    private \rcmail $rc;
    private Services $services;
    private SettingsUi $ui;
    private string $dir;

    protected function setUp(): void
    {
        if (!MIMESHIELD_RC_LOADED) {
            self::markTestSkipped('needs Roundcube (MIMESHIELD_RC)');
        }
        require_once dirname(__DIR__, 2) . '/mimeshield.php';
        $_SESSION = $_GET = $_POST = $_REQUEST = $_FILES = [];
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST['_token'] = 'settings-test-token';
        unset($_SERVER['HTTP_X_ROUNDCUBE_REQUEST']);
        $this->dir = TestPki::tempDir();
        $this->rc = new class extends \rcmail {
            public function __construct() {}
            public function get_request_token() { return 'settings-test-token'; }
            public function gettext($attrib, $domain = null) { return is_array($attrib) ? $attrib['name'] : $attrib; }
            public function text_exists($name, $domain = null, &$ref_domain = null) { return true; }
            public function url($p, $absolute = false, $full = false, $secure = false) { return './'; }
        };
        $this->rc->output = new class {
            public string $type = 'js';
            public array $messages = [];
            public string $form = '';
            public function show_message($label, $type = 'notice', $vars = null): void { $this->messages[] = $label; }
            public function command($command, ...$args): void {}
            public function send($template = null): never { throw new \RuntimeException('response complete'); }
            public function form_tag($attrib, $content): never {
                $this->form = $content;
                throw new \RuntimeException('form rendered');
            }
        };
        $cfg = new class extends \rcube_config {
            public function __construct() {}
            public function get($name, $default = null) { return $default; }
        };
        $this->services = new Services($this->rc, new Config($cfg));
        $plugin = (new \ReflectionClass(\mimeshield::class))->newInstanceWithoutConstructor();
        (new \ReflectionProperty(\mimeshield::class, 'rc'))->setValue($plugin, $this->rc);
        (new \ReflectionProperty(\mimeshield::class, 'services'))->setValue($plugin, $this->services);
        $this->ui = new SettingsUi($plugin);
    }

    protected function tearDown(): void
    {
        $_SESSION = $_GET = $_POST = $_REQUEST = $_FILES = [];
        unset($_SERVER['REQUEST_METHOD']);
        if (isset($this->dir)) {
            foreach (glob($this->dir . '/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($this->dir);
        }
    }

    private function invoke(string $method): string
    {
        try {
            (new \ReflectionMethod(SettingsUi::class, $method))->invoke($this->ui);
        } catch (\RuntimeException $e) {
            return $e->getMessage();
        }
        return '';
    }

    public function testConfirmationWithoutPendingFileIsRefusedBeforeUpload(): void
    {
        $_POST['_confirm'] = '1';
        self::assertSame('response complete', $this->invoke('certImport'));
        self::assertSame(['mimeshield.savecertrefused'], $this->rc->output->messages);
    }

    public function testStaleConfirmationCannotConsumeAnotherTabsFile(): void
    {
        $_SESSION['mimeshield_pending_cert'] = base64_encode('second public file');
        $_POST['_confirm'] = '1';
        $_POST['_pending_digest'] = hash('sha256', 'first public file');
        self::assertSame('response complete', $this->invoke('certImport'));
        self::assertSame(['mimeshield.savecertrefused'], $this->rc->output->messages);
        self::assertSame(base64_encode('second public file'), $_SESSION['mimeshield_pending_cert']);
    }

    public function testGetOfImportFormPreservesPendingConfirmation(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SESSION['mimeshield_pending_cert'] = base64_encode('pending public file');
        self::assertSame('form rendered', $this->invoke('certImport'));
        self::assertSame(base64_encode('pending public file'), $_SESSION['mimeshield_pending_cert']);
    }

    public function testConfirmationFormBindsToWholePendingPublicFile(): void
    {
        $digest = hash('sha256', 'pending public file');
        try {
            (new \ReflectionMethod(SettingsUi::class, 'confirmReplaceForm'))->invoke($this->ui, [], $digest);
        } catch (\RuntimeException $e) {
            self::assertSame('form rendered', $e->getMessage());
        }
        self::assertStringContainsString('name="_pending_digest"', $this->rc->output->form);
        self::assertStringContainsString('value="' . $digest . '"', $this->rc->output->form);
        $_SESSION['mimeshield_pending_cert'] = base64_encode('pending public file');
        $method = new \ReflectionMethod(SettingsUi::class, 'takePendingCertificate');
        self::assertSame('pending public file', $method->invoke(null, $digest));
        self::assertNull($method->invoke(null, $digest), 'confirmation cannot be replayed');
    }

    /** @return array{Database, KeyRepository, int} */
    private function bindings(): array
    {
        $raw = \rcube_db::factory('sqlite:///' . $this->dir . '/settings.db?mode=0600');
        $raw->db_connect('w');
        self::assertNull($raw->is_error());
        self::assertTrue((bool) $raw->exec_script((string) file_get_contents(dirname(__DIR__, 2) . '/SQL/sqlite.initial.sql')));
        $db = new Database($raw);
        $db->query('INSERT INTO users (user_id, username, mail_host, created) VALUES (?, ?, ?, ?)', 1, 'settings-test', 'localhost', Database::now());
        $identities = [];
        foreach ([1, 2] as $id) {
            $db->query('INSERT INTO identities (identity_id, user_id, changed, email) VALUES (?, ?, ?, ?)', $id, 1, Database::now(), 'alice@example.test');
            $identities[] = ['identity_id' => $id, 'email' => 'alice@example.test'];
        }
        $this->rc->user = new class ($identities) {
            public function __construct(public array $identities) {}
            public function list_identities(): array { return $this->identities; }
        };
        $repo = new KeyRepository($db, 1);
        $key = $repo->insert(TestPki::cert('alice'), [], 'unused', 'unused', 1);
        $keys = new KeyService($repo, new KeyVault(new MasterKeyProvider('', '')), new KeyImporter(), null, 25);
        (new \ReflectionProperty(Services::class, 'db'))->setValue($this->services, $db);
        (new \ReflectionProperty(Services::class, 'keys'))->setValue($this->services, $keys);
        $_POST['_id'] = (string) $key;
        $_POST['_identities'] = ['1', '2'];
        return [$db, $repo, $key];
    }

    public function testAllBindingsAreCommittedTogether(): void
    {
        [, $repo, $key] = $this->bindings();
        self::assertSame('response complete', $this->invoke('bind'));
        self::assertSame([1 => $key, 2 => $key], $repo->bindings());
    }

    public function testLaterInvalidIdentityDoesNotSaveEarlierBinding(): void
    {
        [, $repo] = $this->bindings();
        $this->rc->user->identities[1]['email'] = 'other@example.test';
        self::assertSame('response complete', $this->invoke('bind'));
        self::assertSame([], $repo->bindings());
        self::assertSame(['mimeshield.bind_wrongaddress'], $this->rc->output->messages);
    }

    public function testDatabaseFailureRollsBackEarlierWrites(): void
    {
        [$db, $repo] = $this->bindings();
        $db->query("CREATE TRIGGER refuse_second_binding BEFORE INSERT ON mimeshield_bindings WHEN NEW.identity_id = 2 BEGIN SELECT RAISE(ABORT, 'test write failure'); END");
        $db->raw()->set_option('ignore_errors', true);
        try {
            (new \ReflectionMethod(SettingsUi::class, 'bind'))->invoke($this->ui);
            self::fail('a database failure must abort the batch');
        } catch (StorageException) {
            self::assertSame([], $repo->bindings());
            self::assertSame([], $this->rc->output->messages, 'no success confirmation');
        }
    }

    public function testBeginFailureDoesNotRunWrites(): void
    {
        $raw = $this->createMock(\rcube_db::class);
        $raw->expects(self::once())->method('startTransaction')->willReturn(false);
        $raw->expects(self::never())->method('endTransaction');
        $this->expectException(StorageException::class);
        (new Database($raw))->transaction(static function (): void { self::fail('write must not run'); });
    }
}
