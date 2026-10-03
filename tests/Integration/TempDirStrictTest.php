<?php

declare(strict_types=1);

namespace MimeShield\Tests\Integration;

use MimeShield\Config;
use MimeShield\Crypto\CmsService;
use MimeShield\Crypto\SecureTemp;
use MimeShield\Exception\MimeShieldException;
use MimeShield\Exception\ValidationException;
use MimeShield\Services;
use MimeShield\Tests\TestPki;
use PHPUnit\Framework\TestCase;

/**
 * Audit I-15: with mimeshield_temp_dir_strict an unusable configured temp directory refuses every
 * operation that writes message plaintext to temp files instead of using the system temp directory.
 */
final class TempDirStrictTest extends TestCase
{
    private const CONTENT = "Content-Type: text/plain\r\n\r\nSECRET-PLAINTEXT\r\n";

    private string $tmp = '';

    /** @var list<string> */
    private array $shown = [];

    protected function setUp(): void
    {
        if (!MIMESHIELD_RC_LOADED) {
            self::markTestSkipped('needs Roundcube (MIMESHIELD_RC)');
        }
        $this->tmp = TestPki::tempDir();
        $_SESSION = [];
        $_GET = [];
        $_POST = [];
    }

    protected function tearDown(): void
    {
        SecureTemp::refuseBaseDir(null);
        $_SESSION = [];
        $_GET = [];
        $_POST = [];
        if ($this->tmp !== '') {
            foreach (['/mimeshield/no-default-ca', '/mimeshield', ''] as $sub) {
                foreach (glob($this->tmp . $sub . '/*') ?: [] as $f) {
                    if (is_file($f)) {
                        unlink($f);
                    }
                }
                if (is_dir($this->tmp . $sub)) {
                    rmdir($this->tmp . $sub);
                }
            }
        }
    }

    public function testStrictWithUnusableDirectoryRefusesSignEncryptDecryptAndVerify(): void
    {
        // prepared while the directory is usable
        $usable = new CmsService($this->tmp);
        $sig = $usable->signDetached(self::CONTENT, TestPki::cert('alice'), TestPki::key('alice'));
        $env = $usable->encrypt(self::CONTENT, [TestPki::cert('alice')]);

        $cfg = self::config(['mimeshield_temp_dir' => $this->tmp . '/missing', 'mimeshield_temp_dir_strict' => true]);
        self::assertTrue($cfg->tempDirRefused());
        $cms = new CmsService($cfg->tempBaseDir());

        $ops = [
            'sign' => fn () => $cms->signDetached(self::CONTENT, TestPki::cert('alice'), TestPki::key('alice')),
            'encrypt' => fn () => $cms->encrypt(self::CONTENT, [TestPki::cert('alice')]),
            'decrypt' => fn () => $cms->decrypt($env, TestPki::cert('alice'), TestPki::key('alice')),
            'verify' => fn () => $cms->verifyDetached(self::CONTENT, $sig),
        ];
        foreach ($ops as $name => $op) {
            try {
                $op();
                self::fail($name . ' must be refused');
            } catch (ValidationException $e) {
                // a MimeShieldException: IncomingProcessor shows it as the S/MIME status of the part
                self::assertSame('tempdirunavailable', $e->getUserLabel(), $name);
            }
        }
        self::assertDirectoryDoesNotExist($this->tmp . '/missing');
    }

    public function testStrictWithUsableDirectoryWorks(): void
    {
        $cfg = self::config(['mimeshield_temp_dir' => $this->tmp, 'mimeshield_temp_dir_strict' => true]);
        self::assertFalse($cfg->tempDirRefused());
        self::assertSame(realpath($this->tmp), $cfg->tempBaseDir());
        $cms = new CmsService($cfg->tempBaseDir());
        $sig = $cms->signDetached(self::CONTENT, TestPki::cert('alice'), TestPki::key('alice'));
        self::assertTrue($cms->verifyDetached(self::CONTENT, $sig)->valid);
    }

    public function testNonStrictFallsBackToTheSystemTempDirectory(): void
    {
        // a previous strict configuration in the same process does not leak into this one
        self::config(['mimeshield_temp_dir' => $this->tmp . '/missing', 'mimeshield_temp_dir_strict' => true])->tempBaseDir();

        $cfg = self::config(['mimeshield_temp_dir' => $this->tmp . '/missing']);
        self::assertTrue($cfg->tempDirIsFallback());
        self::assertFalse($cfg->tempDirRefused());
        $base = $cfg->tempBaseDir();
        self::assertSame(realpath(sys_get_temp_dir()), $base);
        $t = new SecureTemp($base);
        $t->file('x');
        self::assertSame(1, $t->count());
        $t->cleanup();
    }

    public function testSendIsAbortedWithTheTempDirectoryMessage(): void
    {
        require_once dirname(__DIR__, 2) . '/mimeshield.php';
        foreach ([[], ['_draft' => '1']] as $extra) {
            $this->shown = [];
            $_POST = ['_mimeshield_sign' => '1', '_mimeshield_encrypt' => '0'] + $extra;
            try {
                $this->plugin()->message_ready(['message' => new \Mail_mime(['eol' => "\r\n"])]);
                self::fail('the send must be aborted');
            } catch (\RuntimeException $e) {
                self::assertSame('send aborted', $e->getMessage());
            }
            self::assertSame(['mimeshield.tempdirunavailable'], $this->shown);
        }
    }

    public function testMessageExistsInEveryLocalization(): void
    {
        foreach (['en_US', 'pl_PL'] as $lang) {
            $messages = [];
            $labels = [];
            include dirname(__DIR__, 2) . '/localization/' . $lang . '.inc';
            self::assertNotEmpty($messages['tempdirunavailable'] ?? null, $lang);
        }
    }

    private function plugin(): \mimeshield
    {
        $cfg = self::rcConfig([
            'mimeshield_temp_dir' => $this->tmp . '/missing',
            'mimeshield_temp_dir_strict' => true,
            'mimeshield_enable_signing' => true,
        ]);
        $rc = (new \ReflectionClass(\rcmail::class))->newInstanceWithoutConstructor();
        (new \ReflectionProperty(\rcube::class, 'texts'))->setValue($rc, [
            'mimeshield.tempdirunavailable' => 'x', 'mimeshield.internalerror' => 'x',
        ]);
        $shown = &$this->shown;
        $rc->output = new class ($shown) {
            /** @param list<string> $shown */
            public function __construct(private array &$shown)
            {
            }

            public function show_message(string $label, string $type = 'notice', ?array $vars = null): void
            {
                $this->shown[] = $label;
            }

            public function command(string $cmd, mixed ...$args): void
            {
            }

            public function send(?string $templ = null): never
            {
                throw new \RuntimeException('send aborted');
            }
        };
        $plugin = (new \ReflectionClass(\mimeshield::class))->newInstanceWithoutConstructor();
        (new \ReflectionProperty(\mimeshield::class, 'rc'))->setValue($plugin, $rc);
        (new \ReflectionProperty(\mimeshield::class, 'services'))->setValue($plugin, new Services(\rcube::get_instance(), new Config($cfg)));
        return $plugin;
    }

    /** @param array<string, mixed> $values */
    private static function config(array $values): Config
    {
        return new Config(self::rcConfig($values));
    }

    /** @param array<string, mixed> $values */
    private static function rcConfig(array $values): \rcube_config
    {
        return new class ($values) extends \rcube_config {
            /** @param array<string, mixed> $values */
            public function __construct(private readonly array $values)
            {
            }

            public function get($name, $def = null)
            {
                return array_key_exists($name, $this->values) ? $this->values[$name] : $def;
            }
        };
    }
}
