<?php

declare(strict_types=1);

namespace MimeShield\Tests\Integration;

use MimeShield\Config;
use MimeShield\Mime\IncomingProcessor;
use MimeShield\Mime\PartStatus;
use MimeShield\Service\KeyService;
use MimeShield\Services;
use MimeShield\Ui\ComposeUi;
use PHPUnit\Framework\TestCase;

/** F-09: decrypted content needs an identity/recipient warning even in an encrypted reply. */
final class ComposeWarningTest extends TestCase
{
    protected function setUp(): void
    {
        if (!MIMESHIELD_RC_LOADED) {
            self::markTestSkipped('needs Roundcube (MIMESHIELD_RC)');
        }
        require_once dirname(__DIR__, 2) . '/mimeshield.php';
        $_SESSION = [];
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
        (new \ReflectionProperty(ComposeUi::class, 'state'))->setValue(null, ['restore' => null, 'force' => false]);
    }

    private static function ui(bool $decrypted, bool $optionsEnabled = true, ?object &$output = null): ComposeUi
    {
        $rc = (new \ReflectionClass(\rcmail::class))->newInstanceWithoutConstructor();
        $rc->output = $output = new class () {
            private array $env = ['compose_id' => 'warning-compose', 'save_localstorage' => true];

            public function get_env(string $name): mixed
            {
                return $this->env[$name] ?? null;
            }

            public function set_env(string $name, mixed $value): void
            {
                $this->env[$name] = $value;
            }
        };
        $rc->user = new class () {
            public function list_identities(): array
            {
                return [];
            }
        };
        $cfg = new \rcube_config();
        $cfg->set('mimeshield_enable_signing', $optionsEnabled);
        $cfg->set('mimeshield_enable_encryption', $optionsEnabled);
        $services = new Services($rc, new Config($cfg));
        (new \ReflectionProperty(Services::class, 'keys'))->setValue($services,
            (new \ReflectionClass(KeyService::class))->newInstanceWithoutConstructor());
        $incoming = (new \ReflectionClass(IncomingProcessor::class))->newInstanceWithoutConstructor();
        $st = new PartStatus('1');
        $st->decryption = $decrypted ? true : null;
        (new \ReflectionProperty(IncomingProcessor::class, 'status'))->setValue($incoming, ['1' => $st]);
        (new \ReflectionProperty(Services::class, 'incoming'))->setValue($services, $incoming);
        $plugin = new class ($rc, $services) extends \mimeshield {
            public function __construct(private readonly \rcmail $mail, private readonly Services $graph)
            {
            }

            public function rcmail(): \rcmail
            {
                return $this->mail;
            }

            public function services(): Services
            {
                return $this->graph;
            }

            public function text(string $label, array $vars = []): string
            {
                return '[' . $label . '] <safe-text>';
            }
        };
        return new ComposeUi($plugin);
    }

    public function testDecryptedComposeWarnsBeforeRecipientsAreSelected(): void
    {
        foreach (['reply', 'forward', 'edit'] as $mode) {
            $ui = self::ui(true);
            $ui->composeBody(['mode' => $mode]);
            $html = $ui->optionsHtml();
            self::assertTrue(ComposeUi::isDecryptedCompose('warning-compose'));
            self::assertSame(1, substr_count($html, 'id="mimeshield-decrypted-warning"'));
            self::assertStringContainsString('role="alert"', $html);
            self::assertStringContainsString('[decryptedreplywarning]', $html);
            self::assertStringNotContainsString('<safe-text>', $html);
        }
    }

    public function testWarningRemainsWhenSigningAndEncryptionOptionsAreDisabled(): void
    {
        $ui = self::ui(true, false);
        $ui->composeBody(['mode' => 'reply']);
        self::assertStringContainsString('[decryptedreplywarning]', $ui->optionsHtml());
    }

    public function testOrdinaryComposeHasNoDecryptedWarning(): void
    {
        $ui = self::ui(false);
        $ui->composeBody(['mode' => 'reply']);
        self::assertFalse(ComposeUi::isDecryptedCompose('warning-compose'));
        self::assertStringNotContainsString('[decryptedreplywarning]', $ui->optionsHtml());
    }

    public function testDecryptedComposeIsNeverKeptInBrowserLocalStorage(): void
    {
        // Roundcube stores compose bodies unencrypted in localStorage and restores them into a new,
        // unmarked compose - which would bypass mimeshield_require_encrypt_for_decrypted (F-09)
        self::ui(true, true, $out)->composeBody(['mode' => 'reply']);
        self::assertFalse($out->get_env('save_localstorage'));

        self::ui(false, true, $plain)->composeBody(['mode' => 'reply']);
        self::assertTrue($plain->get_env('save_localstorage'), 'ordinary compose keeps the core setting');
    }
}
