<?php

declare(strict_types=1);

namespace MimeShield\Tests\Integration;

use MimeShield\Config;
use MimeShield\Services;
use MimeShield\Ui\ComposeUi;
use PHPUnit\Framework\TestCase;

/**
 * Audit F-09: with mimeshield_require_encrypt_for_decrypted the real mimeshield::message_ready hook
 * refuses to send or save a compose that was opened with decrypted content unless it is encrypted -
 * decided server-side from the session, whatever the compose form posts.
 */
final class DecryptedReplyPolicyTest extends TestCase
{
    /** @var list<string> */
    private array $shown = [];

    protected function setUp(): void
    {
        if (!MIMESHIELD_RC_LOADED) {
            self::markTestSkipped('needs Roundcube (MIMESHIELD_RC)');
        }
        require_once dirname(__DIR__, 2) . '/mimeshield.php';
        $_SESSION = [];
        $_GET = [];
        $_POST = ['_id' => 'compose-1', '_mimeshield_sign' => '0', '_mimeshield_encrypt' => '0'];
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
        $_GET = [];
        $_POST = [];
    }

    /** @param array<string, mixed> $extra */
    private function plugin(bool $required, array $extra = []): \mimeshield
    {
        $values = ['mimeshield_require_encrypt_for_decrypted' => $required] + $extra;
        $cfg = new class ($values) extends \rcube_config {
            /** @param array<string, mixed> $values */
            public function __construct(private readonly array $values)
            {
            }

            public function get($name, $def = null)
            {
                return array_key_exists($name, $this->values) ? $this->values[$name] : $def;
            }
        };

        $rc = (new \ReflectionClass(\rcmail::class))->newInstanceWithoutConstructor();
        (new \ReflectionProperty(\rcube::class, 'texts'))->setValue($rc, [
            'mimeshield.decryptedplaintext' => 'x', 'mimeshield.internalerror' => 'x', 'mimeshield.protectionunavailable' => 'x',
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

    /**
     * @return array<string, mixed>
     */
    private static function params(): array
    {
        return ['message' => new \Mail_mime(['eol' => "\r\n"])];
    }

    public function testUnencryptedSendOfDecryptedComposeIsRefusedWhenRequired(): void
    {
        ComposeUi::markDecryptedCompose('compose-1');
        try {
            $this->plugin(true)->message_ready(self::params());
            self::fail('the send must be aborted');
        } catch (\RuntimeException $e) {
            self::assertSame('send aborted', $e->getMessage());
        }
        self::assertSame(['mimeshield.decryptedplaintext'], $this->shown);
    }

    public function testUnencryptedDraftOfDecryptedComposeIsRefusedWhenRequired(): void
    {
        ComposeUi::markDecryptedCompose('compose-1');
        $_POST['_draft'] = '1';
        try {
            $this->plugin(true)->message_ready(self::params());
            self::fail('the draft save must be aborted');
        } catch (\RuntimeException $e) {
            self::assertSame('send aborted', $e->getMessage());
        }
        self::assertSame(['mimeshield.decryptedplaintext'], $this->shown);
    }

    public function testEncryptedDraftIsRefusedWhenDraftsAreNotEncrypted(): void
    {
        ComposeUi::markDecryptedCompose('compose-1');
        $_POST['_draft'] = '1';
        $_POST['_mimeshield_encrypt'] = '1';
        try {
            // mimeshield_encrypt_drafts = false would store the "encrypted" draft in plaintext
            $this->plugin(true, ['mimeshield_encrypt_drafts' => false])->message_ready(self::params());
            self::fail('the plaintext draft save must be aborted');
        } catch (\RuntimeException $e) {
            self::assertSame('send aborted', $e->getMessage());
        }
        self::assertSame(['mimeshield.decryptedplaintext'], $this->shown);
    }

    public function testActiveComposeRemainsProtectedAfterRecentMarkerEviction(): void
    {
        $_SESSION['compose_data_compose-1'] = ['id' => 'compose-1'];
        ComposeUi::markDecryptedCompose('compose-1');
        for ($i = 0; $i < 60; $i++) {
            ComposeUi::markDecryptedCompose('another-' . $i);
        }
        try {
            $this->plugin(true)->message_ready(self::params());
            self::fail('active compose protection must outlive the bounded recent lookup');
        } catch (\RuntimeException $e) {
            self::assertSame('send aborted', $e->getMessage());
        }
        self::assertSame(['mimeshield.decryptedplaintext'], $this->shown);
    }

    public function testOtherComposesAndDisabledPolicyAreNotAffected(): void
    {
        ComposeUi::markDecryptedCompose('another-compose');
        $p = self::params();
        self::assertSame($p, $this->plugin(true)->message_ready($p), 'compose without decrypted content');

        ComposeUi::markDecryptedCompose('compose-1');
        self::assertSame($p, $this->plugin(false)->message_ready($p), 'policy off (default)');
        self::assertSame([], $this->shown);
    }

    public function testMissingSchemaCannotBypassTheDecryptedComposePolicy(): void
    {
        ComposeUi::markDecryptedCompose('compose-1');
        try {
            $this->plugin(true)->message_ready_unavailable(self::params());
            self::fail('schema outage must not allow decrypted content to leave unencrypted');
        } catch (\RuntimeException $e) {
            self::assertSame('send aborted', $e->getMessage());
        }
        self::assertSame(['mimeshield.protectionunavailable'], $this->shown);
    }
}
