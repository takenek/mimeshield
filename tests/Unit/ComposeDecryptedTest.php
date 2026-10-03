<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Config;
use MimeShield\Ui\ComposeUi;
use PHPUnit\Framework\TestCase;

/**
 * Audit F-09: the server remembers which compose sessions hold decrypted content (the send hook
 * enforces mimeshield_require_encrypt_for_decrypted on that, not on the compose form).
 */
final class ComposeDecryptedTest extends TestCase
{
    protected function setUp(): void
    {
        $_SESSION = [];
    }

    protected function tearDown(): void
    {
        $_SESSION = [];
    }

    public function testDecryptedComposeIsRememberedPerComposeId(): void
    {
        self::assertFalse(ComposeUi::isDecryptedCompose('abc'));
        ComposeUi::markDecryptedCompose('abc');
        self::assertTrue(ComposeUi::isDecryptedCompose('abc'));
        self::assertFalse(ComposeUi::isDecryptedCompose('other'));
        self::assertFalse(ComposeUi::isDecryptedCompose(''));
        ComposeUi::markDecryptedCompose('');
        self::assertFalse(ComposeUi::isDecryptedCompose(''));
    }

    public function testRememberedComposesAreBounded(): void
    {
        for ($i = 0; $i < 60; $i++) {
            ComposeUi::markDecryptedCompose('id' . $i);
        }
        self::assertFalse(ComposeUi::isDecryptedCompose('id0'), 'oldest entries are dropped');
        self::assertTrue(ComposeUi::isDecryptedCompose('id59'));
        self::assertCount(50, $_SESSION['mimeshield_decrypted_compose']);
    }

    public function testPolicyIsOffByDefault(): void
    {
        self::assertFalse(Config::DEFAULTS['mimeshield_require_encrypt_for_decrypted']);
    }

    public function testAnActiveComposeRetainsProtectionWhenTheRecentLookupIsFull(): void
    {
        $_SESSION['compose_data_original'] = ['id' => 'original'];
        ComposeUi::markDecryptedCompose('original');
        for ($i = 0; $i < 60; $i++) {
            ComposeUi::markDecryptedCompose('new' . $i);
        }
        self::assertArrayNotHasKey('original', $_SESSION['mimeshield_decrypted_compose']);
        self::assertTrue(ComposeUi::isDecryptedCompose('original'));
        unset($_SESSION['compose_data_original']);
        self::assertFalse(ComposeUi::isDecryptedCompose('original'), 'core cleanup releases the persistent marker');
    }
}
