<?php

declare(strict_types=1);

namespace MimeShield\Tests\Integration;

use MimeShield\Mime\IncomingProcessor;
use MimeShield\Mime\PartStatus;
use MimeShield\Crypto\SignatureCheck;
use MimeShield\Services;
use MimeShield\Tests\TestPki;
use MimeShield\Trust\ChainResult;
use MimeShield\Trust\RevocationResult;
use MimeShield\Trust\VerificationResult;
use MimeShield\Ui\MessageUi;
use PHPUnit\Framework\TestCase;

/**
 * Audit F-10: an S/MIME indicator in the header area (outside the message content), shown for every
 * message - including a neutral "not signed" state - and never for single header values.
 */
final class MessageHeaderBadgeTest extends TestCase
{
    protected function setUp(): void
    {
        if (!MIMESHIELD_RC_LOADED) {
            self::markTestSkipped('needs Roundcube (MIMESHIELD_RC)');
        }
        require_once dirname(__DIR__, 2) . '/mimeshield.php';
    }

    /**
     * @param null|array<string, PartStatus> $statuses null: no message was processed by the plugin
     */
    private static function ui(?array $statuses): MessageUi
    {
        $services = (new \ReflectionClass(Services::class))->newInstanceWithoutConstructor();
        (new \ReflectionProperty(Services::class, 'rc'))->setValue($services, \rcube::get_instance());
        if ($statuses !== null) {
            $proc = (new \ReflectionClass(IncomingProcessor::class))->newInstanceWithoutConstructor();
            (new \ReflectionProperty(IncomingProcessor::class, 'status'))->setValue($proc, $statuses);
            (new \ReflectionProperty(Services::class, 'incoming'))->setValue($services, $proc);
        }
        $plugin = new class () extends \mimeshield {
            public Services $s;

            public function __construct()
            {
            }

            public function services(): Services
            {
                return $this->s;
            }

            public function text(string $label, array $vars = []): string
            {
                return '[' . $label . ']';
            }
        };
        $plugin->s = $services;
        return new MessageUi($plugin);
    }

    public function testUnsignedMessageGetsANeutralIndicator(): void
    {
        foreach ([null, []] as $statuses) {
            $html = self::ui($statuses)->headerBadge();
            self::assertStringContainsString('mimeshield-badge-none', $html);
            self::assertStringContainsString('[badge_none]', $html);
        }
    }

    public function testEncryptedUnsignedMessageIsAWarning(): void
    {
        $st = new PartStatus('0');
        $st->decryption = true;
        $html = self::ui(['0' => $st])->headerBadge();
        self::assertStringContainsString('mimeshield-badge-warning', $html);
        self::assertStringContainsString('[badge_warning]', $html);
    }

    public function testOnlyNestedStatusIsPartial(): void
    {
        $st = new PartStatus('2');
        $st->partial = true;
        $st->signatureError = 'sig_notverifiable';
        $html = self::ui(['2' => $st])->headerBadge();
        self::assertStringContainsString('[badge_partial]', $html);
    }

    public function testBadgeIsAddedToTheHeaderBlockOnly(): void
    {
        $ui = self::ui([]);
        $p = $ui->messageHeaders(['name' => 'messageHeaders', 'content' => '<table></table>']);
        self::assertStringStartsWith('<table></table>', $p['content']);
        self::assertStringContainsString('role="status"', $p['content']);

        $subject = $ui->messageHeaders(['name' => 'messageHeaders', 'valueof' => 'subject', 'content' => 'Subject']);
        self::assertSame('Subject', $subject['content']);
    }

    /**
     * Audit I-11: outdated content encryption is a warning, never a full OK.
     */
    public function testOutdatedCipherIsAWarning(): void
    {
        $st = new PartStatus('0');
        $st->decryption = true;
        $st->cipher = 'des-ede3-cbc';
        $html = self::ui(['0' => $st])->render($st);
        self::assertStringContainsString('[enc_weakcipher]', $html);
        self::assertStringContainsString('mimeshield-level-warning', $html);

        // a cipher outside the known AES set (raw OID from the inspector) is never shown as fully OK
        $st->cipher = '1.2.3.4.5';
        self::assertStringContainsString('[enc_weakcipher]', self::ui(['0' => $st])->render($st));
        $st->cipher = 'aes-256-gcm';
        self::assertStringNotContainsString('[enc_weakcipher]', self::ui(['0' => $st])->render($st));
    }

    public function testDisabledRevocationHasAnExplicitWarningOutsideTheBody(): void
    {
        foreach ([false, true] as $encrypted) {
            $st = new PartStatus('0');
            $st->decryption = $encrypted ? true : null;
            $st->signature = new VerificationResult(
                new SignatureCheck(true, SignatureCheck::FAIL_NONE, [], [], null, null, false),
                TestPki::cert('alice'), new ChainResult(ChainResult::TRUSTED, []),
                VerificationResult::IDENTITY_MATCH, VerificationResult::TIME_VALID, true,
                new RevocationResult(RevocationResult::NOT_CHECKED, 'disabled'), false, false, false, [],
            );
            $ui = self::ui(['0' => $st]);
            self::assertSame(VerificationResult::LEVEL_OK, $st->signature->level(), 'trust policy remains unchanged');
            $html = $ui->headerBadge();
            self::assertStringContainsString('mimeshield-badge-warning', $html);
            self::assertStringContainsString('[badge_norevocation]', $html);
            $evaluate = new \ReflectionMethod(MessageUi::class, 'evaluate');
            [, $level, $headline] = $evaluate->invoke($ui, $st);
            self::assertSame('warning', $level);
            self::assertSame($encrypted ? 'status_sig_norevocation_enc' : 'status_sig_norevocation', $headline);
        }
    }
}
