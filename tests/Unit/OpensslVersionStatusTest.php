<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Cli\Tool;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * `diag`: OpenSSL library versions below the CVE-2026-35189 fix of their branch (OpenSSL advisory
 * of 2026-09-29) give a warning that leaves room for a distribution backport.
 */
final class OpensslVersionStatusTest extends TestCase
{
    /**
     * @return iterable<string, array{0: string, 1: bool, 2: string}>
     */
    public static function versions(): iterable
    {
        // [library version text, OK?, fixed release named in the warning]
        yield '3.0.0' => ['OpenSSL 3.0.0 7 sep 2021', false, '3.0.23'];
        yield '3.0.22' => ['OpenSSL 3.0.22 1 Jul 2026', false, '3.0.23'];
        yield '3.0.23' => ['OpenSSL 3.0.23 29 Sep 2026', true, ''];
        yield '3.4.7' => ['OpenSSL 3.4.7 1 Jul 2026', false, '3.4.8'];
        yield '3.4.8' => ['OpenSSL 3.4.8 29 Sep 2026', true, ''];
        yield '3.5.0' => ['OpenSSL 3.5.0 8 Apr 2025', false, '3.5.9'];
        yield '3.5.7' => ['OpenSSL 3.5.7 9 Jun 2026', false, '3.5.9'];
        yield '3.5.8' => ['OpenSSL 3.5.8 1 Jul 2026', false, '3.5.9'];
        yield '3.5.9' => ['OpenSSL 3.5.9 29 Sep 2026', true, ''];
        yield '3.5.10' => ['OpenSSL 3.5.10 1 Jan 2027', true, ''];
        yield '3.6.4' => ['OpenSSL 3.6.4 1 Jul 2026', false, '3.6.5'];
        yield '3.6.5' => ['OpenSSL 3.6.5 29 Sep 2026', true, ''];
        yield '4.0.2' => ['OpenSSL 4.0.2 1 Jul 2026', false, '4.0.3'];
        yield '4.0.3' => ['OpenSSL 4.0.3 29 Sep 2026', true, ''];
        yield '4.0.12' => ['OpenSSL 4.0.12 1 Jan 2028', true, ''];
        // distribution suffix after the upstream version
        yield 'distro 3.0.22' => ['OpenSSL 3.0.22-0ubuntu1 1 Jul 2026', false, '3.0.23'];
        yield 'distro 3.0.23' => ['OpenSSL 3.0.23+deb12u1 29 Sep 2026', true, ''];
        // branches the advisory does not list: no claim either way (no false warning)
        yield '3.1.8' => ['OpenSSL 3.1.8 11 Feb 2025', true, ''];
        yield '3.2.6' => ['OpenSSL 3.2.6 1 Oct 2025', true, ''];
        yield '3.3.5' => ['OpenSSL 3.3.5 1 Oct 2025', true, ''];
        yield '4.1.0' => ['OpenSSL 4.1.0 1 Apr 2027', true, ''];
        yield '30.0.1' => ['OpenSSL 30.0.1 1 Jan 2099', true, ''];
        yield 'LibreSSL' => ['LibreSSL 3.5.2', true, ''];
        yield 'BoringSSL' => ['BoringSSL', true, ''];
        yield 'unparsable' => ['OpenSSL 3.5', true, ''];
    }

    #[DataProvider('versions')]
    public function testCve202635189Warning(string $text, bool $ok, string $fixed): void
    {
        [$isOk, $msg] = Tool::opensslVersionStatus($text);
        self::assertSame($ok, $isOk, $text);
        self::assertStringStartsWith($text, $msg, 'the library version is always shown');
        if ($ok) {
            self::assertSame($text, $msg);
        } else {
            self::assertSame($text . ' - below ' . $fixed . ' (CVE-2026-35189) unless the distribution backported the fix', $msg);
        }
    }

    public function testExistingWarningFor357IsUnchanged(): void
    {
        self::assertSame(
            [false, 'OpenSSL 3.5.7 9 Jun 2026 - below 3.5.9 (CVE-2026-35189) unless the distribution backported the fix'],
            Tool::opensslVersionStatus('OpenSSL 3.5.7 9 Jun 2026')
        );
    }
}
