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
        // branches the advisory does not list: no CVE claim either way (end-of-life is a separate check)
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
        // a date before any branch of the table reached its end of life: only the CVE table applies
        [$isOk, $msg] = Tool::opensslVersionStatus($text, '2024-06-01');
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

    /**
     * Audit V-14: branches past their upstream security support are warned about (the F-16 decision to
     * stay silent about 3.1-3.3 is withdrawn): they never received the 2026 CMS/PKCS#12 fixes.
     *
     * @return iterable<string, array{0: string, 1: string, 2: bool, 3: string}>
     */
    public static function endOfLife(): iterable
    {
        // [library version text, today, OK?, end-of-support date named in the warning]
        yield '3.1.8 after EOL' => ['OpenSSL 3.1.8 11 Feb 2025', '2026-11-04', false, '2025-03-14'];
        yield '3.2.6 after EOL' => ['OpenSSL 3.2.6 1 Oct 2025', '2026-11-04', false, '2025-11-23'];
        yield '3.3.5 after EOL' => ['OpenSSL 3.3.5 1 Oct 2025', '2026-11-04', false, '2026-04-09'];
        yield '3.3.5 before EOL' => ['OpenSSL 3.3.5 1 Oct 2025', '2026-04-09', true, ''];
        yield '1.1.1w' => ['OpenSSL 1.1.1w 11 Sep 2023', '2026-11-04', false, '2023-09-11'];
        yield '3.0.23 (fixed, public support over)' => ['OpenSSL 3.0.23 29 Sep 2026', '2026-11-04', false, '2026-09-07'];
        yield '3.0.22 (CVE warning wins)' => ['OpenSSL 3.0.22 1 Jul 2026', '2026-11-04', false, ''];
        yield '3.4.8 after EOL' => ['OpenSSL 3.4.8 29 Sep 2026', '2026-11-04', false, '2026-10-22'];
        yield '3.6.5 after EOL' => ['OpenSSL 3.6.5 29 Sep 2026', '2026-11-04', false, '2026-11-01'];
        yield '3.6.5 before EOL' => ['OpenSSL 3.6.5 29 Sep 2026', '2026-10-15', true, ''];
        yield '3.5.9 LTS' => ['OpenSSL 3.5.9 29 Sep 2026', '2026-11-04', true, ''];
        yield '4.0.3' => ['OpenSSL 4.0.3 29 Sep 2026', '2026-11-04', true, ''];
        yield '4.1.0' => ['OpenSSL 4.1.0 23 Oct 2026', '2026-11-04', true, ''];
    }

    #[DataProvider('endOfLife')]
    public function testEndOfLifeBranchWarning(string $text, string $today, bool $ok, string $eol): void
    {
        [$isOk, $msg] = Tool::opensslVersionStatus($text, $today);
        self::assertSame($ok, $isOk, $msg);
        self::assertStringStartsWith($text, $msg);
        if ($eol !== '') {
            self::assertStringContainsString('upstream security support ended ' . $eol, $msg);
            self::assertStringContainsString('distribution package with backported fixes', $msg);
        }
    }

    public function testDefaultTodayIsUsedForTheEndOfLifeCheck(): void
    {
        // 3.1 ended 2025-03-14: without an explicit date the current date applies
        self::assertFalse(Tool::opensslVersionStatus('OpenSSL 3.1.8 11 Feb 2025')[0]);
    }
}
