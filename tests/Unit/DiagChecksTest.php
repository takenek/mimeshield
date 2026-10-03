<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Cli\Tool;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * `diag` warnings for installation-level decisions: PHP branch end of security support (audit
 * I-14), temp directory not on a memory file system (I-15) and slow DNS resolver configuration
 * with CRL checking (F-14). All are warnings only.
 */
final class DiagChecksTest extends TestCase
{
    /**
     * @return iterable<string, array{0: string, 1: string, 2: bool}>
     */
    public static function phpVersions(): iterable
    {
        yield '8.1 after EOL' => ['8.1.33', '2026-10-03', false];
        yield '8.1 on EOL day' => ['8.1.33', '2025-12-31', true];
        yield '8.2 before EOL' => ['8.2.29', '2026-10-03', true];
        yield '8.2 after EOL' => ['8.2.29', '2027-01-01', false];
        yield '8.3' => ['8.3.20', '2026-10-03', true];
        yield '8.3 after EOL' => ['8.3.20', '2028-01-01', false];
        yield '8.4' => ['8.4.26', '2026-10-03', true];
        yield '8.5' => ['8.5.3', '2026-10-03', true];
        yield '8.5 after EOL' => ['8.5.3', '2030-01-01', false];
        // branches not in the table: no claim
        yield '8.6' => ['8.6.0', '2040-01-01', true];
        yield '9.0' => ['9.0.0-dev', '2040-01-01', true];
        yield 'unparsable' => ['unknown', '2040-01-01', true];
    }

    #[DataProvider('phpVersions')]
    public function testPhpSecuritySupport(string $version, string $today, bool $ok): void
    {
        [$isOk, $msg] = Tool::phpSupportStatus($version, $today);
        self::assertSame($ok, $isOk);
        self::assertStringStartsWith($version, $msg);
        if ($ok) {
            self::assertSame($version, $msg);
        } else {
            self::assertStringContainsString('security support ended', $msg);
            self::assertStringContainsString('PHP >= 8.3 recommended', $msg);
        }
    }

    public function testPhp81WarningText(): void
    {
        self::assertSame([false, '8.1.33 - PHP 8.1 security support ended 2025-12-31: upgrade, PHP >= 8.3 recommended'],
            Tool::phpSupportStatus('8.1.33', '2026-10-03'));
    }

    private const MOUNTS = "sysfs /sys sysfs rw,nosuid 0 0\n"
        . "/dev/sda1 / ext4 rw,relatime 0 0\n"
        . "tmpfs /run tmpfs rw,nosuid 0 0\n"
        . "tmpfs /var/lib/roundcube/tmp tmpfs rw,mode=700 0 0\n"
        . "/dev/sda2 /var xfs rw 0 0\n"
        . "tmpfs /srv/mail\\040temp tmpfs rw 0 0\n"
        . "ramfs /srv/ram ramfs rw 0 0\n"
        . "/dev/sdb1 /srv/ram/disk ext4 rw 0 0\n"
        . "tmpfs /tmp tmpfs rw 0 0\n";

    /**
     * @return iterable<string, array{0: string, 1: ?bool, 2: string}>
     */
    public static function tempPaths(): iterable
    {
        yield 'tmpfs mount point itself' => ['/var/lib/roundcube/tmp', true, 'tmpfs (/var/lib/roundcube/tmp)'];
        yield 'below tmpfs, longest prefix wins over /var' => ['/var/lib/roundcube/tmp/mimeshield', true, 'tmpfs (/var/lib/roundcube/tmp)'];
        yield 'sibling name is not a prefix' => ['/var/lib/roundcube/tmpx', false, 'xfs (/var)'];
        yield 'disk' => ['/var/spool/x', false, 'xfs (/var)'];
        yield 'root fs' => ['/home/x', false, 'ext4 (/)'];
        yield 'escaped space' => ['/srv/mail temp/ms', true, 'tmpfs (/srv/mail temp)'];
        yield 'ramfs' => ['/srv/ram/x', true, 'ramfs (/srv/ram)'];
        yield 'disk below ramfs' => ['/srv/ram/disk/x', false, 'ext4 (/srv/ram/disk)'];
        yield 'tmp' => ['/tmp', true, 'tmpfs (/tmp)'];
    }

    #[DataProvider('tempPaths')]
    public function testTempDirFileSystem(string $path, ?bool $ok, string $prefix): void
    {
        [$isOk, $msg] = Tool::tmpfsStatus(self::MOUNTS, $path);
        self::assertSame($ok, $isOk, $msg);
        self::assertStringStartsWith($prefix, $msg);
        self::assertSame($ok === false, str_contains($msg, 'put mimeshield_temp_dir on tmpfs'));
    }

    public function testLaterMountOnTheSamePointWins(): void
    {
        self::assertSame([true, 'tmpfs (/data)'], Tool::tmpfsStatus("/dev/sda1 / ext4 rw 0 0\n/dev/sdb /data ext4 rw 0 0\nnone /data tmpfs rw 0 0\n", '/data/t'));
    }

    public function testUnknownMountTableIsInformational(): void
    {
        [$ok, $msg] = Tool::tmpfsStatus(null, '/tmp');
        self::assertNull($ok);
        self::assertStringContainsString('cannot be determined', $msg);
        self::assertNull(Tool::tmpfsStatus("garbage\n", '/tmp')[0]);
    }

    /**
     * @return iterable<string, array{0: string, 1: bool, 2: int}>
     */
    public static function resolvers(): iterable
    {
        // [resolv.conf, OK?, worst case seconds]
        yield 'glibc defaults, one server' => ["nameserver 10.0.0.1\n", true, 10];
        yield 'glibc defaults, two servers' => ["nameserver 10.0.0.1\nnameserver 10.0.0.2\n", false, 20];
        yield 'empty file' => ['', true, 10];
        yield 'two servers, timeout 2' => ["nameserver 10.0.0.1\nnameserver 10.0.0.2\noptions timeout:2 attempts:2 rotate\n", true, 8];
        yield 'three servers' => ["nameserver a\nnameserver b\nnameserver c\noptions timeout:2 attempts:2\n", false, 12];
        yield 'recommended options, three servers' => ["nameserver a\nnameserver b\nnameserver c\n" . Tool::RECOMMENDED_RESOLVER_OPTIONS . "\n", true, 6];
        yield 'only first three servers count' => ["nameserver a\nnameserver b\nnameserver c\nnameserver d\noptions timeout:1 attempts:3\n", true, 9];
        yield 'comments ignored' => ["# nameserver x\n; nameserver y\nnameserver 127.0.0.53\noptions edns0 trust-ad timeout:1 # attempts:9\n", true, 2];
        yield 'last option wins' => ["nameserver a\noptions timeout:1\noptions timeout:7 attempts:1\n", true, 7];
        yield 'glibc caps' => ["nameserver a\noptions timeout:99 attempts:99\n", false, 150];
    }

    #[DataProvider('resolvers')]
    public function testResolverWorstCase(string $conf, bool $ok, int $seconds): void
    {
        [$isOk, $msg] = Tool::resolverStatus($conf);
        self::assertSame($ok, $isOk, $msg);
        self::assertStringStartsWith($seconds . ' s ', $msg);
        self::assertSame(!$ok, str_contains($msg, Tool::RECOMMENDED_RESOLVER_OPTIONS));
    }

    /**
     * The advice diag prints must itself pass the check with the maximum of 3 name servers, and the
     * documentation must recommend the same options (audit F-14: docs and diag must not disagree).
     */
    public function testRecommendedResolverOptionsAgreeWithDocs(): void
    {
        [$isOk] = Tool::resolverStatus("nameserver a\nnameserver b\nnameserver c\nnameserver d\n" . Tool::RECOMMENDED_RESOLVER_OPTIONS . "\n");
        self::assertTrue($isOk);
        [, $msg] = Tool::resolverStatus("nameserver a\nnameserver b\nnameserver c\noptions timeout:2 attempts:2\n");
        self::assertStringNotContainsString('timeout:2 attempts:2', $msg, 'diag must not advise the options already set');
        $root = dirname(__DIR__, 2);
        foreach (['README.md', 'SECURITY.md', 'config.inc.php.dist', 'docs/THREAT_MODEL.md', 'CHANGELOG.md'] as $doc) {
            $text = (string) preg_replace('/\s+/', ' ', (string) file_get_contents($root . '/' . $doc));
            self::assertTrue(str_contains($text, Tool::RECOMMENDED_RESOLVER_OPTIONS), $doc . ' must recommend ' . Tool::RECOMMENDED_RESOLVER_OPTIONS);
            self::assertFalse(str_contains($text, 'timeout:2 attempts:2'), $doc . ' recommends options diag rejects with 3 name servers');
        }
    }
}
