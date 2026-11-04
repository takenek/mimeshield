<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Tests\Unit;

use MimeShield\FileCheck;
use MimeShield\Tests\TestPki;
use PHPUnit\Framework\TestCase;

/**
 * Audit V-10: trust files and the master key file are checked for ownership and write permissions.
 */
final class FileCheckTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = TestPki::tempDir();
        $GLOBALS['mimeshield_test_log'] = [];
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            chmod($f, 0600);
            unlink($f);
        }
        rmdir($this->dir);
    }

    private function file(int $mode): string
    {
        $f = $this->dir . '/trust.pem';
        file_put_contents($f, "x\n");
        chmod($f, $mode);
        return $f;
    }

    public function testOwnFileWithPrivateModeIsAcceptable(): void
    {
        [$ok, $text] = FileCheck::status($this->file(0640));
        self::assertTrue($ok, $text);
        self::assertStringContainsString('mode 0640', $text);
        self::assertFalse(FileCheck::isWorldWritable($this->dir . '/trust.pem'));
    }

    public function testWorldWritableFileIsRefused(): void
    {
        [$ok, $text] = FileCheck::status($this->file(0666));
        self::assertFalse($ok);
        self::assertStringContainsString('WORLD-WRITABLE', $text);
        self::assertTrue(FileCheck::isWorldWritable($this->dir . '/trust.pem'));
    }

    public function testGroupWritableFileIsReported(): void
    {
        [$ok, $text] = FileCheck::status($this->file(0664));
        self::assertFalse($ok);
        self::assertStringContainsString('group-writable', $text);
    }

    public function testWorldWritableParentDirectoryWithoutStickyBitIsReported(): void
    {
        $sub = $this->dir . '/open';
        mkdir($sub, 0777);
        chmod($sub, 0777);
        file_put_contents($sub . '/trust.pem', "x\n");
        chmod($sub . '/trust.pem', 0640);
        try {
            [$ok, $text] = FileCheck::status($sub . '/trust.pem');
            self::assertFalse($ok);
            self::assertStringContainsString('parent directory', $text);
            self::assertStringContainsString('without the sticky bit', $text);
            // the sticky bit (as on /tmp) prevents other users from renaming the entry: acceptable
            chmod($sub, 01777);
            [$ok, $text] = FileCheck::status($sub . '/trust.pem');
            self::assertTrue($ok, $text);
        } finally {
            unlink($sub . '/trust.pem');
            rmdir($sub);
        }
    }

    public function testMissingFile(): void
    {
        self::assertFalse(FileCheck::status($this->dir . '/none')[0]);
    }

    public function testWarnOnceLogsOnlyOncePerProcess(): void
    {
        $f = $this->file(0664);
        FileCheck::warnOnce('truststore', 'CA bundle', $f);
        FileCheck::warnOnce('truststore', 'CA bundle', $f);
        $log = implode("\n", $GLOBALS['mimeshield_test_log']);
        self::assertSame(1, substr_count($log, 'unexpected ownership or permissions'));
        self::assertStringContainsString('group-writable', $log);
        // an acceptable file is never logged
        FileCheck::warnOnce('truststore', 'CA bundle', $this->file(0600) . '');
    }
}
