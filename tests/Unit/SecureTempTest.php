<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Crypto\SecureTemp;
use MimeShield\Exception\CryptoException;
use MimeShield\Tests\TestPki;
use PHPUnit\Framework\TestCase;

final class SecureTempTest extends TestCase
{
    private string $base;

    protected function setUp(): void
    {
        $this->base = TestPki::tempDir();
    }

    protected function tearDown(): void
    {
        self::rmTree($this->base);
    }

    private static function rmTree(string $path): void
    {
        if (is_link($path) || is_file($path)) {
            @unlink($path);
            return;
        }
        if (!is_dir($path)) {
            return;
        }
        @chmod($path, 0700);
        foreach (scandir($path) ?: [] as $e) {
            if ($e !== '.' && $e !== '..') {
                self::rmTree($path . '/' . $e);
            }
        }
        @rmdir($path);
    }

    private static function mode(string $path): int
    {
        clearstatcache(true, $path);
        return fileperms($path) & 0o7777;
    }

    /**
     * @return list<string>
     */
    private static function entries(string $dir): array
    {
        return array_values(array_diff(scandir($dir) ?: [], ['.', '..']));
    }

    /**
     * @return list<string>
     */
    private static function systemTempLeftovers(): array
    {
        return glob(rtrim(sys_get_temp_dir(), '/') . '/RCMTEMPms*') ?: [];
    }

    private static function assertInternalError(callable $fn, string $internal = ''): void
    {
        try {
            $fn();
        } catch (CryptoException $e) {
            self::assertSame('internalerror', $e->getUserLabel());
            if ($internal !== '') {
                self::assertStringContainsString($internal, $e->getMessage());
            }
            return;
        }
        self::fail('expected CryptoException internalerror' . ($internal !== '' ? ' (' . $internal . ')' : ''));
    }

    public function testDirectoryCreated0700EvenWithPermissiveUmask(): void
    {
        $old = umask(0);
        try {
            $t = new SecureTemp($this->base . '/nested/deeper');
        } finally {
            umask($old);
        }
        $dir = $this->base . '/nested/deeper/mimeshield';
        self::assertSame(realpath($dir), $t->getDir());
        self::assertDirectoryExists($dir);
        self::assertSame(0700, self::mode($dir));
        self::assertSame(0, self::mode($this->base . '/nested') & 0o077, 'parents created private too');
    }

    public function testTrailingSlashBaseDir(): void
    {
        $t = new SecureTemp($this->base . '/');
        self::assertSame(realpath($this->base . '/mimeshield'), $t->getDir());
    }

    public function testFilesAre0600InsideDir(): void
    {
        $old = umask(0);
        try {
            $t = new SecureTemp($this->base);
            $empty = $t->file();
            $full = $t->file('content');
        } finally {
            umask($old);
        }
        foreach ([$empty, $full] as $f) {
            self::assertSame($t->getDir(), dirname($f));
            self::assertSame(0600, self::mode($f));
            self::assertStringStartsWith('RCMTEMPms', basename($f));
            self::assertFalse(is_link($f));
        }
        self::assertNotSame($empty, $full);
        self::assertSame(2, $t->count());
        $t->cleanup();
    }

    public function testContentRoundtrip(): void
    {
        $t = new SecureTemp($this->base);
        $cases = ['', 'a', "line1\r\nline2\n", "\0\x01\xff binary \0", random_bytes(1024 * 1024 + 7), TestPki::read('alice.crt')];
        foreach ($cases as $content) {
            $p = $t->file($content);
            self::assertSame(strlen($content), filesize($p));
            self::assertSame($content, $t->read($p));
        }
        // files written by an external party (OpenSSL output) are read back too
        $out = $t->file();
        file_put_contents($out, 'written by openssl');
        self::assertSame('written by openssl', $t->read($out));
        $t->cleanup();
    }

    public function testCleanupRemovesAllFiles(): void
    {
        $t = new SecureTemp($this->base);
        $paths = [];
        for ($i = 0; $i < 10; $i++) {
            $paths[] = $t->file(str_repeat('x', $i * 100));
        }
        self::assertCount(10, self::entries($t->getDir()));
        $t->cleanup();
        self::assertSame(0, $t->count());
        self::assertSame([], self::entries($t->getDir()));
        foreach ($paths as $p) {
            self::assertFileDoesNotExist($p);
        }
        // idempotent
        $t->cleanup();
        self::assertSame(0, $t->count());
    }

    public function testRemoveSingleFile(): void
    {
        $t = new SecureTemp($this->base);
        $a = $t->file('a');
        $b = $t->file('b');
        $t->remove($a);
        self::assertFileDoesNotExist($a);
        self::assertFileExists($b);
        self::assertSame(1, $t->count());
        self::assertInternalError(static fn () => $t->read($a), 'foreign');

        // remove() of a path not owned by the instance is a no-op (never deletes foreign files)
        $foreign = $this->base . '/foreign.txt';
        file_put_contents($foreign, 'keep');
        $t->remove($foreign);
        self::assertSame('keep', file_get_contents($foreign));
        $t->cleanup();
    }

    public function testCleanupOnExceptionInCaller(): void
    {
        $t = new SecureTemp($this->base);
        $created = [];
        try {
            try {
                $created[] = $t->file('signed data');
                $created[] = $t->file();
                throw new \RuntimeException('openssl failed');
            } finally {
                $t->cleanup();
            }
        } catch (\RuntimeException $e) {
            self::assertSame('openssl failed', $e->getMessage());
        }
        self::assertCount(2, $created);
        foreach ($created as $p) {
            self::assertFileDoesNotExist($p);
        }
        self::assertSame([], self::entries($t->getDir()));
    }

    public function testNoLeftoverAfterDestruct(): void
    {
        $t = new SecureTemp($this->base);
        $dir = $t->getDir();
        $paths = [$t->file('one'), $t->file('two'), $t->file()];
        foreach ($paths as $p) {
            self::assertFileExists($p);
        }
        unset($t);
        gc_collect_cycles();
        foreach ($paths as $p) {
            self::assertFileDoesNotExist($p);
        }
        self::assertSame([], self::entries($dir));
    }

    public function testNoLeftoverWhenScopeEnds(): void
    {
        $dir = (function (): string {
            $t = new SecureTemp($this->base);
            $t->file('scoped');
            return $t->getDir();
        })();
        gc_collect_cycles();
        self::assertSame([], self::entries($dir));
    }

    public function testDirSymlinkRefused(): void
    {
        $target = $this->base . '/attacker-target';
        mkdir($target, 0700);
        symlink($target, $this->base . '/mimeshield');
        $before = count($GLOBALS['mimeshield_test_log'] ?? []);
        self::assertInternalError(fn () => new SecureTemp($this->base), 'unsafe temp dir');
        self::assertSame([], self::entries($target));
        $log = implode("\n", array_slice($GLOBALS['mimeshield_test_log'] ?? [], $before));
        self::assertStringContainsString('symlink', $log);
    }

    public function testDanglingSymlinkRefusedAndNotFollowed(): void
    {
        $target = $this->base . '/not-yet-there';
        symlink($target, $this->base . '/mimeshield');
        self::assertInternalError(fn () => new SecureTemp($this->base), 'unsafe temp dir');
        self::assertFalse(file_exists($target), 'mkdir must not follow the dangling symlink');
    }

    public function testRegularFileInPlaceOfDirRefused(): void
    {
        file_put_contents($this->base . '/mimeshield', 'x');
        self::assertInternalError(fn () => new SecureTemp($this->base), 'unsafe temp dir');
    }

    public function testPreExistingWorldWritableDirFixed(): void
    {
        $dir = $this->base . '/mimeshield';
        mkdir($dir);
        chmod($dir, 0777);
        self::assertSame(0777, self::mode($dir));
        $t = new SecureTemp($this->base);
        self::assertSame(0700, self::mode($dir));
        self::assertSame(realpath($dir), $t->getDir());
    }

    public function testDirOwnedByOtherUserRefused(): void
    {
        if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
            self::markTestSkipped('needs root to chown');
        }
        $dir = $this->base . '/mimeshield';
        mkdir($dir, 0700);
        chown($dir, 65534);
        self::assertInternalError(fn () => new SecureTemp($this->base), 'owner');
    }

    public function testRelativeOrEmptyBaseRefused(): void
    {
        foreach (['', 'relative/dir', './tmp', '/'] as $base) {
            if ($base === '/') {
                // '/' -> '' after rtrim: refused, never "/mimeshield"
                self::assertInternalError(static fn () => SecureTemp::prepareDir($base), 'absolute');
                continue;
            }
            self::assertInternalError(static fn () => new SecureTemp($base), 'absolute');
        }
    }

    /**
     * tempnam() falls back to the system temp dir if the dedicated dir disappears; that must be an
     * error and must not leave a file in /tmp.
     */
    public function testTempnamFallbackDetectedWhenDirRemoved(): void
    {
        $t = new SecureTemp($this->base);
        $dir = $t->getDir();
        $leftBefore = self::systemTempLeftovers();
        rmdir($dir);
        self::assertInternalError(static fn () => $t->file('secret plaintext'), 'tempnam');
        self::assertSame($leftBefore, self::systemTempLeftovers());
        self::assertSame(0, $t->count());
    }

    public function testTempnamFallbackDetectedWhenDirReplacedByFile(): void
    {
        $t = new SecureTemp($this->base);
        $dir = $t->getDir();
        $leftBefore = self::systemTempLeftovers();
        rmdir($dir);
        file_put_contents($dir, 'not a dir');
        $before = count($GLOBALS['mimeshield_test_log'] ?? []);
        self::assertInternalError(static fn () => $t->file('secret plaintext'), 'tempnam');
        self::assertSame($leftBefore, self::systemTempLeftovers());
        self::assertSame('not a dir', file_get_contents($dir));
        $log = implode("\n", array_slice($GLOBALS['mimeshield_test_log'] ?? [], $before));
        self::assertStringContainsString('cannot create temp file', $log);
    }

    public function testTempnamFallbackDetectedWhenDirReplacedBySymlink(): void
    {
        $t = new SecureTemp($this->base);
        $dir = $t->getDir();
        $evil = $this->base . '/evil';
        mkdir($evil, 0700);
        rmdir($dir);
        symlink($evil, $dir);
        try {
            $p = $t->file('x');
            // if tempnam resolved the link the path would be in $evil
            self::assertSame($dir, dirname($p));
        } catch (CryptoException $e) {
            self::assertSame('internalerror', $e->getUserLabel());
        }
        $t->cleanup();
        self::assertSame([], self::entries($evil));
    }

    public function testReadOfForeignPathRefused(): void
    {
        $t = new SecureTemp($this->base);
        $other = new SecureTemp($this->base . '/other');
        $foreign = $other->file('other instance');
        self::assertInternalError(static fn () => $t->read($foreign), 'foreign');
        self::assertInternalError(static fn () => $t->read('/etc/passwd'), 'foreign');
        $own = $t->file('own');
        self::assertInternalError(static fn () => $t->read($own . '/../' . basename($own)), 'foreign');
        self::assertInternalError(static fn () => $t->read(dirname($own) . '/./' . basename($own)), 'foreign');
        self::assertSame('own', $t->read($own));
        $t->cleanup();
        $other->cleanup();
    }

    public function testRemovedFileReplacedBySymlinkIsNotTruncatedThroughLink(): void
    {
        $t = new SecureTemp($this->base);
        $p = $t->file('data');
        $victim = $this->base . '/victim.txt';
        file_put_contents($victim, 'precious');
        unlink($p);
        symlink($victim, $p);
        $t->cleanup();
        self::assertSame('precious', file_get_contents($victim));
        self::assertFalse(is_link($p));
    }
}
