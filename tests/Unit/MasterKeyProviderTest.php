<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Exception\ConfigException;
use MimeShield\KeyStore\MasterKeyProvider;
use MimeShield\Tests\TestPki;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class MasterKeyProviderTest extends TestCase
{
    private string $dir;

    private string $envName;

    protected function setUp(): void
    {
        $this->dir = TestPki::tempDir();
        $this->envName = 'MIMESHIELD_TEST_MK_' . strtoupper(bin2hex(random_bytes(6)));
    }

    protected function tearDown(): void
    {
        putenv($this->envName);
        self::rmTree($this->dir);
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

    private function keyFile(string $content, int $mode = 0400, ?string $dir = null): string
    {
        $dir ??= $this->dir;
        $path = $dir . '/master-' . bin2hex(random_bytes(4)) . '.key';
        file_put_contents($path, $content);
        chmod($path, $mode);
        clearstatcache();
        return $path;
    }

    private static function b64(?string $raw = null): string
    {
        return base64_encode($raw ?? random_bytes(32));
    }

    private static function assertUnavailable(callable $fn, string $internal = ''): void
    {
        try {
            $fn();
        } catch (ConfigException $e) {
            self::assertSame('keystoreunavailable', $e->getUserLabel(), $e->getMessage());
            if ($internal !== '') {
                self::assertStringContainsString($internal, $e->getMessage());
            }
            return;
        }
        self::fail('expected ConfigException keystoreunavailable' . ($internal !== '' ? ' (' . $internal . ')' : ''));
    }

    public function testEnvSource(): void
    {
        $k1 = random_bytes(32);
        $k2 = random_bytes(32);
        putenv($this->envName . '=k1:' . base64_encode($k1) . ', k2:' . base64_encode($k2));
        $p = new MasterKeyProvider('', $this->envName);
        self::assertSame('env', $p->source());
        self::assertSame(['k1', 'k2'], $p->kids());
        self::assertSame($k1, $p->key('k1'));
        self::assertSame($k2, $p->key('k2'));
        self::assertSame('k2', $p->activeKid());
    }

    public function testEnvWinsOverFile(): void
    {
        $fileKey = random_bytes(32);
        $envKey = random_bytes(32);
        $file = $this->keyFile('f1 ' . base64_encode($fileKey) . "\n");
        putenv($this->envName . '=e1:' . base64_encode($envKey));
        $p = new MasterKeyProvider($file, $this->envName);
        self::assertSame('env', $p->source());
        self::assertSame(['e1'], $p->kids());

        putenv($this->envName);
        $p = new MasterKeyProvider($file, $this->envName);
        self::assertSame('file', $p->source());
        self::assertSame($fileKey, $p->key('f1'));
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function malformedEnv(): iterable
    {
        yield 'no colon' => ['k1' . base64_encode(str_repeat('a', 32))];
        yield 'trailing comma' => ['k1:' . base64_encode(str_repeat('a', 32)) . ','];
        yield 'empty kid' => [':' . base64_encode(str_repeat('a', 32))];
        yield 'uppercase kid' => ['K1:' . base64_encode(str_repeat('a', 32))];
        yield 'kid too long' => [str_repeat('k', 17) . ':' . base64_encode(str_repeat('a', 32))];
        yield 'short key' => ['k1:' . base64_encode(str_repeat('a', 31))];
        yield 'long key' => ['k1:' . base64_encode(str_repeat('a', 33))];
        yield 'not base64' => ['k1:***not-base64***'];
        yield 'hex key' => ['k1:' . bin2hex(str_repeat('a', 32))];
        yield 'duplicate kid' => ['k1:' . base64_encode(str_repeat('a', 32)) . ',k1:' . base64_encode(str_repeat('b', 32))];
    }

    #[DataProvider('malformedEnv')]
    public function testMalformedEnv(string $value): void
    {
        putenv($this->envName . '=' . $value);
        $p = new MasterKeyProvider('', $this->envName);
        self::assertUnavailable(static fn () => $p->activeKid());
    }

    public function testFileSource0400(): void
    {
        $k1 = random_bytes(32);
        $k2 = random_bytes(32);
        $file = $this->keyFile("# master keys\n\n  k1   " . base64_encode($k1) . "  \r\n# old comment\nk2\t" . base64_encode($k2) . "\n");
        $p = new MasterKeyProvider($file, '');
        self::assertSame('file', $p->source());
        self::assertSame(['k1', 'k2'], $p->kids());
        self::assertSame($k1, $p->key('k1'));
        self::assertSame($k2, $p->key('k2'));
        self::assertSame('k2', $p->activeKid());
    }

    public function testFileSource0440And0600Accepted(): void
    {
        foreach ([0440, 0600, 0640] as $mode) {
            $p = new MasterKeyProvider($this->keyFile('k1 ' . self::b64() . "\n", $mode), '');
            self::assertSame(['k1'], $p->kids(), sprintf('mode %o', $mode));
        }
    }

    public function testWorldAccessibleFileRefused(): void
    {
        foreach ([0404, 0644, 0666, 0401, 0402] as $mode) {
            $p = new MasterKeyProvider($this->keyFile('k1 ' . self::b64() . "\n", $mode), '');
            self::assertUnavailable(static fn () => $p->key('k1'), 'permissions');
        }
    }

    public function testFileInsideForbiddenRootRefused(): void
    {
        $web = $this->dir . '/public_html';
        mkdir($web . '/sub', 0700, true);
        $file = $this->keyFile('k1 ' . self::b64() . "\n", 0400, $web . '/sub');
        $p = new MasterKeyProvider($file, '', '', ['/nonexistent-root-' . bin2hex(random_bytes(3)), $web]);
        self::assertUnavailable(static fn () => $p->activeKid(), 'forbidden');

        // trailing slash in the configured root
        $p = new MasterKeyProvider($file, '', '', [$web . '/']);
        self::assertUnavailable(static fn () => $p->activeKid(), 'forbidden');

        // the same file outside the root is fine; a sibling with a common prefix is not "inside"
        $sibling = $this->dir . '/public_html2';
        mkdir($sibling, 0700);
        $ok = $this->keyFile('k1 ' . self::b64() . "\n", 0400, $sibling);
        $p = new MasterKeyProvider($ok, '', '', [$web]);
        self::assertSame(['k1'], $p->kids());
    }

    public function testSymlinkIntoForbiddenRootRefused(): void
    {
        $web = $this->dir . '/plugins';
        mkdir($web, 0700);
        $target = $this->keyFile('k1 ' . self::b64() . "\n", 0400, $web);
        $safe = $this->dir . '/etc';
        mkdir($safe, 0700);
        $link = $safe . '/master.key';
        symlink($target, $link);
        $p = new MasterKeyProvider($link, '', '', [$web]);
        self::assertUnavailable(static fn () => $p->activeKid(), 'forbidden');

        // forbidden root given via a symlink alias
        $alias = $this->dir . '/webalias';
        symlink($web, $alias);
        $p = new MasterKeyProvider($target, '', '', [$alias]);
        self::assertUnavailable(static fn () => $p->activeKid(), 'forbidden');
    }

    public function testRelativePathRefused(): void
    {
        foreach (['master.key', './master.key', '../etc/master.key', 'file://' . $this->dir . '/x'] as $path) {
            $p = new MasterKeyProvider($path, '');
            self::assertUnavailable(static fn () => $p->activeKid(), 'absolute');
        }
    }

    public function testMissingOrUnreadableFile(): void
    {
        $p = new MasterKeyProvider($this->dir . '/does-not-exist.key', '');
        self::assertUnavailable(static fn () => $p->activeKid(), 'not readable');
        $p = new MasterKeyProvider($this->dir, '');
        self::assertUnavailable(static fn () => $p->activeKid(), 'not readable');
    }

    public function testFileTooLargeRefused(): void
    {
        $content = str_repeat("# padding padding padding padding\n", 600) . 'k1 ' . self::b64() . "\n";
        self::assertGreaterThan(16384, strlen($content));
        $p = new MasterKeyProvider($this->keyFile($content), '');
        self::assertUnavailable(static fn () => $p->activeKid(), 'too large');
    }

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function malformedFile(): iterable
    {
        $k = base64_encode(str_repeat('k', 32));
        yield 'three fields' => ["k1 $k extra\n", 'malformed'];
        yield 'one field' => ["k1\n", 'malformed'];
        yield 'colon env syntax' => ["k1:$k\n", 'malformed'];
        yield 'bad kid' => ["Key-1 $k\n", 'invalid master key id'];
        yield 'short key' => ['k1 ' . base64_encode(str_repeat('k', 16)) . "\n", '32 random bytes'];
        yield 'long key' => ['k1 ' . base64_encode(str_repeat('k', 64)) . "\n", '32 random bytes'];
        yield 'not base64' => ["k1 ????\n", '32 random bytes'];
        yield 'duplicate kid' => ["k1 $k\nk1 " . base64_encode(str_repeat('z', 32)) . "\n", 'duplicate'];
        yield 'only comments' => ["# nothing\n\n", 'no key'];
        yield 'empty' => ['', 'no key'];
    }

    #[DataProvider('malformedFile')]
    public function testMalformedFile(string $content, string $internal): void
    {
        $p = new MasterKeyProvider($this->keyFile($content), '');
        self::assertUnavailable(static fn () => $p->activeKid(), $internal);
    }

    public function testActiveKidExplicit(): void
    {
        $file = $this->keyFile('a1 ' . self::b64() . "\nb2 " . self::b64() . "\nc3 " . self::b64() . "\n");
        self::assertSame('c3', (new MasterKeyProvider($file, ''))->activeKid());
        self::assertSame('a1', (new MasterKeyProvider($file, '', 'a1'))->activeKid());
        self::assertSame('b2', (new MasterKeyProvider($file, '', 'b2'))->activeKid());

        $p = new MasterKeyProvider($file, '', 'zz');
        self::assertUnavailable(static fn () => $p->activeKid(), 'active master key id not found');
    }

    public function testUnknownKidRequested(): void
    {
        putenv($this->envName . '=k1:' . self::b64());
        $p = new MasterKeyProvider('', $this->envName);
        self::assertUnavailable(static fn () => $p->key('k2'), 'unknown master key id');
        self::assertUnavailable(static fn () => $p->key(''), 'unknown master key id');
    }

    public function testMissingConfiguration(): void
    {
        $p = new MasterKeyProvider('', '');
        self::assertUnavailable(static fn () => $p->activeKid(), 'no master key configured');
        $p = new MasterKeyProvider('', $this->envName); // env var unset, no file
        self::assertUnavailable(static fn () => $p->kids(), 'no master key configured');
        putenv($this->envName . '=');
        $p = new MasterKeyProvider('', $this->envName); // empty env var
        self::assertUnavailable(static fn () => $p->key('k1'), 'no master key configured');
    }

    /**
     * A configuration error must stay an error: a failed load() must not leave a half-loaded provider
     * that answers the second call (regression test).
     */
    public function testFailedLoadIsNotCachedAsPartialSuccess(): void
    {
        $file = $this->keyFile('k1 ' . self::b64() . "\nthis line is malformed\n");
        $p = new MasterKeyProvider($file, '');
        self::assertUnavailable(static fn () => $p->activeKid());
        self::assertUnavailable(static fn () => $p->activeKid()); // second call must fail too
        self::assertUnavailable(static fn () => $p->key('k1'));
    }

    public function testFailedActiveKidIsNotCached(): void
    {
        $file = $this->keyFile('k1 ' . self::b64() . "\n");
        $p = new MasterKeyProvider($file, '', 'missing');
        self::assertUnavailable(static fn () => $p->activeKid());
        self::assertUnavailable(static fn () => $p->activeKid()); // second call must fail too
    }

    public function testGenerateLine(): void
    {
        $line = MasterKeyProvider::generateLine('k2026');
        self::assertMatchesRegularExpression('~^k2026 [A-Za-z0-9+/]{43}=$~', $line);
        [$kid, $b64] = explode(' ', $line);
        self::assertSame('k2026', $kid);
        self::assertSame(32, strlen((string) base64_decode($b64, true)));
        self::assertNotSame($line, MasterKeyProvider::generateLine('k2026'));

        // generated line is loadable
        $p = new MasterKeyProvider($this->keyFile($line . "\n"), '');
        self::assertSame(['k2026'], $p->kids());
        self::assertSame(base64_decode($b64, true), $p->key('k2026'));

        foreach (['', 'K1', 'k-1', 'k 1', str_repeat('a', 17), "k1\nk2"] as $bad) {
            try {
                MasterKeyProvider::generateLine($bad);
                self::fail('invalid kid accepted: ' . $bad);
            } catch (ConfigException $e) {
                self::assertSame('internalerror', $e->getUserLabel());
            }
        }
        self::assertStringStartsWith(str_repeat('a', 16) . ' ', MasterKeyProvider::generateLine(str_repeat('a', 16)));
    }

    /**
     * The kid regex uses '$' without the D modifier, so a trailing "\n" passes validation and the
     * returned "key line" contains a line break (kid "k1\n" -> "k1\n <base64>").
     */
    public function testGenerateLineRejectsTrailingNewline(): void
    {
        try {
            $line = MasterKeyProvider::generateLine("k1\n");
            self::fail('kid with trailing newline accepted, line: ' . json_encode($line));
        } catch (ConfigException $e) {
            self::assertSame('internalerror', $e->getUserLabel());
        }
    }

    public function testKeyMaterialNotLogged(): void
    {
        $raw = random_bytes(32);
        $file = $this->keyFile('k1 ' . base64_encode($raw) . "\n", 0644);
        $before = count($GLOBALS['mimeshield_test_log'] ?? []);
        $p = new MasterKeyProvider($file, '');
        self::assertUnavailable(static fn () => $p->activeKid());
        $log = implode("\n", array_slice($GLOBALS['mimeshield_test_log'] ?? [], $before));
        self::assertStringContainsString('world-accessible', $log);
        self::assertStringNotContainsString(base64_encode($raw), $log);
    }
}
