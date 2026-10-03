<?php

declare(strict_types=1);

namespace MimeShield\Tests\Integration;

use MimeShield\Cli\Tool;
use MimeShield\Tests\TestPki;
use PHPUnit\Framework\TestCase;

/**
 * bin/mimeshield.sh keygen: missing / unusable parent directory of --file and --create-parent.
 */
final class CliKeygenTest extends TestCase
{
    private string $base;

    protected function setUp(): void
    {
        if (!MIMESHIELD_RC_LOADED) {
            self::markTestSkipped('needs the Roundcube library (MIMESHIELD_RC)');
        }
        $this->base = TestPki::tempDir();
        chmod($this->base, 0o700);
    }

    protected function tearDown(): void
    {
        if (isset($this->base)) {
            self::rmTree($this->base);
        }
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
        @chmod($path, 0o700);
        foreach (scandir($path) ?: [] as $e) {
            if ($e !== '.' && $e !== '..') {
                self::rmTree($path . '/' . $e);
            }
        }
        @rmdir($path);
    }

    /**
     * @param array<int|string, mixed> $args
     *
     * @return array{0: int, 1: string}
     */
    private function keygen(array $args): array
    {
        $out = fopen('php://memory', 'w+');
        self::assertIsResource($out);
        $code = (new Tool(\rcube::get_instance(), dirname(__DIR__, 2), $out))->run($args);
        rewind($out);
        $text = (string) stream_get_contents($out);
        fclose($out);
        return [$code, $text];
    }

    public function testMissingParentDirectoryIsReportedPreciselyAndNothingIsCreated(): void
    {
        $dir = $this->base . '/etc/roundcube';
        [$code, $out] = $this->keygen(['keygen', 'file' => $dir . '/mimeshield.key']);

        self::assertSame(1, $code);
        self::assertStringContainsString("Parent directory {$dir} does not exist.", $out);
        self::assertStringContainsString('install -d -m 0750 -o root -g PHP_GROUP ' . escapeshellarg($dir), $out);
        self::assertStringContainsString('--create-parent', $out);
        self::assertStringNotContainsString('Cannot create', $out);
        self::assertFileDoesNotExist($this->base . '/etc', 'keygen must not create directories without --create-parent');
    }

    public function testCreateParentCreatesPrivateDirectoriesAndTheKeyFile(): void
    {
        $dir = $this->base . '/etc/roundcube';
        $file = $dir . '/mimeshield.key';
        [$code, $out] = $this->keygen(['keygen', 'file' => $file, 'kid' => 'k1', 'create-parent' => true]);

        self::assertSame(0, $code, $out);
        self::assertStringContainsString("Created directory {$dir} (mode 0700", $out);
        foreach ([$this->base . '/etc', $dir] as $d) {
            self::assertDirectoryExists($d);
            self::assertFalse(is_link($d));
            self::assertSame(0o700, fileperms($d) & 0o7777, $d);
        }
        self::assertSame(0o400, fileperms($file) & 0o777);
        self::assertMatchesRegularExpression('/^k1 [A-Za-z0-9+\/]{43}=$/m', (string) file_get_contents($file));
        self::assertStringNotContainsString((string) file_get_contents($file), $out, 'key material must not be printed');
    }

    public function testCreateParentRefusesSymbolicLinksInThePath(): void
    {
        mkdir($this->base . '/real', 0o700);
        symlink($this->base . '/real', $this->base . '/link');

        // the missing directory would be created below a symbolic link
        [$code, $out] = $this->keygen(['keygen', 'file' => $this->base . '/link/sub/mimeshield.key', 'create-parent' => true]);
        self::assertSame(1, $code);
        self::assertStringContainsString($this->base . '/link is a symbolic link', $out);
        self::assertFileDoesNotExist($this->base . '/real/sub');

        // a dangling symbolic link in place of the directory to create
        symlink($this->base . '/nowhere', $this->base . '/dangling');
        [$code, $out] = $this->keygen(['keygen', 'file' => $this->base . '/dangling/mimeshield.key', 'create-parent' => true]);
        self::assertSame(1, $code);
        self::assertStringContainsString('symbolic link', $out);
        self::assertFileDoesNotExist($this->base . '/nowhere');
    }

    public function testCreateParentRefusesSymbolicLinkInTheMiddleOfThePath(): void
    {
        // link -> real; real/existing is a real directory: the existing part of the path below the
        // symbolic link must not be trusted either
        mkdir($this->base . '/real/existing', 0o700, true);
        symlink($this->base . '/real', $this->base . '/link');

        [$code, $out] = $this->keygen(['keygen', 'file' => $this->base . '/link/existing/new/sub/mimeshield.key', 'create-parent' => true]);
        self::assertSame(1, $code, $out);
        self::assertStringContainsString($this->base . '/link is a symbolic link', $out);
        self::assertFileDoesNotExist($this->base . '/real/existing/new');
        self::assertStringNotContainsString('Created directory', $out);
    }

    public function testCreateParentRefusesExistingDirectoryOwnedByAnotherUser(): void
    {
        if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
            self::markTestSkipped('needs root to give a directory to another uid');
        }
        // mode 0700: the mode bits alone look safe, the owner is not trusted
        $other = $this->base . '/other';
        mkdir($other, 0o700);
        self::assertTrue(chown($other, 65534));

        [$code, $out] = $this->keygen(['keygen', 'file' => $other . '/new/mimeshield.key', 'create-parent' => true]);
        self::assertSame(1, $code, $out);
        self::assertStringContainsString("{$other} is owned by uid 65534", $out);
        self::assertFileDoesNotExist($other . '/new');

        // also when the foreign directory is higher up in the path
        mkdir($other . '/sub', 0o700);
        chown($other . '/sub', 0);
        [$code, $out] = $this->keygen(['keygen', 'file' => $other . '/sub/new/mimeshield.key', 'create-parent' => true]);
        self::assertSame(1, $code, $out);
        self::assertStringContainsString("{$other} is owned by uid 65534", $out);
        self::assertFileDoesNotExist($other . '/sub/new');
    }

    public function testCreateParentRefusesExistingParentReachedThroughSymbolicLink(): void
    {
        // nothing has to be created, the existing parent is still checked component by component
        mkdir($this->base . '/real/existing', 0o700, true);
        symlink($this->base . '/real', $this->base . '/link');

        [$code, $out] = $this->keygen(['keygen', 'file' => $this->base . '/link/existing/mimeshield.key', 'create-parent' => true]);
        self::assertSame(1, $code, $out);
        self::assertStringContainsString($this->base . '/link is a symbolic link', $out);
        self::assertFileDoesNotExist($this->base . '/real/existing/mimeshield.key');
    }

    public function testCreateParentRefusesExistingParentOwnedByAnotherUser(): void
    {
        if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
            self::markTestSkipped('needs root to give a directory to another uid');
        }
        $foreign = $this->base . '/foreign';
        mkdir($foreign, 0o700);
        self::assertTrue(chown($foreign, 65534));

        [$code, $out] = $this->keygen(['keygen', 'file' => $foreign . '/mimeshield.key', 'create-parent' => true]);
        self::assertSame(1, $code, $out);
        self::assertStringContainsString("{$foreign} is owned by uid 65534", $out);
        self::assertFileDoesNotExist($foreign . '/mimeshield.key');
    }

    public function testCreateParentRefusesDirectoriesWritableByOthersAndUnnormalisedPaths(): void
    {
        mkdir($this->base . '/shared', 0o700);
        chmod($this->base . '/shared', 0o777);
        [$code, $out] = $this->keygen(['keygen', 'file' => $this->base . '/shared/keys/mimeshield.key', 'create-parent' => true]);
        self::assertSame(1, $code);
        self::assertStringContainsString('writable by other users', $out);
        self::assertFileDoesNotExist($this->base . '/shared/keys');

        [$code, $out] = $this->keygen(['keygen', 'file' => $this->base . '/a/../b/mimeshield.key', 'create-parent' => true]);
        self::assertSame(1, $code);
        self::assertStringContainsString('normalised absolute path', $out);
        self::assertFileDoesNotExist($this->base . '/a');

        [$code, $out] = $this->keygen(['keygen', 'file' => $this->base . '/x/mimeshield.key', 'create-parent' => true, 'append' => true]);
        self::assertSame(1, $code);
        self::assertStringContainsString('cannot be combined with --append', $out);
    }

    public function testParentPathThatIsAFileIsReported(): void
    {
        file_put_contents($this->base . '/notadir', 'x');
        [$code, $out] = $this->keygen(['keygen', 'file' => $this->base . '/notadir/mimeshield.key']);
        self::assertSame(1, $code);
        self::assertStringContainsString('exists but is not a directory', $out);
    }

    public function testExistingDirectoryStillWorksAndIsNeverOverwritten(): void
    {
        $file = $this->base . '/mimeshield.key';
        [$code, $out] = $this->keygen(['keygen', 'file' => $file, 'kid' => 'k1']);
        self::assertSame(0, $code, $out);
        self::assertStringNotContainsString('Created directory', $out);
        [$code, $out] = $this->keygen(['keygen', 'file' => $file, 'kid' => 'k2', 'create-parent' => true]);
        self::assertSame(1, $code);
        self::assertStringContainsString('Refusing to overwrite', $out);
    }

    /**
     * Audit MS-12: the directory chain is checked without --create-parent too (new file and --append).
     */
    public function testDefaultModeAndAppendRefuseDirectoryWritableByOthers(): void
    {
        mkdir($this->base . '/shared', 0o700);
        $file = $this->base . '/shared/mimeshield.key';
        [$code, $out] = $this->keygen(['keygen', 'file' => $file, 'kid' => 'k1']);
        self::assertSame(0, $code, $out);

        chmod($this->base . '/shared', 0o777);
        [$code, $out] = $this->keygen(['keygen', 'file' => $this->base . '/shared/other.key']);
        self::assertSame(1, $code);
        self::assertStringContainsString('writable by other users', $out);
        self::assertFileDoesNotExist($this->base . '/shared/other.key');

        $before = (string) file_get_contents($file);
        [$code, $out] = $this->keygen(['keygen', 'file' => $file, 'kid' => 'k2', 'append' => true]);
        self::assertSame(1, $code);
        self::assertStringContainsString('writable by other users', $out);
        self::assertSame($before, (string) file_get_contents($file), 'key file unchanged');

        // the same directory restricted again: --append works and keeps the file mode
        chmod($this->base . '/shared', 0o700);
        [$code, $out] = $this->keygen(['keygen', 'file' => $file, 'kid' => 'k2', 'append' => true]);
        self::assertSame(0, $code, $out);
        self::assertMatchesRegularExpression('/^k2 /m', (string) file_get_contents($file));
        self::assertSame(0o400, fileperms($file) & 0o777);
        self::assertSame([], glob($file . '.new.*') ?: []);
    }

    public function testDefaultModeRefusesParentReachedThroughSymbolicLinkInThePath(): void
    {
        mkdir($this->base . '/real', 0o700);
        symlink($this->base . '/real', $this->base . '/link');
        mkdir($this->base . '/real/keys', 0o700);
        [$code, $out] = $this->keygen(['keygen', 'file' => $this->base . '/link/keys/mimeshield.key']);
        self::assertSame(1, $code);
        self::assertStringContainsString('is a symbolic link', $out);
        self::assertFileDoesNotExist($this->base . '/real/keys/mimeshield.key');
    }

    /**
     * Audit F-12: an empty (or unreadable) key file is never replaced by a file with only the new key.
     */
    public function testAppendRefusesAnEmptyKeyFile(): void
    {
        $file = $this->base . '/mimeshield.key';
        file_put_contents($file, '');
        chmod($file, 0o400);
        [$code, $out] = $this->keygen(['keygen', 'file' => $file, 'kid' => 'k2', 'append' => true]);
        self::assertSame(1, $code);
        self::assertStringContainsString('nothing appended', $out);
        self::assertSame('', (string) file_get_contents($file));
        self::assertSame([], glob($file . '.new.*') ?: []);
    }

    /** F-12: inject read failure and a short write followed by failure without needing disk faults. */
    public function testAppendIoFailuresPreserveAllExistingKeys(): void
    {
        $file = $this->base . '/mimeshield.key';
        [$code, $out] = $this->keygen(['keygen', 'file' => $file, 'kid' => 'k1']);
        self::assertSame(0, $code, $out);
        $original = (string) file_get_contents($file);
        foreach (['read', 'write'] as $failure) {
            $script = $this->base . '/io-failure.php';
            // Namespace wrappers affect this isolated subprocess only; all unrelated I/O is real.
            $wrappers = <<<'PHP'
<?php
namespace MimeShield\Cli {
    function file_get_contents($path) {
        if ($GLOBALS['io_failure'] === 'read' && $path === $GLOBALS['key_file']) {
            return false;
        }
        return \file_get_contents($path);
    }
    function fwrite($stream, $data) {
        $path = \stream_get_meta_data($stream)['uri'];
        if ($GLOBALS['io_failure'] === 'write' && str_starts_with($path, $GLOBALS['key_file'] . '.new.')) {
            if (!empty($GLOBALS['short_write_done'])) {
                return false;
            }
            $GLOBALS['short_write_done'] = true;
            return \fwrite($stream, substr($data, 0, 7));
        }
        return \fwrite($stream, $data);
    }
}
namespace {
PHP;
            file_put_contents($script, $wrappers
                . '$GLOBALS["io_failure"] = ' . var_export($failure, true) . ';'
                . '$GLOBALS["key_file"] = ' . var_export($file, true) . ';'
                . 'require ' . var_export(dirname(__DIR__) . '/bootstrap.php', true) . ';'
                . 'exit((new MimeShield\Cli\Tool(rcube::get_instance(), ' . var_export(dirname(__DIR__, 2), true) . '))'
                . '->run(["keygen", "file" => $GLOBALS["key_file"], "kid" => "k2", "append" => true])); }');
            $proc = proc_open([PHP_BINARY, $script], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null,
                ['MIMESHIELD_RC' => (string) getenv('MIMESHIELD_RC')]);
            self::assertIsResource($proc);
            $output = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            self::assertSame(1, proc_close($proc), $output);
            self::assertTrue(hash_equals($original, (string) file_get_contents($file)), $failure . ': original keys preserved');
            self::assertSame([], glob($file . '.new.*') ?: [], $failure . ': partial temporary file removed');
        }
    }

    /**
     * Audit F-12: --append is serialised by a lock file; a second run waits and then keeps both keys.
     */
    public function testConcurrentAppendsAreSerialisedAndKeepEveryKey(): void
    {
        $file = $this->base . '/mimeshield.key';
        [$code, $out] = $this->keygen(['keygen', 'file' => $file, 'kid' => 'k1']);
        self::assertSame(0, $code, $out);

        $lock = fopen($file . '.lock', 'c');
        self::assertIsResource($lock);
        self::assertTrue(flock($lock, LOCK_EX));

        $script = $this->base . '/append.php';
        file_put_contents($script, '<?php require ' . var_export(dirname(__DIR__) . '/bootstrap.php', true) . ';'
            . '$out = fopen("php://stdout", "w");'
            . 'exit((new MimeShield\\Cli\\Tool(\\rcube::get_instance(), ' . var_export(dirname(__DIR__, 2), true) . ', $out))'
            . '->run(["keygen", "file" => ' . var_export($file, true) . ', "kid" => "k3", "append" => true]));');
        $proc = proc_open([PHP_BINARY, $script], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, ['MIMESHIELD_RC' => (string) getenv('MIMESHIELD_RC')]);
        self::assertIsResource($proc);
        usleep(700000);
        self::assertTrue(proc_get_status($proc)['running'], 'the second run waits for the lock');

        // meanwhile this run appends k2 (as if it held the lock first)
        flock($lock, LOCK_UN);
        fclose($lock);
        [$code, $out] = $this->keygen(['keygen', 'file' => $file, 'kid' => 'k2', 'append' => true]);
        self::assertSame(0, $code, $out);

        $childOut = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        self::assertSame(0, proc_close($proc), $childOut);

        $content = (string) file_get_contents($file);
        foreach (['k1', 'k2', 'k3'] as $kid) {
            self::assertMatchesRegularExpression('/^' . $kid . ' /m', $content, 'no key may be lost');
        }
        self::assertSame([], glob($file . '.new.*') ?: []);
    }
}
