<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Crypto;

use MimeShield\Exception\CryptoException;
use MimeShield\Log;

/**
 * Secure temporary files for the PHP OpenSSL CMS API (which only accepts real file paths).
 *
 * - files live in a dedicated directory (mode 0700) that is verified not to be a symlink and to be
 *   owned by the current process user,
 * - files are created by tempnam() (mkstemp: O_CREAT|O_EXCL, mode 0600, unpredictable name), so a
 *   pre-created file or symlink can never be followed,
 * - output files are always pre-created, so OpenSSL never creates a file with the umask mode,
 * - every file is truncated and unlinked by cleanup(), which callers run in `finally`; the destructor
 *   and a shutdown function are a backstop,
 * - private keys are NEVER written here: OpenSSL accepts keys as PEM strings / key objects.
 *   Message plaintext and signatures do pass through these files for the duration of one call.
 */
final class SecureTemp
{
    private string $dir;

    /** @var array<string, true> */
    private array $files = [];

    public function __construct(string $baseDir)
    {
        $this->dir = self::prepareDir($baseDir);
        $self = \WeakReference::create($this);
        register_shutdown_function(static function () use ($self): void {
            $obj = $self->get();
            if ($obj !== null) {
                $obj->cleanup();
            }
        });
    }

    public function __destruct()
    {
        $this->cleanup();
    }

    public function getDir(): string
    {
        return $this->dir;
    }

    /**
     * Create a new temp file containing $content. Returns its absolute path.
     */
    public function file(string $content = ''): string
    {
        $path = @tempnam($this->dir, 'RCMTEMPms');
        if ($path === false || dirname($path) !== $this->dir) {
            // tempnam() silently falls back to the system temp dir if $dir is unusable
            if (is_string($path)) {
                @unlink($path);
            }
            Log::error('tempfile', 'cannot create temp file in dedicated directory');
            throw new CryptoException('internalerror', 'tempnam failed');
        }
        $this->files[$path] = true;
        @chmod($path, 0600);

        if ($content !== '') {
            $fh = @fopen($path, 'wb');
            if ($fh === false) {
                throw new CryptoException('internalerror', 'cannot open temp file');
            }
            try {
                $len = strlen($content);
                $written = 0;
                while ($written < $len) {
                    $w = fwrite($fh, $written === 0 ? $content : substr($content, $written));
                    if ($w === false || $w === 0) {
                        throw new CryptoException('internalerror', 'cannot write temp file');
                    }
                    $written += $w;
                }
            } finally {
                fclose($fh);
            }
        }

        return $path;
    }

    /**
     * Read a temp file created by this instance.
     */
    public function read(string $path): string
    {
        if (!isset($this->files[$path])) {
            throw new CryptoException('internalerror', 'read of foreign temp file');
        }
        clearstatcache(true, $path);
        $data = @file_get_contents($path);
        return $data === false ? '' : $data;
    }

    /**
     * Truncate and remove one file.
     */
    public function remove(string $path): void
    {
        if (!isset($this->files[$path])) {
            return;
        }
        unset($this->files[$path]);
        if (is_file($path) && !is_link($path)) {
            // truncate first so the data blocks are released even if unlink fails
            $fh = @fopen($path, 'r+b');
            if ($fh !== false) {
                @ftruncate($fh, 0);
                fclose($fh);
            }
        }
        @unlink($path);
    }

    /**
     * Remove all files created by this instance.
     */
    public function cleanup(): void
    {
        foreach (array_keys($this->files) as $path) {
            $this->remove($path);
        }
    }

    /**
     * Number of files still owned (tests/diagnostics).
     */
    public function count(): int
    {
        return count($this->files);
    }

    /**
     * Create/verify the dedicated directory.
     */
    public static function prepareDir(string $baseDir): string
    {
        $baseDir = rtrim($baseDir, '/');
        if ($baseDir === '' || !str_starts_with($baseDir, '/')) {
            throw new CryptoException('internalerror', 'temp dir must be an absolute path');
        }

        $dir = $baseDir . '/mimeshield';
        if (!file_exists($dir) && !is_link($dir)) {
            $old = umask(0077);
            try {
                if (!@mkdir($dir, 0700, true) && !is_dir($dir)) {
                    throw new CryptoException('internalerror', 'cannot create temp dir');
                }
            } finally {
                umask($old);
            }
        }

        clearstatcache(true, $dir);
        if (is_link($dir) || !is_dir($dir)) {
            Log::error('tempfile', 'temp dir is a symlink or not a directory', ['dir' => $dir]);
            throw new CryptoException('internalerror', 'unsafe temp dir');
        }

        $stat = @lstat($dir);
        if ($stat === false) {
            throw new CryptoException('internalerror', 'cannot stat temp dir');
        }
        if (function_exists('posix_geteuid') && $stat['uid'] !== posix_geteuid()) {
            Log::error('tempfile', 'temp dir is not owned by the PHP process user', ['dir' => $dir]);
            throw new CryptoException('internalerror', 'unsafe temp dir owner');
        }
        if (($stat['mode'] & 0077) !== 0) {
            if (!@chmod($dir, 0700)) {
                throw new CryptoException('internalerror', 'unsafe temp dir mode');
            }
        }
        if (!is_writable($dir)) {
            throw new CryptoException('internalerror', 'temp dir not writable');
        }

        $real = realpath($dir);
        return $real === false ? $dir : $real;
    }
}
