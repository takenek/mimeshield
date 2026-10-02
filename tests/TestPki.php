<?php

declare(strict_types=1);

/**
 * MIME Shield - access to the TEST-ONLY PKI fixtures (tests/fixtures/pki).
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Tests;

use MimeShield\Cert\Certificate;

final class TestPki
{
    /** Password of every PKCS#12 fixture (non-ASCII on purpose). */
    public const PASSWORD = 'test-password-Zażółć';

    public static function dir(): string
    {
        return __DIR__ . '/fixtures/pki';
    }

    public static function path(string $name): string
    {
        $p = self::dir() . '/' . $name;
        if (!is_file($p)) {
            throw new \RuntimeException('missing fixture ' . $name . ' - run tests/fixtures/generate.sh');
        }
        return $p;
    }

    public static function read(string $name): string
    {
        return (string) file_get_contents(self::path($name));
    }

    public static function cert(string $name): Certificate
    {
        return Certificate::fromString(self::read($name . '.crt'));
    }

    public static function key(string $name): string
    {
        return self::read($name . '.key');
    }

    /**
     * Fresh private temp directory for a test.
     */
    public static function tempDir(): string
    {
        $d = sys_get_temp_dir() . '/mimeshield-test-' . bin2hex(random_bytes(6));
        mkdir($d, 0700, true);
        return $d;
    }
}
