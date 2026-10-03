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
     * Issue a certificate for $csr, signed by $caCrt/$caKey with the extensions of section "e" in
     * $extFile and explicit validity dates (YYYYMMDDHHMMSSZ). `x509 -not_before/-not_after` needs the
     * OpenSSL >= 3.4 CLI; older CLIs (e.g. 3.0 on CI runners) issue the same certificate through
     * `openssl ca -startdate/-enddate`.
     */
    public static function issueCertificate(string $csr, string $caCrt, string $caKey, string $extFile, string $notBefore, string $notAfter, string $out): void
    {
        if (self::x509HasValidityDates()) {
            self::run(['/usr/bin/openssl', 'x509', '-req', '-in', $csr, '-CA', $caCrt, '-CAkey', $caKey,
                '-set_serial', '0x' . bin2hex(random_bytes(8)), '-sha256', '-not_before', $notBefore, '-not_after', $notAfter,
                '-extfile', $extFile, '-extensions', 'e', '-out', $out]);
            return;
        }
        $d = dirname($out) . '/ca-' . bin2hex(random_bytes(4));
        mkdir($d, 0700);
        touch($d . '/index.txt');
        file_put_contents($d . '/serial', bin2hex(random_bytes(8)) . "\n");
        file_put_contents($d . '/ca.cnf', "[ca]\ndefault_ca = c\n[c]\ndatabase = {$d}/index.txt\nserial = {$d}/serial\n"
            . "new_certs_dir = {$d}\ndefault_md = sha256\npolicy = p\nunique_subject = no\nemail_in_dn = no\n[p]\ncommonName = optional\n");
        self::run(['/usr/bin/openssl', 'ca', '-batch', '-notext', '-preserveDN', '-config', $d . '/ca.cnf', '-in', $csr,
            '-cert', $caCrt, '-keyfile', $caKey, '-startdate', $notBefore, '-enddate', $notAfter,
            '-extfile', $extFile, '-extensions', 'e', '-out', $out]);
    }

    private static function x509HasValidityDates(): bool
    {
        static $has = null;
        if ($has === null) {
            exec('/usr/bin/openssl x509 -help 2>&1', $help);
            $has = str_contains(implode("\n", $help), '-not_before');
        }
        return $has;
    }

    /**
     * @param list<string> $cmd
     */
    private static function run(array $cmd): void
    {
        exec(implode(' ', array_map('escapeshellarg', $cmd)) . ' 2>&1', $output, $rc);
        if ($rc !== 0) {
            throw new \RuntimeException('command failed: ' . implode(' ', $cmd) . "\n" . implode("\n", $output));
        }
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
