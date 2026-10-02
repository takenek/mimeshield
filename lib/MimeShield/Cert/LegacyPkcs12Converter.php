<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Cert;

use MimeShield\Exception\ValidationException;
use MimeShield\Log;

/**
 * OPT-IN last-resort converter for legacy PKCS#12 files (RC2-40 certificate bags, as produced by
 * the Windows "TripleDES-SHA1" export) that OpenSSL 3 cannot read without the legacy provider.
 *
 * Disabled by default (mimeshield_pkcs12_legacy_cli). When enabled it runs the openssl binary with
 * proc_open() and an argument ARRAY (no shell, no interpolation). The PKCS#12 is passed on stdin,
 * the password on a separate pipe (fd 3, "-passin fd:3"), and the PEM result is read from stdout:
 * no secret ever touches the filesystem or the process argument list.
 */
final class LegacyPkcs12Converter
{
    public function __construct(private readonly string $opensslBinary, private readonly int $timeout = 10)
    {
    }

    public static function isAvailable(string $binary): bool
    {
        return $binary !== '' && function_exists('proc_open') && is_file($binary) && is_executable($binary);
    }

    /**
     * Convert a legacy PKCS#12 into an unencrypted PEM bundle (in memory).
     */
    public function toPem(#[\SensitiveParameter] string $pkcs12, #[\SensitiveParameter] string $password): string
    {
        if (!self::isAvailable($this->opensslBinary)) {
            throw new ValidationException('p12legacy', 'legacy converter not available');
        }
        $cmd = [$this->opensslBinary, 'pkcs12', '-legacy', '-nodes', '-passin', 'fd:3'];
        $spec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w'], 3 => ['pipe', 'r']];
        $env = ['PATH' => '/usr/bin:/bin', 'LANG' => 'C'];
        $proc = @proc_open($cmd, $spec, $pipes, null, $env);
        if (!is_resource($proc)) {
            throw new ValidationException('p12legacy', 'cannot start openssl');
        }
        $out = '';
        $err = '';
        try {
            fwrite($pipes[3], $password . "\n");
            fclose($pipes[3]);
            fwrite($pipes[0], $pkcs12);
            fclose($pipes[0]);
            stream_set_blocking($pipes[1], false);
            stream_set_blocking($pipes[2], false);
            $deadline = microtime(true) + $this->timeout;
            while (true) {
                $r = [$pipes[1], $pipes[2]];
                $w = null;
                $e = null;
                if (@stream_select($r, $w, $e, 1) === false) {
                    break;
                }
                foreach ($r as $s) {
                    $chunk = fread($s, 65536);
                    if ($s === $pipes[1]) {
                        $out .= (string) $chunk;
                    } else {
                        $err .= (string) $chunk;
                    }
                }
                if (feof($pipes[1]) && feof($pipes[2])) {
                    break;
                }
                if (microtime(true) > $deadline || strlen($out) > 1048576) {
                    proc_terminate($proc);
                    throw new ValidationException('p12legacy', 'openssl timeout or oversized output');
                }
            }
        } finally {
            foreach ($pipes as $p) {
                if (is_resource($p)) {
                    fclose($p);
                }
            }
            $code = proc_close($proc);
        }
        if ($code !== 0 || !str_contains($out, 'PRIVATE KEY-----')) {
            if (stripos($err, 'mac verify') !== false || stripos($err, 'invalid password') !== false) {
                throw new ValidationException('badpassword', 'legacy PKCS#12 MAC verification failed');
            }
            Log::warning('import', 'legacy PKCS#12 conversion failed', ['exit' => $code]);
            throw new ValidationException('p12legacy', 'legacy conversion failed');
        }
        return $out;
    }
}
