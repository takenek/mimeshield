<?php

declare(strict_types=1);

/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Original author: Marek Królikowski (TaKeN)
 * Original project: https://github.com/takenek/mimeshield
 * SPDX-License-Identifier: GPL-3.0-or-later
 * See LICENSE and COPYRIGHT for the license and GPL section 7 attribution terms.
 *
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
        // input is written non-blocking inside the same select loop as the output: the deadline covers
        // the whole operation, a child that stops reading can never block the PHP worker (INF-05)
        $pending = [3 => $password . "\n", 0 => $pkcs12];
        try {
            foreach ($pipes as $p) {
                stream_set_blocking($p, false);
            }
            $deadline = microtime(true) + $this->timeout;
            while (true) {
                $r = array_values(array_filter([$pipes[1], $pipes[2]], static fn ($p) => is_resource($p) && !feof($p)));
                $w = [];
                foreach (array_keys($pending) as $i) {
                    $w[] = $pipes[$i];
                }
                if ($r === [] && $w === []) {
                    break;
                }
                $e = null;
                if (@stream_select($r, $w, $e, 1) === false) {
                    break;
                }
                foreach ($w as $s) {
                    $i = array_search($s, $pipes, true);
                    $n = @fwrite($s, $pending[$i]);
                    if ($n === false) {
                        $pending[$i] = '';
                    } elseif ($n > 0) {
                        $pending[$i] = (string) substr($pending[$i], $n);
                    }
                    if ($pending[$i] === '') {
                        unset($pending[$i]);
                        fclose($s);
                    }
                }
                foreach ($r as $s) {
                    $chunk = fread($s, 65536);
                    if ($s === $pipes[1]) {
                        $out .= (string) $chunk;
                    } else {
                        $err .= (string) $chunk;
                    }
                }
                if (microtime(true) > $deadline || strlen($out) > 1048576 || strlen($err) > 65536) {
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
