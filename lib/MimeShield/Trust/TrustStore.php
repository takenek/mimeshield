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

namespace MimeShield\Trust;

use MimeShield\Cert\Certificate;
use MimeShield\Config;
use MimeShield\Crypto\SecureTemp;
use MimeShield\Exception\MimeShieldException;
use MimeShield\Exception\ValidationException;
use MimeShield\Log;

/**
 * Administrator-controlled trust anchors and intermediate certificates.
 *
 * Trust anchors come ONLY from configuration: explicitly configured CA bundle file(s) and,
 * optionally, the system OpenSSL default bundle. Users cannot add trust anchors, and end-entity
 * certificates are never added to the anchors. Intermediates (configured file + certificates
 * shipped in messages / PKCS#12 files) are "untrusted" helpers for path building only.
 *
 * Isolation from the OpenSSL default store (audit F-02): PHP adds OpenSSL's default CA FILE when
 * ca_info names no file and its default hash DIRECTORY (OPENSSLDIR/certs, SSL_CERT_DIR) when ca_info
 * names no directory. verifyLocations() therefore always adds an empty, plugin-owned directory, so
 * the verification store holds only the configured bundle files; in addition ChainValidator accepts
 * a path only when it ends in one of anchors() (defence in depth).
 */
final class TrustStore
{
    private const MAX_ANCHORS = 2000;

    /** @var null|list<Certificate> */
    private ?array $anchors = null;

    /** @var null|list<Certificate> */
    private ?array $intermediates = null;

    /**
     * @param list<string> $bundleFiles       CA bundle files (PEM) configured by the admin
     * @param bool         $useSystemStore    Also trust the OpenSSL default CA bundle
     * @param list<string> $intermediateFiles PEM files with intermediate CAs (not trusted, path building only)
     */
    public function __construct(
        private readonly array $bundleFiles,
        private readonly bool $useSystemStore,
        private readonly array $intermediateFiles = [],
    ) {
    }

    /**
     * Build from the plugin configuration (MimeShield\Config: user preferences named like these
     * administrator options are ignored).
     */
    public static function fromConfig(Config $config): self
    {
        $bundles = array_values(array_filter(array_map('strval', (array) $config->get('mimeshield_ca_bundle'))));
        $inter = array_values(array_filter(array_map('strval', (array) $config->get('mimeshield_intermediates'))));
        return new self($bundles, $config->bool('mimeshield_use_system_ca'), $inter);
    }

    /**
     * Files to pass as ca_info to OpenSSL.
     *
     * @return list<string>
     */
    public function caInfo(): array
    {
        $files = [];
        foreach ($this->bundleFiles as $f) {
            if (is_file($f) && is_readable($f)) {
                $files[] = $f;
            } else {
                Log::warning('truststore', 'configured CA bundle not readable', ['file' => $f]);
            }
        }
        if ($this->useSystemStore && ($sys = self::systemBundle()) !== null) {
            $files[] = $sys;
        }
        return $files;
    }

    /**
     * Locations for OpenSSL's verification store: the bundle files plus an empty directory owned by
     * the plugin (disables the implicit default CA directory). null when the isolation directory
     * cannot be guaranteed (fail closed: nothing is trusted).
     *
     * @return null|list<string>
     */
    public function verifyLocations(string $tempBaseDir): ?array
    {
        $files = $this->caInfo();
        if ($files === []) {
            return null;
        }
        $dir = self::isolationDir($tempBaseDir);
        return $dir === null ? null : [...$files, $dir];
    }

    /**
     * Empty directory (mode 0700, owned by the PHP user, not a symlink) under the plugin temp dir.
     */
    public static function isolationDir(string $tempBaseDir): ?string
    {
        try {
            $base = SecureTemp::prepareDir($tempBaseDir);
        } catch (MimeShieldException) {
            return null;
        }
        $dir = $base . '/no-default-ca';
        if (!file_exists($dir) && !is_link($dir)) {
            $old = umask(0077);
            @mkdir($dir, 0700);
            umask($old);
        }
        clearstatcache(true, $dir);
        $st = @lstat($dir);
        if ($st === false || is_link($dir) || !is_dir($dir)
            || (function_exists('posix_geteuid') && $st['uid'] !== posix_geteuid()) || ($st['mode'] & 0077) !== 0) {
            Log::error('truststore', 'CA isolation directory is unsafe', ['dir' => $dir]);
            return null;
        }
        if (array_diff(@scandir($dir) ?: ['?'], ['.', '..']) !== []) {
            Log::error('truststore', 'CA isolation directory is not empty', ['dir' => $dir]);
            return null;
        }
        return $dir;
    }

    /**
     * Whether any trust anchor source is available.
     */
    public function hasAnchors(): bool
    {
        return $this->anchors() !== [];
    }

    /**
     * @return list<Certificate>
     */
    public function anchors(): array
    {
        if ($this->anchors === null) {
            $this->anchors = [];
            foreach ($this->caInfo() as $file) {
                foreach ($this->loadFile($file) as $c) {
                    // anchors must be CA certificates; an end entity in a bundle is ignored
                    if ($c->isCa) {
                        $this->anchors[] = $c;
                    }
                    if (count($this->anchors) >= self::MAX_ANCHORS) {
                        break 2;
                    }
                }
            }
        }
        return $this->anchors;
    }

    /**
     * Configured intermediate certificates.
     *
     * @return list<Certificate>
     */
    public function intermediates(): array
    {
        if ($this->intermediates === null) {
            $this->intermediates = [];
            foreach ($this->intermediateFiles as $file) {
                if (!is_file($file) || !is_readable($file)) {
                    Log::warning('truststore', 'configured intermediates file not readable', ['file' => $file]);
                    continue;
                }
                foreach ($this->loadFile($file) as $c) {
                    if ($c->isCa) {
                        $this->intermediates[] = $c;
                    }
                }
            }
        }
        return $this->intermediates;
    }

    /**
     * Is $cert (byte-identical) one of the trust anchors?
     */
    public function isAnchor(Certificate $cert): bool
    {
        foreach ($this->anchors() as $a) {
            if ($a->fingerprint === $cert->fingerprint) {
                return true;
            }
        }
        return false;
    }

    /**
     * Issuer certificate of $cert among the configured intermediates, the trust anchors and the given
     * (untrusted) certificates - administrator-controlled certificates first, and among equal
     * candidates one that may sign CRLs (a copy without cRLSign shipped in a message never shadows
     * the real issuer, audit F-05). Revocation checking uses the accepted chain path instead
     * (ChainResult::$certs); this lookup remains for diagnostics.
     *
     * @param list<string> $extraPems e.g. certificates embedded in a message or stored with a record
     */
    public function findIssuer(Certificate $cert, array $extraPems = []): ?Certificate
    {
        $candidates = [];
        foreach ($extraPems as $pem) {
            try {
                $candidates[] = Certificate::fromString($pem);
            } catch (ValidationException) {
            }
        }
        $found = null;
        foreach (array_merge($this->intermediates(), $this->anchors(), $candidates) as $c) {
            if ($c->fingerprint !== $cert->fingerprint && $cert->isIssuedBy($c)) {
                if ($c->hasKeyUsage(Certificate::KU_CRL_SIGN)) {
                    return $c;
                }
                $found ??= $c;
            }
        }
        return $found;
    }

    /**
     * An administrator-controlled certificate (configured intermediate or anchor) that issued $cert
     * and may sign CRLs.
     */
    public function trustedCrlIssuer(Certificate $cert): ?Certificate
    {
        foreach (array_merge($this->intermediates(), $this->anchors()) as $c) {
            if ($c->fingerprint !== $cert->fingerprint && $c->subjectNameDer === $cert->issuerNameDer
                && $c->hasKeyUsage(Certificate::KU_CRL_SIGN) && $cert->isIssuedBy($c)) {
                return $c;
            }
        }
        return null;
    }

    /**
     * Path of the OpenSSL default CA bundle, if present.
     */
    public static function systemBundle(): ?string
    {
        $loc = openssl_get_cert_locations();
        $candidates = [];
        $env = getenv((string) ($loc['default_cert_file_env'] ?? 'SSL_CERT_FILE'));
        if (is_string($env) && $env !== '') {
            $candidates[] = $env;
        }
        if (!empty($loc['default_cert_file'])) {
            $candidates[] = (string) $loc['default_cert_file'];
        }
        $candidates[] = '/etc/ssl/certs/ca-certificates.crt';
        $candidates[] = '/etc/pki/tls/certs/ca-bundle.crt';
        foreach ($candidates as $c) {
            if (is_file($c) && is_readable($c)) {
                return $c;
            }
        }
        return null;
    }

    /**
     * @return list<Certificate>
     */
    private function loadFile(string $file): array
    {
        $size = @filesize($file);
        if ($size === false || $size > 8 * 1024 * 1024) {
            Log::warning('truststore', 'CA file too large or unreadable', ['file' => $file]);
            return [];
        }
        $data = @file_get_contents($file);
        if ($data === false) {
            return [];
        }
        $out = [];
        foreach (Certificate::splitPemBundle($data, self::MAX_ANCHORS) as $pem) {
            try {
                $out[] = Certificate::fromString($pem);
            } catch (ValidationException) {
                // skip unparsable entries
            }
        }
        return $out;
    }
}
