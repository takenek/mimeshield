<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Trust;

use MimeShield\Cert\Certificate;
use MimeShield\Config;
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
 * Note: OpenSSL treats an empty ca_info array as "use the default store", so the list passed to
 * OpenSSL is always built explicitly here and is never empty (a placeholder is used otherwise).
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
     * Issuer certificate of $cert among the given (untrusted) certificates, the configured
     * intermediates and the trust anchors. Shared by signature verification and recipient
     * resolution, so that revocation checking finds the same issuer in both paths (audit MS-04).
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
        foreach (array_merge($candidates, $this->intermediates(), $this->anchors()) as $c) {
            if ($c->fingerprint !== $cert->fingerprint && $cert->isIssuedBy($c)) {
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
