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

namespace MimeShield;

use MimeShield\Cert\KeyImporter;
use MimeShield\Cert\LegacyPkcs12Converter;
use MimeShield\Cert\PublicCertImporter;
use MimeShield\Crypto\CmsService;
use MimeShield\Exception\StorageException;
use MimeShield\KeyStore\KeyVault;
use MimeShield\KeyStore\MasterKeyProvider;
use MimeShield\Mime\IncomingProcessor;
use MimeShield\Service\CertificateService;
use MimeShield\Service\KeyService;
use MimeShield\Service\OutgoingService;
use MimeShield\Service\SignatureVerifier;
use MimeShield\Storage\CertRepository;
use MimeShield\Storage\Database;
use MimeShield\Storage\KeyRepository;
use MimeShield\Trust\ChainValidator;
use MimeShield\Trust\RevocationChecker;
use MimeShield\Trust\SafeHttpClient;
use MimeShield\Trust\SharedCacheCrlNumberStore;
use MimeShield\Trust\TrustStore;

/**
 * Lazily built service graph for one request.
 *
 * The user id always comes from the authenticated Roundcube session ($rcmail->user->ID), never
 * from request parameters.
 */
final class Services
{
    private ?Database $db = null;
    private ?KeyService $keys = null;
    private ?CertificateService $certs = null;
    private ?TrustStore $trust = null;
    private ?ChainValidator $chains = null;
    private ?RevocationChecker $revocation = null;
    private ?SignatureVerifier $verifier = null;
    private ?IncomingProcessor $incoming = null;
    private ?MasterKeyProvider $master = null;

    public function __construct(private readonly \rcube $rc, public readonly Config $config)
    {
    }

    public function userId(): int
    {
        $id = (int) ($this->rc->user->ID ?? 0);
        if ($id <= 0) {
            throw new StorageException('notloggedin', 'no authenticated user');
        }
        return $id;
    }

    public function db(): Database
    {
        return $this->db ??= new Database($this->rc->get_dbh());
    }

    public function masterKeys(): MasterKeyProvider
    {
        // built from the protected configuration: a user preference named like an administrator
        // option can never change the master key source or the trust anchors (audit MS-13)
        return $this->master ??= MasterKeyProvider::fromConfig($this->config);
    }

    public function vault(): KeyVault
    {
        return new KeyVault($this->masterKeys());
    }

    public function cms(): CmsService
    {
        return new CmsService($this->config->tempBaseDir(), $this->config->bool('mimeshield_smime_capabilities'));
    }

    public function trustStore(): TrustStore
    {
        return $this->trust ??= TrustStore::fromConfig($this->config);
    }

    public function chains(): ChainValidator
    {
        return $this->chains ??= new ChainValidator($this->trustStore(), $this->config->tempBaseDir());
    }

    public function revocation(): RevocationChecker
    {
        if ($this->revocation === null) {
            $http = null;
            if ($this->config->revocationMode() === RevocationChecker::MODE_CRL) {
                $http = new SafeHttpClient(
                    $this->config->int('mimeshield_revocation_timeout', 1, 30),
                    min(3, $this->config->int('mimeshield_revocation_timeout', 1, 30)),
                    [80, 443],
                    $this->config->list('mimeshield_revocation_allow_hosts'),
                    $this->config->list('mimeshield_revocation_deny_hosts'),
                    (string) $this->config->get('mimeshield_revocation_proxy'),
                );
            }
            $this->revocation = new RevocationChecker(
                $this->config->revocationMode(),
                $http,
                $this->config->tempBaseDir() . '/mimeshield',
                $this->config->int('mimeshield_revocation_max_bytes', 65536, 104857600),
                $this->config->int('mimeshield_revocation_cache_ttl', 60, 604800),
                acceptSha1: in_array('sha1', $this->config->legacyDigests(), true),
                crlNumbers: $http !== null ? $this->crlNumberStore() : null,
            );
        }
        return $this->revocation;
    }

    /**
     * Highest cRLNumber per CRL issuer/scope in Roundcube's shared cache (audit I-02). Always the db
     * driver (table cache_shared): deliberately not rcube::get_cache_shared(), which is off unless a
     * "<name>_cache" option is set and whose driver/TTL options could be overridden by user
     * preferences (audit I-02 decision 2026-10-03). Without the cache there is no rollback tracking.
     */
    private function crlNumberStore(): ?SharedCacheCrlNumberStore
    {
        try {
            $cache = \rcube_cache::factory('db', 0, SharedCacheCrlNumberStore::PREFIX, SharedCacheCrlNumberStore::TTL);
            return new SharedCacheCrlNumberStore($cache);
        } catch (\Throwable $e) {
            Log::info('revocation', 'CRL number tracking disabled: shared cache unavailable (' . $e->getMessage() . ')');
            return null;
        }
    }

    public function verifier(): SignatureVerifier
    {
        return $this->verifier ??= new SignatureVerifier(
            $this->chains(),
            $this->trustStore(),
            $this->revocation(),
            $this->config->allowedDigests(),
            $this->config->legacyDigests(),
            $this->config->bool('mimeshield_subject_email_fallback'),
            $this->config->int('mimeshield_min_rsa_bits', 1024, 16384),
        );
    }

    public function keys(): KeyService
    {
        if ($this->keys === null) {
            $legacy = null;
            $bin = (string) $this->config->get('mimeshield_openssl_bin');
            if ($this->config->bool('mimeshield_pkcs12_legacy_cli') && LegacyPkcs12Converter::isAvailable($bin)) {
                $legacy = new LegacyPkcs12Converter($bin);
            }
            $this->keys = new KeyService(
                new KeyRepository($this->db(), $this->userId()),
                $this->vault(),
                new KeyImporter($this->config->int('mimeshield_max_key_upload', 1024, 1048576), $this->config->int('mimeshield_min_rsa_bits', 1024, 16384)),
                $legacy,
                $this->config->int('mimeshield_max_keys_per_user', 1, 1000),
                $this->config->bool('mimeshield_subject_email_fallback'),
            );
        }
        return $this->keys;
    }

    public function certs(): CertificateService
    {
        return $this->certs ??= new CertificateService(
            new CertRepository($this->db(), $this->userId()),
            new PublicCertImporter($this->config->int('mimeshield_max_cert_upload', 1024, 1048576)),
            $this->chains(),
            $this->revocation(),
            $this->keys(),
            $this->config->int('mimeshield_max_certs_per_user', 1, 100000),
            $this->config->encryptUntrusted(),
            $this->config->bool('mimeshield_subject_email_fallback'),
            $this->trustStore(),
            $this->config->revocationUnknownPolicy(),
            fn () => array_values(array_filter(array_map(
                static fn ($i) => (string) ($i['email'] ?? ''),
                (array) $this->rc->user->list_identities()
            ))),
        );
    }

    public function outgoing(): OutgoingService
    {
        return new OutgoingService(
            $this->keys(),
            $this->certs(),
            $this->cms(),
            $this->config->cipher(),
            $this->config->bool('mimeshield_encrypt_to_self'),
            $this->config->bool('mimeshield_encrypt_drafts'),
            $this->config->bccMode(),
            $this->config->int('mimeshield_max_message_size', 65536, PHP_INT_MAX),
            $this->config->int('mimeshield_max_recipients', 1, 1000),
            $this->config->int('mimeshield_max_total_envelope_bytes', 1048576, PHP_INT_MAX),
        );
    }

    /**
     * @param bool $verify Verify signatures (show/preview/print only)
     */
    public function incoming(bool $verify, bool $allowDecrypt = true): IncomingProcessor
    {
        $rc = $this->rc;
        return $this->incoming ??= new IncomingProcessor(
            $this->keys(),
            $this->cms(),
            $verify ? $this->verifier() : null,
            static fn () => $rc->get_storage(),
            $this->config->int('mimeshield_max_message_size', 65536, PHP_INT_MAX),
            $allowDecrypt,
        );
    }

    public function hasIncoming(): bool
    {
        return $this->incoming !== null;
    }
}
