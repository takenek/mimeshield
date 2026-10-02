<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield;

use MimeShield\Crypto\CmsService;

/**
 * Typed access to the plugin configuration (config.inc.php) with safe defaults.
 *
 * Every option documented in config.inc.php.dist has its default here; values are validated and
 * clamped so a broken configuration cannot weaken security (e.g. unknown cipher -> AES-256-CBC).
 */
final class Config
{
    public const DEFAULTS = [
        'mimeshield_enable_signing' => true,
        'mimeshield_enable_encryption' => true,
        'mimeshield_sign_default' => false,
        'mimeshield_encrypt_default' => false,
        'mimeshield_options_lock' => [],
        'mimeshield_encrypt_to_self' => true,
        'mimeshield_encrypt_drafts' => true,
        'mimeshield_bcc_mode' => 'separate',
        'mimeshield_cipher' => CmsService::CIPHER_AES_256_CBC,
        'mimeshield_allowed_digests' => ['sha256', 'sha384', 'sha512'],
        'mimeshield_legacy_digests' => ['sha1'],
        'mimeshield_smime_capabilities' => false,
        'mimeshield_encrypt_untrusted' => 'block',
        'mimeshield_max_key_upload' => 102400,
        'mimeshield_max_cert_upload' => 65536,
        'mimeshield_max_keys_per_user' => 20,
        'mimeshield_max_certs_per_user' => 500,
        'mimeshield_max_message_size' => 52428800,
        'mimeshield_max_recipients' => 100,
        'mimeshield_min_rsa_bits' => 2048,
        'mimeshield_ca_bundle' => [],
        'mimeshield_use_system_ca' => true,
        'mimeshield_intermediates' => [],
        'mimeshield_subject_email_fallback' => true,
        'mimeshield_revocation' => 'off',
        'mimeshield_revocation_timeout' => 5,
        'mimeshield_revocation_max_bytes' => 10485760,
        'mimeshield_revocation_cache_ttl' => 86400,
        'mimeshield_revocation_allow_hosts' => [],
        'mimeshield_revocation_deny_hosts' => [],
        'mimeshield_revocation_proxy' => '',
        'mimeshield_temp_dir' => '',
        'mimeshield_master_key_file' => '',
        'mimeshield_master_key_env' => 'MIMESHIELD_MASTER_KEY',
        'mimeshield_master_key_active' => '',
        'mimeshield_pkcs12_legacy_cli' => false,
        'mimeshield_openssl_bin' => '/usr/bin/openssl',
        'mimeshield_decrypt_in_compose' => true,
        'mimeshield_debug' => false,
    ];

    public function __construct(private readonly \rcube_config $config)
    {
    }

    public function get(string $name): mixed
    {
        return $this->config->get($name, self::DEFAULTS[$name] ?? null);
    }

    public function bool(string $name): bool
    {
        return (bool) $this->get($name);
    }

    public function int(string $name, int $min = 0, int $max = PHP_INT_MAX): int
    {
        return max($min, min($max, (int) $this->get($name)));
    }

    /**
     * @return list<string>
     */
    public function list(string $name): array
    {
        return array_values(array_filter(array_map(static fn ($v) => strtolower(trim((string) $v)), (array) $this->get($name)), static fn ($v) => $v !== ''));
    }

    public function cipher(): string
    {
        $c = strtolower((string) $this->get('mimeshield_cipher'));
        return in_array($c, CmsService::supportedCiphers(), true) ? $c : CmsService::CIPHER_AES_256_CBC;
    }

    public function bccMode(): string
    {
        return $this->get('mimeshield_bcc_mode') === 'single' ? 'single' : 'separate';
    }

    public function revocationMode(): string
    {
        return $this->get('mimeshield_revocation') === 'crl' ? 'crl' : 'off';
    }

    public function encryptUntrusted(): string
    {
        return $this->get('mimeshield_encrypt_untrusted') === 'warn' ? 'warn' : 'block';
    }

    /**
     * Base directory for temporary files (the plugin creates "<base>/mimeshield" with mode 0700).
     */
    public function tempBaseDir(): string
    {
        $dir = (string) $this->get('mimeshield_temp_dir');
        if ($dir === '') {
            $dir = (string) $this->config->get('temp_dir', '');
        }
        if ($dir === '' || !is_dir($dir) || !is_writable($dir)) {
            $dir = sys_get_temp_dir();
        }
        $real = realpath($dir);
        return $real !== false ? $real : $dir;
    }

    /**
     * Digests accepted without warning on verification. MD5 can never be enabled.
     *
     * @return list<string>
     */
    public function allowedDigests(): array
    {
        return array_values(array_diff($this->list('mimeshield_allowed_digests'), ['md5']));
    }

    /**
     * @return list<string>
     */
    public function legacyDigests(): array
    {
        return array_values(array_diff($this->list('mimeshield_legacy_digests'), ['md5']));
    }

    /**
     * @return list<string>
     */
    public function optionsLock(): array
    {
        return array_values(array_intersect($this->list('mimeshield_options_lock'), ['sign', 'encrypt']));
    }
}
