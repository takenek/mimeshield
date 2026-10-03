<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield;

use MimeShield\Crypto\CmsService;
use MimeShield\Crypto\SecureTemp;

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
        // Deliberate (audit I-01 decision 2026-10-03): SHA-1 signatures stay accepted with a visible
        // warning, never green (Outlook on the web signs SHA-1); admins may set []. Also governs
        // SHA-1 signed CRLs (I-09).
        'mimeshield_legacy_digests' => ['sha1'],
        'mimeshield_smime_capabilities' => false,
        'mimeshield_encrypt_untrusted' => 'block',
        'mimeshield_max_key_upload' => 102400,
        'mimeshield_max_cert_upload' => 65536,
        'mimeshield_max_keys_per_user' => 20,
        'mimeshield_max_certs_per_user' => 500,
        'mimeshield_max_message_size' => 52428800,
        'mimeshield_max_recipients' => 100,
        'mimeshield_max_total_envelope_bytes' => 268435456,
        'mimeshield_min_rsa_bits' => 2048,
        'mimeshield_ca_bundle' => [],
        'mimeshield_use_system_ca' => false,
        'mimeshield_intermediates' => [],
        'mimeshield_subject_email_fallback' => true,
        // Deliberate (audit I-01 decision 2026-10-03): off by default because 'crl' needs outbound
        // HTTP and discloses checked certificates to CAs; the UI then says "revocation not checked".
        // README/SECURITY recommend 'crl' where egress is allowed.
        'mimeshield_revocation' => 'off',
        'mimeshield_revocation_unknown' => 'warn',
        'mimeshield_revocation_timeout' => 5,
        'mimeshield_revocation_max_bytes' => 10485760,
        'mimeshield_revocation_cache_ttl' => 86400,
        'mimeshield_revocation_allow_hosts' => [],
        'mimeshield_revocation_deny_hosts' => [],
        'mimeshield_revocation_proxy' => '',
        'mimeshield_temp_dir' => '',
        'mimeshield_temp_dir_strict' => false,
        'mimeshield_master_key_file' => '',
        'mimeshield_master_key_env' => 'MIMESHIELD_MASTER_KEY',
        'mimeshield_master_key_active' => '',
        'mimeshield_pkcs12_legacy_cli' => false,
        'mimeshield_openssl_bin' => '/usr/bin/openssl',
        'mimeshield_decrypt_in_compose' => true,
        'mimeshield_require_encrypt_for_decrypted' => false,
        'mimeshield_debug' => false,
    ];

    /** Options only the administrator may set: user preferences under these names are ignored */
    private const ADMIN_ONLY_PREFIX = 'mimeshield_';
    private const USER_PREFS = ['mimeshield_pref_sign', 'mimeshield_pref_encrypt'];

    /** @var null|array<string, mixed> */
    private ?array $adminValues = null;

    private static bool $tempFallbackLogged = false;

    /**
     * @param array<string, mixed> $userPrefs the logged-in user's stored preferences
     */
    public function __construct(private readonly \rcube_config $config, private readonly array $userPrefs = [])
    {
    }

    public function get(string $name): mixed
    {
        // Roundcube merges user preferences over the configuration; a (stale or injected) user
        // preference must never change an administrator option of this plugin
        if (str_starts_with($name, self::ADMIN_ONLY_PREFIX) && !in_array($name, self::USER_PREFS, true)
            && array_key_exists($name, $this->userPrefs)) {
            $admin = $this->adminValues();
            return array_key_exists($name, $admin) ? $admin[$name] : (self::DEFAULTS[$name] ?? null);
        }
        return $this->config->get($name, self::DEFAULTS[$name] ?? null);
    }

    /**
     * Configuration as written by the administrator (fresh load without user preferences).
     *
     * @return array<string, mixed>
     */
    private function adminValues(): array
    {
        if ($this->adminValues === null) {
            $fresh = new \rcube_config();
            $dir = defined('RCUBE_PLUGINS_DIR') ? RCUBE_PLUGINS_DIR : (defined('INSTALL_PATH') ? INSTALL_PATH . 'plugins/' : '');
            if ($dir !== '' && is_file($dir . 'mimeshield/config.inc.php')) {
                $fresh->load_from_file($dir . 'mimeshield/config.inc.php');
            } else {
                $fresh->load_from_file('mimeshield.inc.php');
            }
            $this->adminValues = $fresh->all();
        }
        return $this->adminValues;
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

    /**
     * Recipient whose revocation status cannot be determined (CRL checking on): 'warn' (encrypt, show
     * a warning) or 'block' (treat the certificate as not usable).
     */
    public function revocationUnknownPolicy(): string
    {
        return $this->get('mimeshield_revocation_unknown') === 'block' ? 'block' : 'warn';
    }

    public function encryptUntrusted(): string
    {
        return $this->get('mimeshield_encrypt_untrusted') === 'warn' ? 'warn' : 'block';
    }

    /**
     * Base directory for temporary files (the plugin creates "<base>/mimeshield" with mode 0700).
     *
     * With mimeshield_temp_dir_strict (administrator-only, like every mimeshield_* option) an unusable
     * configured directory is not silently replaced: the system temp directory is still returned, but
     * registered with SecureTemp as refused, so every operation that would write message plaintext
     * there (sign, encrypt, decrypt, verify) fails with 'tempdirunavailable' (audit I-15).
     * Deliberate (audit I-15 decision 2026-10-03): the refusal is enforced lazily where SecureTemp
     * prepares its directory, not by throwing here - the service graph is built for every displayed
     * message and settings page, and a throw here would break plain messages and certificate lists.
     * Default false keeps the fallback (logged and reported by diag) for installations without a
     * dedicated temp directory.
     */
    public function tempBaseDir(): string
    {
        $dir = $this->configuredTempDir();
        $fallback = $dir === '' || !is_dir($dir) || !is_writable($dir);
        $strict = $fallback && $this->bool('mimeshield_temp_dir_strict');
        if ($fallback) {
            if (($dir !== '' || $strict) && !self::$tempFallbackLogged) {
                // never silent: decrypted content may end up on a non-tmpfs, shared directory (INF-03)
                self::$tempFallbackLogged = true;
                if ($strict) {
                    Log::error('config', 'configured temp directory not usable, S/MIME operations refused (mimeshield_temp_dir_strict)', ['dir' => $dir]);
                } else {
                    Log::warning('config', 'configured temp directory not usable, falling back to the system temp directory', ['dir' => $dir]);
                }
            }
            $dir = sys_get_temp_dir();
        }
        $real = realpath($dir);
        $real = $real !== false ? $real : $dir;
        SecureTemp::refuseBaseDir($strict ? $real : null);
        return $real;
    }

    /**
     * The configured temp directory (mimeshield_temp_dir, else Roundcube's temp_dir) is unusable and
     * the system temp directory is used instead.
     */
    public function tempDirIsFallback(): bool
    {
        $dir = $this->configuredTempDir();
        return $dir === '' || !is_dir($dir) || !is_writable($dir);
    }

    /**
     * mimeshield_temp_dir_strict is on and the configured temp directory is unusable: S/MIME
     * operations that need temporary files are refused (audit I-15).
     */
    public function tempDirRefused(): bool
    {
        return $this->bool('mimeshield_temp_dir_strict') && $this->tempDirIsFallback();
    }

    private function configuredTempDir(): string
    {
        $dir = (string) $this->get('mimeshield_temp_dir');
        return $dir !== '' ? $dir : (string) $this->config->get('temp_dir', '');
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
     * Default state of a compose option ('sign' | 'encrypt').
     *
     * The administrator default lives in mimeshield_<opt>_default; the user's own choice is stored
     * as the separate preference mimeshield_pref_<opt> (never under the admin key), so a locked
     * option always uses the administrator value and cannot be overridden by user preferences.
     */
    public function optionDefault(string $opt): bool
    {
        $admin = $this->bool('mimeshield_' . $opt . '_default');
        if (in_array($opt, $this->optionsLock(), true)) {
            return $admin;
        }
        $pref = $this->config->get('mimeshield_pref_' . $opt, null);
        return $pref === null ? $admin : (bool) $pref;
    }

    public function isLocked(string $opt): bool
    {
        return in_array($opt, $this->optionsLock(), true);
    }

    /**
     * @return list<string>
     */
    public function optionsLock(): array
    {
        return array_values(array_intersect($this->list('mimeshield_options_lock'), ['sign', 'encrypt']));
    }
}
