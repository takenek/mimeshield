<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\KeyStore;

use MimeShield\Exception\ConfigException;
use MimeShield\Log;

/**
 * Loads the installation master key(s) used to wrap users' private keys.
 *
 * Sources (first configured wins):
 *  1. environment variable (default name MIMESHIELD_MASTER_KEY): "kid:base64[,kid:base64...]"
 *  2. key file (config mimeshield_master_key_file): one key per line "kid base64", '#' comments.
 *
 * Several keys may be present to allow rotation; the active key (used for new encryptions) is the
 * one named by mimeshield_master_key_active or, if unset, the LAST key listed. Old keys stay
 * available for decryption until every record was re-wrapped (bin/mimeshield.sh rotate).
 *
 * The key never comes from the database and is never generated implicitly.
 */
final class MasterKeyProvider
{
    public const KEY_BYTES = 32;

    /** @var array<string, string> kid => raw key */
    private array $keys = [];

    private string $activeKid = '';

    private string $source = '';

    /**
     * @param string $file      Path of the key file ('' = not used)
     * @param string $envName   Environment variable name ('' = not used)
     * @param string $activeKid Explicit active key id ('' = last key)
     * @param list<string> $forbiddenRoots Directories the key file must not be inside (web roots)
     */
    public function __construct(
        private readonly string $file,
        private readonly string $envName = 'MIMESHIELD_MASTER_KEY',
        string $activeKid = '',
        private readonly array $forbiddenRoots = [],
    ) {
        $this->activeKid = $activeKid;
    }

    /**
     * Build from Roundcube configuration.
     */
    public static function fromConfig(\rcube_config $config): self
    {
        $roots = [];
        if (defined('RCUBE_INSTALL_PATH')) {
            $roots[] = rtrim(RCUBE_INSTALL_PATH, '/') . '/public_html';
            $roots[] = rtrim(RCUBE_INSTALL_PATH, '/') . '/plugins';
        }
        if (!empty($_SERVER['DOCUMENT_ROOT']) && is_string($_SERVER['DOCUMENT_ROOT'])) {
            $roots[] = $_SERVER['DOCUMENT_ROOT'];
        }

        return new self(
            (string) $config->get('mimeshield_master_key_file', ''),
            (string) $config->get('mimeshield_master_key_env', 'MIMESHIELD_MASTER_KEY'),
            (string) $config->get('mimeshield_master_key_active', ''),
            $roots,
        );
    }

    /**
     * Raw key for $kid.
     */
    public function key(string $kid): string
    {
        $this->load();
        if (!isset($this->keys[$kid])) {
            Log::error('masterkey', 'requested master key id not available', ['kid' => $kid]);
            throw new ConfigException('keystoreunavailable', 'unknown master key id');
        }
        return $this->keys[$kid];
    }

    public function activeKid(): string
    {
        $this->load();
        return $this->activeKid;
    }

    /**
     * @return list<string>
     */
    public function kids(): array
    {
        $this->load();
        return array_keys($this->keys);
    }

    public function source(): string
    {
        $this->load();
        return $this->source;
    }

    /**
     * Generate a new key line ("kid base64") - used by the CLI tool only.
     */
    public static function generateLine(string $kid): string
    {
        if (!preg_match('/^[a-z0-9]{1,16}$/D', $kid)) {
            throw new ConfigException('internalerror', 'invalid key id');
        }
        return $kid . ' ' . base64_encode(random_bytes(self::KEY_BYTES));
    }

    private function load(): void
    {
        if ($this->keys !== []) {
            return;
        }

        // build into locals and publish only after every check passed: a broken configuration must
        // fail on every call, never be cached as a partial success
        $keys = [];
        $env = $this->envName !== '' ? getenv($this->envName) : false;
        if (is_string($env) && $env !== '') {
            foreach (explode(',', $env) as $entry) {
                $p = explode(':', trim($entry), 2);
                if (count($p) !== 2) {
                    throw new ConfigException('keystoreunavailable', 'malformed master key environment variable');
                }
                self::addKey($keys, $p[0], $p[1]);
            }
            $source = 'env';
        } elseif ($this->file !== '') {
            $keys = $this->loadFile();
            $source = 'file';
        } else {
            throw new ConfigException('keystoreunavailable', 'no master key configured');
        }

        if ($keys === []) {
            throw new ConfigException('keystoreunavailable', 'master key source contains no key');
        }
        $active = $this->activeKid;
        if ($active === '') {
            $kids = array_keys($keys);
            $active = (string) end($kids);
        } elseif (!isset($keys[$active])) {
            throw new ConfigException('keystoreunavailable', 'configured active master key id not found');
        }

        $this->keys = $keys;
        $this->activeKid = $active;
        $this->source = $source;
    }

    /**
     * @return array<string, string>
     */
    private function loadFile(): array
    {
        $path = $this->file;
        if (!str_starts_with($path, '/')) {
            throw new ConfigException('keystoreunavailable', 'master key file path must be absolute');
        }
        clearstatcache(true, $path);
        $real = realpath($path);
        if ($real === false || !is_file($real) || !is_readable($real)) {
            throw new ConfigException('keystoreunavailable', 'master key file not readable');
        }
        foreach ($this->forbiddenRoots as $root) {
            $r = realpath($root);
            if ($r !== false && ($real === $r || str_starts_with($real, rtrim($r, '/') . '/'))) {
                Log::error('masterkey', 'master key file is inside a web-accessible or plugin directory - refusing');
                throw new ConfigException('keystoreunavailable', 'master key file inside forbidden directory');
            }
        }
        $perms = fileperms($real);
        if ($perms !== false && ($perms & 0o007) !== 0) {
            Log::error('masterkey', 'master key file is world-accessible - refusing (chmod 0400/0440)');
            throw new ConfigException('keystoreunavailable', 'master key file permissions too open');
        }
        $size = filesize($real);
        if ($size === false || $size > 16384) {
            throw new ConfigException('keystoreunavailable', 'master key file too large');
        }
        $data = file_get_contents($real);
        if ($data === false) {
            throw new ConfigException('keystoreunavailable', 'master key file not readable');
        }
        $keys = [];
        foreach (preg_split('/\r?\n/', $data) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $p = preg_split('/\s+/', $line);
            if ($p === false || count($p) !== 2) {
                throw new ConfigException('keystoreunavailable', 'malformed master key file line');
            }
            self::addKey($keys, $p[0], $p[1]);
        }
        return $keys;
    }

    /**
     * @param array<string, string> $keys
     */
    private static function addKey(array &$keys, string $kid, string $b64): void
    {
        $kid = trim($kid);
        if (!preg_match('/^[a-z0-9]{1,16}$/D', $kid)) {
            throw new ConfigException('keystoreunavailable', 'invalid master key id');
        }
        $raw = base64_decode(trim($b64), true);
        if ($raw === false || strlen($raw) !== self::KEY_BYTES) {
            throw new ConfigException('keystoreunavailable', 'master key must be 32 random bytes, base64 encoded');
        }
        if (isset($keys[$kid])) {
            throw new ConfigException('keystoreunavailable', 'duplicate master key id');
        }
        $keys[$kid] = $raw;
    }
}
