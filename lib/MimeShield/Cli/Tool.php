<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Cli;

use MimeShield\Config;
use MimeShield\Crypto\CmsService;
use MimeShield\Crypto\SecureTemp;
use MimeShield\Exception\MimeShieldException;
use MimeShield\KeyStore\KeyVault;
use MimeShield\KeyStore\MasterKeyProvider;
use MimeShield\Storage\Database;
use MimeShield\Storage\KeyRecord;
use MimeShield\Trust\TrustStore;

/**
 * Administrator command line tool (bin/mimeshield.sh). Never prints key material.
 */
final class Tool
{
    private int $failures = 0;

    public function __construct(private readonly \rcube $rc, private readonly string $pluginDir)
    {
    }

    /**
     * @param array<int|string, mixed> $args
     */
    public function run(array $args): int
    {
        $cmd = (string) ($args[0] ?? 'help');
        switch ($cmd) {
            case 'diag':
                return $this->diag();
            case 'keygen':
                return $this->keygen((string) ($args['file'] ?? ''), (string) ($args['kid'] ?? ''), !empty($args['append']));
            case 'rotate':
                return $this->rotate(!empty($args['dry-run']));
            case 'check-keystore':
                return $this->checkKeystore();
            default:
                $this->out("MIME Shield administration tool\n\n"
                    . "Usage: plugins/mimeshield/bin/mimeshield.sh <command> [options]  (run from the Roundcube directory as the web server user)\n\n"
                    . "  diag                              check the installation (no secrets are shown)\n"
                    . "  keygen --file=PATH [--kid=ID]     create a new master key file (mode 0400)\n"
                    . "  keygen --file=PATH --append [--kid=ID]\n"
                    . "                                    add a new key to an existing file (rotation step 1)\n"
                    . "  rotate [--dry-run]                re-encrypt all private keys with the active master key\n"
                    . "  check-keystore                    verify that every stored private key can be unlocked\n");
                return $cmd === 'help' ? 0 : 1;
        }
    }

    private function diag(): int
    {
        $cfg = new Config($this->rc->config);

        $this->section('Versions');
        $this->ok('Roundcube', defined('RCMAIL_VERSION') ? RCMAIL_VERSION : 'unknown');
        $this->ok('PHP', PHP_VERSION);
        $this->ok('OpenSSL (PHP)', OPENSSL_VERSION_TEXT);

        $this->section('PHP extensions');
        foreach (['openssl', 'mbstring'] as $ext) {
            $this->check(extension_loaded($ext), 'ext-' . $ext, extension_loaded($ext) ? 'loaded' : 'MISSING');
        }
        $this->check(extension_loaded('intl'), 'ext-intl', extension_loaded('intl') ? 'loaded' : 'missing - internationalised domain names cannot be matched', true);
        $this->check(extension_loaded('sodium'), 'ext-sodium', extension_loaded('sodium') ? 'loaded (XChaCha20-Poly1305 key store)' : 'missing - AES-256-GCM fallback is used', !extension_loaded('sodium'));
        $this->check(extension_loaded('curl') || $cfg->revocationMode() === 'off', 'ext-curl', extension_loaded('curl') ? 'loaded' : 'missing (needed only for CRL checking)', !extension_loaded('curl'));
        foreach (['openssl_cms_sign', 'openssl_cms_verify', 'openssl_cms_encrypt', 'openssl_cms_decrypt', 'openssl_cms_read', 'openssl_pkcs12_read'] as $fn) {
            $this->check(function_exists($fn), $fn . '()', function_exists($fn) ? 'available' : 'MISSING');
        }
        $this->ok('ciphers for new messages', implode(', ', CmsService::supportedCiphers()));
        $this->ok('configured cipher', $cfg->cipher());
        [$legacy] = [@openssl_encrypt('x', 'rc2-40-cbc', '0123456789abcdef', 0, '01234567')];
        $this->ok('OpenSSL legacy provider (RC2)', $legacy !== false ? 'active' : 'not active (legacy RC2 PKCS#12 need conversion)');
        $this->ok('legacy PKCS#12 CLI conversion', $cfg->bool('mimeshield_pkcs12_legacy_cli') ? 'enabled (' . $cfg->get('mimeshield_openssl_bin') . ')' : 'disabled');

        $this->section('Temporary directory');
        try {
            $dir = SecureTemp::prepareDir($cfg->tempBaseDir());
            $t = new SecureTemp($cfg->tempBaseDir());
            $f = $t->file('test');
            $mode = fileperms($f) & 0o777;
            $t->cleanup();
            $this->check($mode === 0o600, 'temp dir ' . $dir, sprintf('writable, files 0%o', $mode));
        } catch (MimeShieldException $e) {
            $this->check(false, 'temp dir', $e->getMessage());
        }

        $this->section('Trust store');
        $store = TrustStore::fromConfig($this->rc->config);
        $files = $store->caInfo();
        $this->check($files !== [], 'CA bundle files', $files !== [] ? implode(', ', $files) : 'NONE - signatures cannot be verified as trusted');
        $this->ok('trust anchors loaded', (string) count($store->anchors()));
        $this->ok('configured intermediates', (string) count($store->intermediates()));
        $this->ok('revocation checking', $cfg->revocationMode());

        $this->section('Master key');
        try {
            $mk = MasterKeyProvider::fromConfig($this->rc->config);
            $kid = $mk->activeKid();
            $this->ok('source', $mk->source());
            $this->ok('key ids', implode(', ', $mk->kids()) . ' (active: ' . $kid . ')');
            $vault = new KeyVault($mk);
            $blob = $vault->encrypt('self-test', 'diag');
            $this->check($vault->decrypt($blob, 'diag') === 'self-test', 'AEAD self-test', 'algorithm ' . (KeyVault::preferredAlgorithm() === KeyVault::ALG_XCHACHA20POLY1305 ? 'XChaCha20-Poly1305' : 'AES-256-GCM'));
        } catch (MimeShieldException $e) {
            $this->check(false, 'master key', $e->getMessage());
        }

        $this->section('Database');
        try {
            $db = new Database($this->rc->get_dbh());
            $v = $db->schemaVersion();
            $this->check($db->isSchemaCurrent(), 'schema mimeshield-version', $v !== '' ? $v . ' (required ' . Database::SCHEMA_VERSION . ')' : 'NOT INSTALLED - run bin/initdb.sh --dir=plugins/mimeshield/SQL');
            if ($v !== '') {
                $row = $db->fetchOne('SELECT COUNT(*) AS cnt FROM ' . $db->table('mimeshield_keys'));
                $this->ok('stored private keys', (string) ($row['cnt'] ?? 0));
                $row = $db->fetchOne('SELECT COUNT(*) AS cnt FROM ' . $db->table('mimeshield_certs'));
                $this->ok('stored contact certificates', (string) ($row['cnt'] ?? 0));
            }
        } catch (\Throwable $e) {
            $this->check(false, 'database', $e->getMessage());
        }

        $this->section('Configuration');
        $plugins = (array) $this->rc->config->get('plugins', []);
        $this->check(in_array('mimeshield', $plugins, true), "'mimeshield' in \$config['plugins']", in_array('mimeshield', $plugins, true) ? 'yes' : 'NO');
        $this->check(is_file($this->pluginDir . '/config.inc.php') || is_file(RCUBE_CONFIG_DIR . 'mimeshield.inc.php'), 'plugin config file',
            is_file($this->pluginDir . '/config.inc.php') ? 'plugins/mimeshield/config.inc.php' : (is_file(RCUBE_CONFIG_DIR . 'mimeshield.inc.php') ? 'config/mimeshield.inc.php' : 'not found - defaults are used'), true);
        $this->ok('encrypt-to-self', $cfg->bool('mimeshield_encrypt_to_self') ? 'on' : 'off');
        $this->ok('Bcc mode', $cfg->bccMode());
        $this->ok('untrusted recipients', $cfg->encryptUntrusted());

        $this->out("\n" . ($this->failures === 0 ? 'Result: OK' : 'Result: ' . $this->failures . ' problem(s) found') . "\n");
        return $this->failures === 0 ? 0 : 2;
    }

    private function keygen(string $file, string $kid, bool $append): int
    {
        if ($file === '' || !str_starts_with($file, '/')) {
            $this->out("--file=ABSOLUTE_PATH is required\n");
            return 1;
        }
        $kid = $kid !== '' ? $kid : 'k' . gmdate('Ymd');
        $line = MasterKeyProvider::generateLine($kid);
        if (is_link($file) || is_link(dirname($file))) {
            $this->out("Refusing to write through a symbolic link: {$file}\n");
            return 1;
        }
        if (file_exists($file) && !$append) {
            $this->out("Refusing to overwrite existing file {$file} (use --append to add a new key for rotation)\n");
            return 1;
        }
        if ($append) {
            if (!is_file($file)) {
                $this->out("File {$file} does not exist\n");
                return 1;
            }
            $existing = (string) file_get_contents($file);
            if (preg_match('/^' . preg_quote($kid, '/') . '\s/m', $existing)) {
                $this->out("Key id {$kid} already exists in {$file}\n");
                return 1;
            }
            // atomic: write a new file next to the old one, then rename (never truncate the only copy)
            $perms = fileperms($file) & 0o777;
            $tmp = $file . '.new.' . bin2hex(random_bytes(4));
            $old = umask(0o277);
            $fh = @fopen($tmp, 'x');
            umask($old);
            $ok = $fh !== false && fwrite($fh, rtrim($existing, "\n") . "\n" . $line . "\n") !== false && fflush($fh);
            if ($fh !== false) {
                fclose($fh);
            }
            if ($ok) {
                @chown($tmp, (int) fileowner($file));
                @chgrp($tmp, (int) filegroup($file));
                @chmod($tmp, $perms);
                $ok = @rename($tmp, $file);
            }
            if (!$ok) {
                @unlink($tmp);
            }
        } else {
            $old = umask(0o277);
            $fh = @fopen($file, 'x');
            umask($old);
            if ($fh === false) {
                $this->out("Cannot create {$file}\n");
                return 1;
            }
            $ok = fwrite($fh, "# MIME Shield master key file - keep secret, never commit, back up securely\n" . $line . "\n") !== false;
            fclose($fh);
            @chmod($file, 0o400);
        }
        KeyVault::wipe($line);
        if (!$ok) {
            $this->out("Writing {$file} failed\n");
            return 1;
        }
        $this->out("Master key '{$kid}' written to {$file}.\n"
            . "Make it readable by the PHP user only, e.g.:  chown root:www-data {$file} && chmod 0440 {$file}\n"
            . "Then set \$config['mimeshield_master_key_file'] = '{$file}';\n"
            . ($append ? "Set \$config['mimeshield_master_key_active'] = '{$kid}'; and run: plugins/mimeshield/bin/mimeshield.sh rotate\n" : '')
            . "BACK UP THIS FILE: without it no stored private key can be used.\n");
        return 0;
    }

    private function rotate(bool $dryRun): int
    {
        $db = new Database($this->rc->get_dbh());
        $vault = new KeyVault(MasterKeyProvider::fromConfig($this->rc->config));
        $active = MasterKeyProvider::fromConfig($this->rc->config)->activeKid();
        $rows = $db->fetchAll('SELECT `key_id`, `user_id`, `fingerprint`, `key_blob`, `key_kid` FROM ' . $db->table('mimeshield_keys'));
        $done = 0;
        $skipped = 0;
        $failed = 0;
        foreach ($rows as $r) {
            if ((string) $r['key_kid'] === $active && KeyVault::blobKid((string) $r['key_blob']) === $active
                && KeyVault::blobVersion((string) $r['key_blob']) === KeyVault::FORMAT_VERSION) {
                $skipped++;
                continue;
            }
            try {
                $ctx = KeyRecord::context((int) $r['user_id'], (string) $r['fingerprint']);
                $new = $vault->rewrap((string) $r['key_blob'], $ctx);
                if (!$dryRun) {
                    $db->query('UPDATE ' . $db->table('mimeshield_keys') . ' SET `key_blob` = ?, `key_kid` = ?, `key_format` = ?, `changed` = ? WHERE `key_id` = ? AND `user_id` = ?',
                        $new, $active, KeyVault::FORMAT_VERSION, Database::now(), (int) $r['key_id'], (int) $r['user_id']);
                }
                $done++;
            } catch (MimeShieldException $e) {
                $failed++;
                $this->out(sprintf("key_id %d (user %d): %s\n", (int) $r['key_id'], (int) $r['user_id'], $e->getMessage()));
            }
        }
        $this->out(sprintf("%s: %d re-encrypted with key '%s', %d already current, %d failed\n", $dryRun ? 'Dry run' : 'Done', $done, $active, $skipped, $failed));
        if (!$dryRun && $failed === 0) {
            $this->out("Old key ids can be removed from the key file once all web servers use the new configuration.\n");
        }
        return $failed === 0 ? 0 : 2;
    }

    private function checkKeystore(): int
    {
        $db = new Database($this->rc->get_dbh());
        $vault = new KeyVault(MasterKeyProvider::fromConfig($this->rc->config));
        $rows = $db->fetchAll('SELECT `key_id`, `user_id`, `fingerprint`, `key_blob`, `cert_pem` FROM ' . $db->table('mimeshield_keys'));
        $bad = 0;
        foreach ($rows as $r) {
            try {
                $pem = $vault->decrypt((string) $r['key_blob'], KeyRecord::context((int) $r['user_id'], (string) $r['fingerprint']));
                $match = openssl_x509_check_private_key((string) $r['cert_pem'], $pem);
                KeyVault::wipe($pem);
                if ($match !== true) {
                    throw new \RuntimeException('key does not match certificate');
                }
            } catch (\Throwable $e) {
                $bad++;
                $this->out(sprintf("key_id %d (user %d): FAILED (%s)\n", (int) $r['key_id'], (int) $r['user_id'], $e->getMessage()));
            }
        }
        $this->out(sprintf("%d keys checked, %d failed\n", count($rows), $bad));
        return $bad === 0 ? 0 : 2;
    }

    private function section(string $title): void
    {
        $this->out("\n== {$title}\n");
    }

    private function ok(string $what, string $value): void
    {
        $this->out(sprintf("  [ OK ] %-34s %s\n", $what, $value));
    }

    private function check(bool $cond, string $what, string $value, bool $warnOnly = false): void
    {
        if (!$cond && !$warnOnly) {
            $this->failures++;
        }
        $this->out(sprintf("  [%s] %-34s %s\n", $cond ? ' OK ' : ($warnOnly ? 'WARN' : 'FAIL'), $what, $value));
    }

    private function out(string $s): void
    {
        fwrite(STDOUT, $s);
    }
}
