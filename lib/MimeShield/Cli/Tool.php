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
    /** oldest Roundcube release without published security fixes the plugin relies on (MS-14) */
    private const MIN_SECURE_ROUNDCUBE = '1.7.4';

    /**
     * CVE-2026-35189 (excessive memory allocation in relative CRL distribution point processing,
     * certificate parsing): branch => first fixed patch release, from the OpenSSL advisory of
     * 2026-09-29 (3.0.23 is a premium support release; 1.1.1 / 1.0.2 are below the plugin minimum)
     */
    private const CVE_2026_35189_FIXED = ['3.0' => 23, '3.4' => 8, '3.5' => 9, '3.6' => 5, '4.0' => 3];

    /**
     * End of security support per PHP branch, from https://www.php.net/supported-versions.php
     * (update with each PHP release). composer.json deliberately keeps php >=8.1 <8.6: diag warns about
     * an unsupported branch instead of refusing to install (audit I-14 decision 2026-10-03).
     */
    private const PHP_SECURITY_EOL = ['8.1' => '2025-12-31', '8.2' => '2026-12-31', '8.3' => '2027-12-31', '8.4' => '2028-12-31', '8.5' => '2029-12-31'];

    /** worst-case duration of one blocking DNS lookup (seconds) above which diag warns (audit F-14) */
    private const MAX_DNS_LOOKUP_SECONDS = 10;

    /**
     * Resolver options recommended by diag and the documentation (README, SECURITY.md,
     * config.inc.php.dist, THREAT_MODEL): 1 s x 2 attempts x at most 3 name servers (glibc MAXNS)
     * = 6 s, so it stays below MAX_DNS_LOOKUP_SECONDS for every server count (audit F-14).
     */
    public const RECOMMENDED_RESOLVER_OPTIONS = 'options timeout:1 attempts:2';

    private int $failures = 0;

    /** @var resource */
    private $output;

    /**
     * @param resource|null $output stream for the tool output (default STDOUT)
     */
    public function __construct(private readonly \rcube $rc, private readonly string $pluginDir, $output = null)
    {
        $this->output = $output ?? STDOUT;
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
                return $this->keygen((string) ($args['file'] ?? ''), (string) ($args['kid'] ?? ''), !empty($args['append']), !empty($args['create-parent']));
            case 'rotate':
                return $this->rotate(!empty($args['dry-run']));
            case 'check-keystore':
                return $this->checkKeystore();
            default:
                $this->out("MIME Shield administration tool\n\n"
                    . "Usage: plugins/mimeshield/bin/mimeshield.sh <command> [options]  (run from the Roundcube directory as the web server user)\n\n"
                    . "  diag                              check the installation (no secrets are shown)\n"
                    . "  keygen --file=PATH [--kid=ID] [--create-parent]\n"
                    . "                                    create a new master key file (mode 0400); --create-parent\n"
                    . "                                    also creates missing parent directories (mode 0700)\n"
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
        // decrypted mail is rendered by Roundcube core (HTML sanitiser): its security releases matter (MS-14)
        $rcVersion = defined('RCMAIL_VERSION') ? (string) RCMAIL_VERSION : 'unknown';
        $rcRelease = preg_match('/^\d+\.\d+\.\d+$/D', $rcVersion) === 1;
        $rcCurrent = $rcRelease && version_compare($rcVersion, self::MIN_SECURE_ROUNDCUBE, '>=');
        $this->check($rcCurrent, 'Roundcube', $rcVersion . ($rcCurrent ? '' : ($rcRelease
            ? ' - older than ' . self::MIN_SECURE_ROUNDCUBE . ' (security releases): update Roundcube'
            : ' - not a release version: make sure it contains the fixes of ' . self::MIN_SECURE_ROUNDCUBE)), true);
        [$phpOk, $phpText] = self::phpSupportStatus(PHP_VERSION, gmdate('Y-m-d'));
        $this->check($phpOk, 'PHP', $phpText, true);
        $this->ok('OpenSSL (PHP build headers)', OPENSSL_VERSION_TEXT);
        [$libOk, $libText] = self::opensslLibraryStatus();
        $this->check($libOk, 'OpenSSL library (this PHP SAPI)', $libText . ' - check the PHP-FPM SAPI too (php-fpm -i)', true);

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
        $this->check(!$cfg->tempDirIsFallback(), 'configured temp directory', $cfg->tempDirIsFallback()
            ? 'NOT USABLE - falling back to ' . sys_get_temp_dir() . ' (set mimeshield_temp_dir, ideally on tmpfs)' : 'usable', true);
        $dir = $cfg->tempBaseDir();
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
        // decrypted plaintext passes through these files: on disk it may survive in the journal or
        // free blocks after unlink (audit I-15); a warning only - the directory is installation policy
        $real = realpath($dir);
        $mounts = PHP_OS_FAMILY === 'Linux' && is_readable('/proc/mounts') ? @file_get_contents('/proc/mounts') : false;
        [$memOk, $memText] = self::tmpfsStatus(is_string($mounts) ? $mounts : null, $real !== false ? $real : $dir);
        if ($memOk === null) {
            $this->info('temp dir file system', $memText);
        } else {
            $this->check($memOk, 'temp dir file system', $memText, true);
        }

        $this->section('Trust store');
        $store = TrustStore::fromConfig($cfg);
        $files = $store->caInfo();
        $this->check($files !== [], 'CA bundle files', $files !== [] ? implode(', ', $files) : 'NONE - signatures cannot be verified as trusted');
        $this->ok('trust anchors loaded', (string) count($store->anchors()));
        $this->check(!$cfg->bool('mimeshield_use_system_ca'), 'system CA bundle as S/MIME anchors',
            $cfg->bool('mimeshield_use_system_ca') ? 'ENABLED - TLS CAs are trusted for e-mail; configure mimeshield_ca_bundle with S/MIME CAs instead' : 'not used', true);
        $this->ok('configured intermediates', (string) count($store->intermediates()));
        $this->ok('revocation checking', $cfg->revocationMode());
        if ($cfg->revocationMode() === 'crl') {
            // the CRL host name is resolved by a blocking libc lookup that no plugin time budget can
            // interrupt: only the resolver configuration bounds it (audit F-14)
            $resolv = @file_get_contents('/etc/resolv.conf');
            if (is_string($resolv)) {
                [$dnsOk, $dnsText] = self::resolverStatus($resolv);
                $this->check($dnsOk, 'DNS lookup worst case (CRL hosts)', $dnsText, true);
            } else {
                $this->info('DNS lookup worst case (CRL hosts)', '/etc/resolv.conf not readable - check the resolver timeout yourself');
            }
        }
        if ($cfg->revocationMode() === 'crl' && (string) $cfg->get('mimeshield_revocation_proxy') !== '') {
            // through a proxy the plugin cannot pin addresses: the proxy enforces egress (audit I-03)
            $this->check($cfg->list('mimeshield_revocation_allow_hosts') !== [], 'CRL proxy host allow-list',
                $cfg->list('mimeshield_revocation_allow_hosts') !== [] ? 'set' : 'EMPTY - the proxy must restrict CRL egress, or set mimeshield_revocation_allow_hosts', true);
        }

        $this->section('Request time limits');
        // deliberate: request time limits belong to the installation; the plugin only bounds its own
        // expensive work (at most 8 signature checks per request, CRL time budget) (audit F-07 decision
        // 2026-10-03). max_execution_time of the web SAPI cannot be read from the CLI and does not
        // count time spent in system calls on Linux anyway.
        $this->info('web request timeout', 'not visible from the CLI - REQUIRED: request_terminate_timeout (PHP-FPM) or a reverse-proxy timeout');

        $this->section('Master key');
        try {
            $mk = MasterKeyProvider::fromConfig($cfg);
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
                // a stored key alone does not sign: bindings select the signing key of an identity
                $row = $db->fetchOne('SELECT COUNT(*) AS cnt FROM ' . $db->table('mimeshield_bindings'));
                $this->ok('stored identity bindings', (string) ($row['cnt'] ?? 0));
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
        // 'single' reveals the certificates of Bcc recipients to To/Cc recipients (audit I-08)
        $this->check($cfg->bccMode() !== 'single', 'Bcc mode', $cfg->bccMode() === 'single' ? 'single - Bcc recipients are identifiable in RecipientInfos' : $cfg->bccMode(), true);
        $this->ok('untrusted recipients', $cfg->encryptUntrusted());

        $this->out("\n" . ($this->failures === 0 ? 'Result: OK' : 'Result: ' . $this->failures . ' problem(s) found') . "\n");
        return $this->failures === 0 ? 0 : 2;
    }

    private function keygen(string $file, string $kid, bool $append, bool $createParent = false): int
    {
        if ($file === '' || !str_starts_with($file, '/')) {
            $this->out("--file=ABSOLUTE_PATH is required\n");
            return 1;
        }
        if ($createParent && $append) {
            $this->out("--create-parent cannot be combined with --append (the key file must already exist)\n");
            return 1;
        }
        // the directory chain is verified in every mode, also for --append (audit MS-12)
        if (!$this->prepareParentDir(dirname($file), $createParent)) {
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
            // serialise read-modify-rename (a stable lock file: the key file itself is replaced)
            $lock = $this->lockFile($file . '.lock');
            if ($lock === null) {
                return 1;
            }
            try {
                $ok = $this->appendKey($file, $kid, $line);
            } finally {
                flock($lock, LOCK_UN);
                fclose($lock);
            }
            if (!$ok) {
                KeyVault::wipe($line);
                return 1;
            }
        } else {
            $old = umask(0o277);
            error_clear_last();
            $fh = @fopen($file, 'x');
            umask($old);
            if ($fh === false) {
                $err = error_get_last();
                $this->out("Cannot create {$file}" . (is_array($err) ? ': ' . preg_replace('/^fopen\([^)]*\):\s*/', '', $err['message']) : '') . "\n");
                return 1;
            }
            $content = "# MIME Shield master key file - keep secret, never commit, back up securely\n" . $line . "\n";
            $ok = self::writeAll($fh, $content);
            KeyVault::wipe($content);
            if ($ok) {
                @chmod($file, 0o400);
            } else {
                // never leave a truncated key file behind: it would look like a valid one (audit F-12)
                @unlink($file);
            }
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

    /**
     * keygen --append (caller holds the lock): read the existing file strictly, write old content +
     * new line to a new file (every byte checked, fsync, fclose), verify that the new file holds
     * exactly that content - in particular every existing key line - and only then rename it over the
     * key file. Any failure leaves the original untouched (audit F-12). Prints the reason on failure.
     */
    private function appendKey(string $file, string $kid, #[\SensitiveParameter] string $line): bool
    {
        clearstatcache(true, $file);
        $existing = @file_get_contents($file);
        if (!is_string($existing) || trim($existing) === '') {
            $this->out("Cannot read {$file} (or it is empty) - nothing appended\n");
            return false;
        }
        if (preg_match('/^' . preg_quote($kid, '/') . '\s/m', $existing)) {
            $this->out("Key id {$kid} already exists in {$file}\n");
            return false;
        }
        $payload = rtrim($existing, "\n") . "\n" . $line . "\n";
        // atomic: write a new file next to the old one, then rename (never truncate the only copy)
        $perms = fileperms($file) & 0o777;
        $tmp = $file . '.new.' . bin2hex(random_bytes(4));
        $old = umask(0o277);
        $fh = @fopen($tmp, 'x');
        umask($old);
        if ($fh === false) {
            $this->out("Cannot create {$tmp}\n");
            return false;
        }
        $written = fstat($fh);
        $ok = self::writeAll($fh, $payload);
        if ($ok) {
            @chown($tmp, (int) fileowner($file));
            @chgrp($tmp, (int) filegroup($file));
            @chmod($tmp, $perms);
            // the file renamed over the key file must still be the one written above, with exactly
            // the intended content (all previous keys + the new one)
            clearstatcache(true, $tmp);
            $now = @lstat($tmp);
            $ok = is_array($written) && is_array($now) && ($now['mode'] & 0o170000) === 0o100000
                && $now['ino'] === $written['ino'] && $now['dev'] === $written['dev'];
            if (!$ok) {
                $this->out("Refusing to continue: {$tmp} was replaced while it was being written\n");
            } else {
                $check = @file_get_contents($tmp);
                $ok = is_string($check) && hash_equals($payload, $check);
                if (is_string($check)) {
                    KeyVault::wipe($check);
                }
                if (!$ok) {
                    $this->out("Refusing to continue: {$tmp} does not contain the expected keys\n");
                }
            }
            $ok = $ok && @rename($tmp, $file);
        }
        KeyVault::wipe($payload);
        KeyVault::wipe($existing);
        if (!$ok) {
            @unlink($tmp);
            $this->out("Writing {$file} failed - the original file is unchanged\n");
        }
        return $ok;
    }

    /**
     * Write every byte (a short write is retried, no progress is a failure), flush, fsync when
     * available, and close the handle; true only if all of it succeeded.
     *
     * @param resource $fh
     */
    private static function writeAll($fh, #[\SensitiveParameter] string $data): bool
    {
        $ok = true;
        for ($done = 0, $len = strlen($data); $ok && $done < $len; $done += $w) {
            $w = @fwrite($fh, substr($data, $done));
            $ok = is_int($w) && $w > 0;
            $w = (int) $w;
        }
        $ok = $ok && fflush($fh) && (!function_exists('fsync') || fsync($fh));
        return fclose($fh) && $ok;
    }

    /**
     * Exclusive lock on a stable lock file next to the key file (created 0600, never a symlink).
     *
     * @return null|resource
     */
    private function lockFile(string $path)
    {
        if (is_link($path)) {
            $this->out("Refusing to use a symbolic link as lock file: {$path}\n");
            return null;
        }
        $old = umask(0o177);
        $fh = @fopen($path, 'c');
        umask($old);
        $st = $fh !== false ? fstat($fh) : false;
        $ls = @lstat($path);
        if ($fh === false || !is_array($st) || !is_array($ls) || ($ls['mode'] & 0o170000) !== 0o100000
            || $st['ino'] !== $ls['ino'] || $st['dev'] !== $ls['dev']) {
            if ($fh !== false) {
                fclose($fh);
            }
            $this->out("Cannot open lock file {$path}\n");
            return null;
        }
        if (!flock($fh, LOCK_EX)) {
            fclose($fh);
            $this->out("Cannot lock {$path}\n");
            return null;
        }
        return $fh;
    }

    /**
     * The directory of the key file must exist, be a real directory and be writable. Missing
     * directories are only created on the administrator's explicit request (--create-parent): one
     * level at a time with mkdir() (which fails if the final name exists, also as a symbolic link,
     * but does follow symbolic links in the ancestor path), mode 0700 for the current user. In every
     * mode (new file, --append, --create-parent) every existing component of the path, including the
     * parent directory itself, must not be a symbolic link, owned by a user other than root / the
     * current user, or writable by other users without the sticky bit (audit MS-12).
     */
    private function prepareParentDir(string $dir, bool $create): bool
    {
        if (is_link($dir)) {
            $this->out("Refusing to write through a symbolic link: {$dir}\n");
            return false;
        }
        if (file_exists($dir)) {
            if (!is_dir($dir)) {
                $this->out("Parent path {$dir} exists but is not a directory\n");
                return false;
            }
            if (!is_writable($dir)) {
                $this->out("Parent directory {$dir} is not writable by the current user ({$this->currentUser()}).\n"
                    . "Run keygen as a user that may write there (e.g. root) and then adjust ownership of the key file.\n");
                return false;
            }
            // the existing parent goes through the same path-chain check below (in every mode)
        } elseif (!$create) {
            $this->out("Parent directory {$dir} does not exist.\n"
                . "keygen does not create directories on its own. Create it deliberately with restrictive permissions,\n"
                . "readable only by the group the PHP process runs as, e.g.:\n"
                . '  install -d -m 0750 -o root -g PHP_GROUP ' . escapeshellarg($dir) . "\n"
                . "(PHP_GROUP: the group of the web server / PHP-FPM user, e.g. www-data, apache or nginx)\n"
                . "and run keygen again, or pass --create-parent to create it with mode 0700 for the current user.\n");
            return false;
        }

        // the path is checked (and created) component by component: no "." / ".." / empty segments
        $parts = $dir === '/' ? [] : explode('/', substr($dir, 1));
        foreach ($parts as $p) {
            if ($p === '' || $p === '.' || $p === '..') {
                $this->out("keygen needs a normalised absolute path (no '.', '..' or '//'): {$dir}\n");
                return false;
            }
        }
        // every existing component from "/" down is checked with lstat(): a symbolic link anywhere in
        // the chain, a component owned by another user (only root and the current user are trusted)
        // or one writable by group/others without the sticky bit stops the operation
        $euid = function_exists('posix_geteuid') ? posix_geteuid() : (int) getmyuid();
        $base = '/';
        $missing = [];
        foreach (array_merge([''], $parts) as $i => $name) {
            $path = $i === 0 ? '/' : $base . ($base === '/' ? '' : '/') . $name;
            if ($missing !== []) {
                $missing[] = $name;
                continue;
            }
            clearstatcache(true, $path);
            $st = @lstat($path);
            if ($st === false) {
                $missing[] = $name;
                continue;
            }
            if (($st['mode'] & 0o170000) === 0o120000) {
                $this->out("Refusing to use {$dir}: {$path} is a symbolic link (use the real path)\n");
                return false;
            }
            if (($st['mode'] & 0o170000) !== 0o040000) {
                $this->out("Refusing to use {$dir}: {$path} is not a directory\n");
                return false;
            }
            if ($st['uid'] !== 0 && $st['uid'] !== $euid) {
                $this->out("Refusing to use {$dir}: {$path} is owned by uid {$st['uid']} (only root or the current user are trusted)\n");
                return false;
            }
            if (($st['mode'] & 0o022) !== 0 && ($st['mode'] & 0o1000) === 0) {
                $this->out("Refusing to use {$dir}: {$path} is writable by other users (and not sticky)\n");
                return false;
            }
            $base = $path;
        }
        if ($missing === []) {
            return true; // the whole path exists and passed the checks: nothing to create
        }
        $old = umask(0o077);
        try {
            foreach ($missing as $name) {
                $base .= ($base === '/' ? '' : '/') . $name;
                error_clear_last();
                if (!@mkdir($base, 0o700)) {
                    $err = error_get_last();
                    $this->out("Cannot create directory {$base}" . (is_array($err) ? ': ' . preg_replace('/^mkdir\(\):\s*/', '', $err['message']) : '') . "\n");
                    return false;
                }
                clearstatcache(true, $base);
                if (is_link($base) || !is_dir($base)) {
                    $this->out("Refusing to continue: {$base} was replaced while it was being created\n");
                    return false;
                }
            }
        } finally {
            umask($old);
        }
        $this->out("Created directory {$dir} (mode 0700, owner {$this->currentUser()}).\n"
            . 'Allow the PHP process to read it, e.g.:  chgrp PHP_GROUP ' . escapeshellarg($dir) . ' && chmod 0750 ' . escapeshellarg($dir) . "\n");
        return true;
    }

    private function currentUser(): string
    {
        $uid = function_exists('posix_geteuid') ? posix_geteuid() : (int) getmyuid();
        $pw = function_exists('posix_getpwuid') ? posix_getpwuid($uid) : false;
        return (is_array($pw) ? $pw['name'] . ', ' : '') . 'uid ' . $uid;
    }

    private function rotate(bool $dryRun): int
    {
        $db = new Database($this->rc->get_dbh());
        $mk = MasterKeyProvider::fromConfig(new Config($this->rc->config));
        $vault = new KeyVault($mk);
        $active = $mk->activeKid();
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
        $vault = new KeyVault(MasterKeyProvider::fromConfig(new Config($this->rc->config)));
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

    /**
     * Version of the OpenSSL library actually loaded by this PHP SAPI (not the build headers) and
     * whether it is below a release with a known fix relevant to certificate parsing.
     *
     * @return array{0: bool, 1: string}
     */
    private static function opensslLibraryStatus(): array
    {
        ob_start();
        try {
            (new \ReflectionExtension('openssl'))->info();
        } finally {
            $info = (string) ob_get_clean();
        }
        if (!preg_match('/OpenSSL Library Version\s*(?:=>|<\/td><td[^>]*>)\s*([^\n<]+)/', $info, $m)) {
            return [false, 'unknown'];
        }
        return self::opensslVersionStatus(trim($m[1]));
    }

    /**
     * Whether an OpenSSL library version text (e.g. "OpenSSL 3.5.7 9 Jun 2026") is below the release
     * of its branch that fixes a known issue. Only the upstream version is visible: distributions may
     * backport the fix without changing it, so a version below the fix is a warning, not a proof.
     * Branches not listed (other libraries, end-of-life branches, newer releases) give no warning.
     * Deliberate (audit F-16 decision 2026-10-03): end-of-life branches 3.1-3.3 are not warned about,
     * because the CVE-2026-35189 advisory lists fixed versions for supported branches only; such
     * libraries are out of support anyway, and CertPrecheck refuses the triggering certificates in
     * the plugin's own input paths before OpenSSL parses them.
     *
     * @return array{0: bool, 1: string}
     *
     * @internal public for tests
     */
    public static function opensslVersionStatus(string $text): array
    {
        if (preg_match('/\bOpenSSL (\d+)\.(\d+)\.(\d+)/', $text, $v)) {
            $branch = $v[1] . '.' . $v[2];
            $fixedPatch = self::CVE_2026_35189_FIXED[$branch] ?? null;
            if ($fixedPatch !== null && (int) $v[3] < $fixedPatch) {
                return [false, sprintf('%s - below %s.%d (CVE-2026-35189) unless the distribution backported the fix', $text, $branch, $fixedPatch)];
            }
        }
        return [true, $text];
    }

    /**
     * Whether the PHP branch of a version (e.g. "8.1.33") is still within its security support on
     * $today (Y-m-d). Branches not in the table (newer releases) give no warning.
     *
     * @return array{0: bool, 1: string}
     *
     * @internal public for tests
     */
    public static function phpSupportStatus(string $version, string $today): array
    {
        if (preg_match('/^(\d+\.\d+)\./', $version, $m)) {
            $eol = self::PHP_SECURITY_EOL[$m[1]] ?? null;
            if ($eol !== null && $today > $eol) {
                return [false, sprintf('%s - PHP %s security support ended %s: upgrade, PHP >= 8.3 recommended', $version, $m[1], $eol)];
            }
        }
        return [true, $version];
    }

    /**
     * Whether $path lies on a memory file system (tmpfs / ramfs) according to the text of
     * /proc/mounts (null: unknown, e.g. not Linux). The longest mount point that is a path prefix of
     * $path (resolved by the caller) wins; octal escapes of the mount table (\040 = space) are decoded.
     *
     * @return array{0: ?bool, 1: string}
     *
     * @internal public for tests
     */
    public static function tmpfsStatus(?string $mounts, string $path): array
    {
        $best = null;
        $type = '';
        foreach ($mounts === null ? [] : explode("\n", $mounts) as $row) {
            $f = preg_split('/\s+/', trim($row));
            if ($f === false || count($f) < 3) {
                continue;
            }
            $mp = preg_replace_callback('/\\\\([0-7]{3})/', static fn (array $o): string => chr((int) octdec($o[1])), $f[1]);
            $mp = $mp === '/' ? '/' : rtrim((string) $mp, '/');
            $prefix = $mp === '/' || $path === $mp || str_starts_with($path, $mp . '/');
            // equal length: the later entry is the one mounted on top
            if ($prefix && ($best === null || strlen($mp) >= strlen($best))) {
                $best = $mp;
                $type = $f[2];
            }
        }
        if ($best === null) {
            return [null, 'cannot be determined (no /proc/mounts) - use tmpfs for mimeshield_temp_dir'];
        }
        if (in_array($type, ['tmpfs', 'ramfs'], true)) {
            return [true, $type . ' (' . $best . ')'];
        }
        return [false, $type . ' (' . $best . ') - decrypted content is written to disk: put mimeshield_temp_dir on tmpfs'];
    }

    /**
     * Worst-case duration of one blocking host name lookup from the text of /etc/resolv.conf:
     * timeout x attempts x name servers (glibc defaults timeout 5, attempts 2; rotate changes only
     * the order). A warning above MAX_DNS_LOOKUP_SECONDS.
     *
     * @return array{0: bool, 1: string}
     *
     * @internal public for tests
     */
    public static function resolverStatus(string $resolvConf): array
    {
        $servers = 0;
        $timeout = 5;
        $attempts = 2;
        foreach (explode("\n", $resolvConf) as $row) {
            $row = trim((string) preg_replace('/[#;].*$/', '', $row));
            if (preg_match('/^nameserver\s+\S/', $row)) {
                $servers = min($servers + 1, 3);   // glibc uses the first 3 (MAXNS)
            } elseif (preg_match('/^options\s+(.*)$/', $row, $o)) {
                foreach (preg_split('/\s+/', $o[1]) ?: [] as $opt) {
                    if (preg_match('/^timeout:(\d+)$/', $opt, $v)) {
                        $timeout = min((int) $v[1], 30);   // glibc caps at 30 (RES_MAXRETRANS)
                    } elseif (preg_match('/^attempts:(\d+)$/', $opt, $v)) {
                        $attempts = min((int) $v[1], 5);   // glibc caps at 5 (RES_MAXRETRY)
                    }
                }
            }
        }
        $worst = $timeout * $attempts * max(1, $servers);
        $text = sprintf('%d s (timeout %d x attempts %d x %d name server(s))', $worst, $timeout, $attempts, max(1, $servers));
        if ($worst > self::MAX_DNS_LOOKUP_SECONDS) {
            return [false, $text . ' - reduce it to at most ' . self::MAX_DNS_LOOKUP_SECONDS . ' s, e.g. "'
                . self::RECOMMENDED_RESOLVER_OPTIONS . '", or use a local caching resolver'];
        }
        return [true, $text];
    }

    private function section(string $title): void
    {
        $this->out("\n== {$title}\n");
    }

    private function ok(string $what, string $value): void
    {
        $this->out(sprintf("  [ OK ] %-34s %s\n", $what, $value));
    }

    /** informational line: never counts as a problem */
    private function info(string $what, string $value): void
    {
        $this->out(sprintf("  [INFO] %-34s %s\n", $what, $value));
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
        fwrite($this->output, $s);
    }
}
