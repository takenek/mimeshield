# MIME Shield (`mimeshield`) – S/MIME for Roundcube 1.7

[![CI](https://github.com/takenek/mimeshield/actions/workflows/ci.yml/badge.svg)](https://github.com/takenek/mimeshield/actions/workflows/ci.yml)
[![Packagist](https://img.shields.io/packagist/v/takenek/mimeshield.svg)](https://packagist.org/packages/takenek/mimeshield)
[![License](https://img.shields.io/packagist/l/takenek/mimeshield.svg)](LICENSE)

MIME Shield adds complete S/MIME support to Roundcube Webmail 1.7.x using only the official plugin
API (no changes to Roundcube core):

* **sign** outgoing mail (clear-signed `multipart/signed`, `application/pkcs7-signature`,
  `smime.p7s`, SHA-256),
* **verify** incoming signatures (clear-signed and opaque, `x-pkcs7-*` aliases) with separate
  status for signature, certificate chain, sender address, validity, key usage and revocation,
* **encrypt** (AES-256-CBC by default, multiple recipients, Cc/Bcc, encrypt-to-self, separate
  envelopes for Bcc) and **decrypt** (AES-CBC/GCM, 3DES legacy, RSA PKCS#1/OAEP, ECDH),
* **sign + encrypt**, nested/triple-wrapped messages on receipt,
* **PKCS#12 (.p12/.pfx) and PEM import**, private keys stored **encrypted** (AEAD with an
  installation master key kept outside the database),
* certificates per **Roundcube identity**, key rotation (old keys stay for decryption),
* **recipient certificate store** (import, save from signed messages, preferred certificate,
  fingerprint-change warning),
* **trust validation** against an administrator-defined CA bundle, optional SSRF-safe CRL checks,
* UI in Settings, Compose and message view (Elastic skin), English and Polish translations,
* CLI diagnostics and master-key tools.

Created and maintained by **[Marek Królikowski (TaKeN)](https://github.com/takenek)**,
operating as **TaKeN.PL Usługi Informatyczne Marek Królikowski**.

Documentation: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) ·
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) · [SECURITY.md](SECURITY.md) ·
[docs/INTEROPERABILITY.md](docs/INTEROPERABILITY.md) · [docs/TESTING.md](docs/TESTING.md) ·
[CHANGELOG.md](CHANGELOG.md)

---

## 1. Requirements

| Component | Requirement |
|---|---|
| Roundcube | 1.7.5 or later 1.7.x security release (`min-version` 1.7.5: the release of 2026-10-19 fixes bypasses of the remote-content blocking in the core HTML sanitiser - CVE-2026-114722, CVE-2026-114728, CVE-2026-114729 - on which the plugin relies for decrypted mail, and a session deserialization flaw, CVE-2026-114724; tested: see [Compatibility](#9-compatibility)), Elastic skin. Check <https://roundcube.net/news/> for newer security releases (`composer audit` cannot: the Packagist advisory feed does not carry the Roundcube CVEs). `min-version` is enforced only by the Composer plugin installer, and a core installed from Packagist reports `1.7-git`, which passes every 1.7.x threshold (audit N-01): `diag`, which warns below 1.7.5 and notes when a newer release than the one known at the plugin's release date is installed, is the main version control |
| PHP | 8.1 – 8.5 accepted (composer `php >=8.1 <8.6`); PHP ≥ 8.3 recommended. Run the current patch level of the branch: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 of 2026-10-21 fix CVE-2026-109618 and CVE-2026-109619 (critical, in the request-handling layer of every SAPI), 8.1 has no fix. `diag` warns below these levels (or when a distribution backport cannot be told apart) and once a PHP branch is past its security support (audit I-14 decision, V-14) |
| PHP extensions | `openssl` (with CMS functions, OpenSSL ≥ 3.0; keep the library loaded by PHP-FPM patched — for CVE-2026-35189 ≥ 3.0.23 / 3.4.8 / 3.5.9 / 3.6.5 / 4.0.3 on the respective branch or a distribution backport; `diag` shows the library version and warns for a branch whose upstream security support has ended - 1.1.1, 3.1, 3.2, 3.3, 3.4, 3.6 and, from 2026-09-07, 3.0 - which is acceptable only as a distribution package with backported fixes), `mbstring`; recommended: `intl` (internationalised domain names), `sodium` (XChaCha20-Poly1305 key store; otherwise AES-256-GCM), `curl` (only for CRL checks) |
| Database | whatever Roundcube 1.7 supports: MySQL/MariaDB, PostgreSQL, SQLite |
| OpenSSL CLI | optional, only for converting legacy RC2 PKCS#12 files (`mimeshield_pkcs12_legacy_cli`) |

**Installation requirements** (deliberate design decisions of the 2026-10-03 audit, see
[SECURITY.md](SECURITY.md#design-decisions-and-accepted-risks); `diag` checks or reminds of each):

* **OpenSSL with the CVE-2026-35189 fix** in the library loaded by PHP-FPM (versions above). The
  plugin's `CertPrecheck` refuses the triggering certificates in its own input paths, but other
  libcrypto use is only protected by the update (F-16).
* **A request time limit**: `request_terminate_timeout` in the PHP-FPM pool or a reverse-proxy read
  timeout. The plugin bounds only its own work (8 signature checks, CRL budget, a structure budget
  for decrypted content) and does not limit the number of MIME parts of the original message (F-07).
* **With `mimeshield_revocation = 'crl'`: resolver timeouts**, e.g. `options timeout:1 attempts:2`
  in `/etc/resolv.conf` (worst case 6 s with up to 3 name servers; `diag` warns above 10 s), or a
  local caching resolver; synchronous DNS lookups cannot be interrupted
  without losing the SSRF pinning (F-14).
* **Temp directory on tmpfs** (`mimeshield_temp_dir`, e.g. under `/dev/shm`); optionally
  `mimeshield_temp_dir_strict = true` to refuse S/MIME operations rather than fall back to the
  system temp directory (I-15). Hardened profile: a dedicated directory owned by the PHP user, mode
  0700, with strict mode on.
* **With `mimeshield_revocation_proxy`: `mimeshield_revocation_allow_hosts`** is required; a proxy
  without the allow-list disables CRL checking (every status "unknown", logged, `diag` FAIL) because
  the plugin cannot pin the connected address through a proxy (V-12).
* Recommended: enable `mimeshield_revocation = 'crl'` wherever outbound HTTP from the web server is
  allowed (default `off`, audit I-01 decision).

## 2. Installation

All commands are run in the Roundcube installation directory (e.g. `/var/www/roundcube`).

### 2.1 Install the plugin files

**git / tarball**

```sh
cd /var/www/roundcube/plugins
git clone https://github.com/takenek/mimeshield.git mimeshield
```

The directory **must** be named `plugins/mimeshield`.

**Composer** (Roundcube's plugin installer)

```sh
cd /var/www/roundcube
composer require "takenek/mimeshield:^1.0"    # a tagged release; never dev-main in production
```

MIME Shield is published on [Packagist](https://packagist.org/packages/takenek/mimeshield).
Production installations should use a signed, tagged release by version constraint; never install
`dev-main` in production. See [docs/RELEASING.md](docs/RELEASING.md) (section 2 for installation
and section 3 for verifying the tag signature).

For deliberate testing of unreleased code only, add the repository as a Composer VCS repository
and pin an explicitly reviewed commit:

```sh
composer config repositories.mimeshield vcs https://github.com/takenek/mimeshield
composer require "takenek/mimeshield:dev-main#<commit-sha>"
```

The installer (roundcube/plugin-installer) copies `config.inc.php.dist` to
`plugins/mimeshield/config.inc.php`, creates the database tables (unless `SKIP_DB_INIT` is set) and
asks whether to enable the plugin — skip 2.3 and 2.5 then, and edit
`plugins/mimeshield/config.inc.php` (a `config/mimeshield.inc.php` is read only when the plugin
directory contains no `config.inc.php`).

### 2.2 Generate the master key

The master key encrypts the users' private keys. It must not be inside the database. The plugin
refuses key files that are group-writable or accessible by others (mode bits 027) and key files
under `<roundcube>/public_html/`, `<roundcube>/plugins/` or the web server document root; keeping it
outside the whole Roundcube directory is recommended.

```sh
plugins/mimeshield/bin/mimeshield.sh keygen --file=/etc/roundcube/mimeshield.key
chown root:www-data /etc/roundcube/mimeshield.key      # group = the PHP-FPM / web server user
chmod 0440 /etc/roundcube/mimeshield.key
```

`keygen` does not create a missing parent directory on its own; it stops with a message and an
example. Create the directory deliberately, e.g.
`install -d -m 0750 -o root -g www-data /etc/roundcube` (group = the PHP-FPM / web server user),
or pass `--create-parent`: missing directories are then created with mode 0700 for the user running
the tool. It refuses (and creates nothing) when any existing component of the path, from `/` down,
is a symbolic link (give the real path), is owned by a user other than root or the user running the
tool, or is writable by group/others without the sticky bit. Adjust the group and mode of the new
directories afterwards so the PHP process can read the key.

Back this file up **separately from database backups** (without it stored keys are unusable;
with it plus a DB dump all keys are exposed). Alternative: provide the key in the environment
variable `MIMESHIELD_MASTER_KEY` (`kid:base64`) of the PHP-FPM pool. Prefer the file (outside the
web root, readable only by the PHP user, e.g. 0440 root:www-data): an environment variable takes
precedence when both are set and is visible to every script of the pool and to diagnostics such as
`phpinfo()` (audit I-13).

### 2.3 Create the database tables

```sh
bin/initdb.sh --dir=plugins/mimeshield/SQL
```

The script uses the Roundcube database configuration and honours `$config['db_prefix']`.
For later plugin upgrades:

```sh
bin/updatedb.sh --package=mimeshield --dir=plugins/mimeshield/SQL
```

### 2.4 Configure the plugin

```sh
cp plugins/mimeshield/config.inc.php.dist plugins/mimeshield/config.inc.php
# or put the settings into config/mimeshield.inc.php
```

Minimum settings:

```php
$config['mimeshield_master_key_file'] = '/etc/roundcube/mimeshield.key';
// CA certificates you trust for S/MIME (PEM bundle). Distribution bundles contain TLS roots only.
$config['mimeshield_ca_bundle'] = ['/etc/roundcube/smime-ca-bundle.pem'];
// default false: the system (TLS) CA bundle is not trusted for e-mail
$config['mimeshield_use_system_ca'] = false;
```

Build `smime-ca-bundle.pem` from the S/MIME roots your organisation approves (e.g. roots carrying
the "email" trust bit of a root programme, or the roots of the CAs your correspondents use).
Enabling `mimeshield_use_system_ca` trusts every public TLS CA for signatures and recipients;
`diag` warns while it is enabled.

For the Actalis "S/MIME Mailbox Validated" certificates, the bundle should contain the root
"Actalis Authentication Root CA" (current hierarchy, issuing CA "Actalis Client Authentication
CA G3") and, for newer certificates, "Actalis SMIME RSA Root CA 2025" — both downloadable from
Actalis' legal repository. All options are documented in `config.inc.php.dist`.

### 2.5 Enable the plugin

In `config/config.inc.php`:

```php
$config['plugins'] = [ /* ... */ 'mimeshield'];
```

If the `enigma` plugin is enabled too, both work side by side; PGP and S/MIME cannot be selected
for the same message.

### 2.6 File system permissions

* `plugins/mimeshield` readable by the web server, not writable.
* The master key file: `0400`/`0440`, owner root, group = PHP user. The plugin refuses a file with
  group-write or any other-access bits and logs a warning (once per process; `diag` WARN) when the
  file, the CA bundle or an intermediate bundle is owned by a user other than root or the PHP
  process user; a world-writable trust bundle is refused outright (audit V-10).
* Temporary files: Roundcube `temp_dir` (or `mimeshield_temp_dir`) must be writable by the PHP
  user; the plugin creates a private `mimeshield/` subdirectory with mode `0700`. A tmpfs is
  recommended (e.g. `$config['mimeshield_temp_dir'] = '/dev/shm/roundcube';`, directory owned by
  the PHP user, mode 0700). If it is unusable the plugin falls back to the system temp directory
  (logged, `diag`), where the subdirectory is named `mimeshield-<uid>` so that another PHP user's
  installation on the same host cannot occupy it (V-11); `mimeshield_temp_dir_strict = true`
  refuses sign/encrypt/decrypt/verify instead (error "the server's temporary directory cannot be
  used"; certificate chains then show as untrusted).
* The CRL disk cache (`<temp>/mimeshield/crl`) and its `mimeshield` parent must be private
  directories, owned by the PHP user with mode 0700. An unsafe directory disables disk caching;
  review its ownership and contents before restoring access. The plugin does not repair it.
* Logs: `<log_dir>/mimeshield` (or syslog, depending on `log_driver`).
* Web server: only `plugins/mimeshield/{js,skins}` need to be reachable over HTTP. Deny HTTP access
  to `plugins/mimeshield/{bin,lib,SQL,tests,docs,localization}` and the configuration, e.g. for
  nginx `location ~ ^/plugins/mimeshield/(bin|lib|SQL|tests|docs|localization|config\.inc\.php) { deny all; }`
  (with Roundcube's `public_html` document root, plugin files are served only through
  `static.php`, which delivers static asset types; the rule matters for installations whose
  document root is the Roundcube directory itself). The directories `bin/`, `lib/`, `SQL/`, `docs/`,
  `localization/` and `tests/` ship a `.htaccess` with `Require all denied` for Apache 2.4 installations
  that honour `AllowOverride` (audit N-10); nginx needs the rule above. Release archives built
  with `git archive` leave out `tests/` and developer tooling (`.gitattributes`).
* `keygen` refuses a key file directory (or any parent) that is a symbolic link, owned by a user
  other than root / the current user, or writable by group/others without the sticky bit — in
  every mode, including `--append`.

### 2.7 Test the installation

```sh
sudo -u www-data plugins/mimeshield/bin/mimeshield.sh diag
```

The command checks Roundcube/PHP/OpenSSL versions (warning for Roundcube older than 1.7.5, with a
note when a newer release than the one known at the plugin's release date exists; for PHP below the
patch level that fixes CVE-2026-109618/109619 - 8.2.35, 8.3.36, 8.4.27, 8.5.12 - or past the end of
its security support; for an OpenSSL library below the CVE-2026-35189 fix of its branch — 3.0.23,
3.4.8, 3.5.9, 3.6.5, 4.0.3 — and for an OpenSSL branch whose upstream security support has ended;
only the upstream version number is visible, so a distribution backport is not detected; the CLI
SAPI may load a different OpenSSL than PHP-FPM — compare with `php-fpm -i`). Since F-16 the plugin
also refuses, before any OpenSSL call, certificates with more than 8 or relative
(nameRelativeToCRLIssuer) CRL distribution points or a duplicate cRLDistributionPoints extension
(`CertPrecheck`), since V-08 also inside uploaded PKCS#12 files. `diag` further checks the PHP
branch support date, extensions, CMS functions, the temp directory (0600 files; warning when the
configured directory is not usable), whether the temp directory is on tmpfs/ramfs, the resolver
worst case with CRL checking (warning above 10 seconds per lookup), a CRL proxy without
`mimeshield_revocation_allow_hosts` (FAIL: CRL checking is disabled, V-12), reminds that a
PHP-FPM/proxy request timeout is required, checks the CA bundle (warning while the system TLS
bundle is trusted) and the ownership of the trust files, the master key (AEAD self-test, never
printed; WARN for a key taken from an environment variable, which every PHP-FPM worker inherits, or
for a key file owned by another user), the effective size limits against PHP's `memory_limit`
(V-06), the database schema (with the number of stored private keys, identity bindings and contact
certificates) and the configuration. Exit code 0 = OK (warnings such as a missing `intl` do
not fail). If the plugin directory is a symlink, set `ROUNDCUBE_INSTALL_PATH=/var/www/roundcube`.

## 3. Using it

### 3.1 Importing a PKCS#12 / PFX (e.g. Actalis)

1. Settings → **S/MIME certificates** → *Import*.
2. Select the `.p12` / `.pfx` file, enter its password, *Import*.
3. The details page shows Subject, Issuer, e-mail address, serial number, SHA-256 fingerprint,
   validity, key usage, extended key usage, key algorithm/size and chain status.
4. If the certificate is valid for signing, it is assigned automatically to every identity whose
   e-mail address it contains, unless that identity already uses a valid certificate that expires
   later. The assignment is stored right away (a confirmation says so); nothing needs to be saved.
   To change it, tick or untick identities under *Use for signing messages from* and click *Save*
   (enabled only while the selection differs from the stored one).

The password is used only for the import. If the import says the file uses an outdated algorithm
(RC2), re-export the certificate from Windows with **AES256-SHA256** (certificate export wizard)
or convert it:

```sh
openssl pkcs12 -legacy -in old.pfx -nodes | openssl pkcs12 -export -out new.p12
```

(or enable `mimeshield_pkcs12_legacy_cli`).

### 3.2 Correspondents' certificates

* Open a signed message → *Save sender certificate to S/MIME contacts* (offered only when the
  signature is valid and matches the sender), or
* Settings → **S/MIME contacts** → *Import* (`.cer`, `.crt`, `.pem`, `.der`, `.p7b`, `.p7c`).
  Importing the same certificate again together with its CA chain updates the stored chain.

If a different certificate already exists for an address, the import shows both fingerprints and
requires confirmation. Confirmation applies only to the file shown in that dialog. Opening another
import form preserves it; a stale dialog from another tab cannot confirm a replacement file.

### 3.3 Compose

Users choose their default state in Preferences → Encryption → *S/MIME (MIME Shield)* unless
the administrator locked it (`mimeshield_options_lock`).

The *Options and attachments* sidebar contains **Sign S/MIME** and **Encrypt S/MIME** with the
certificate status of the selected identity and the certificate status of each recipient.
If encryption is requested and a recipient has no usable certificate, the message is **not sent**;
you can cancel or explicitly choose *Send without encryption*. Replies and forwards of decrypted
messages are encrypted by default and the dialog warns that the quoted content was encrypted; with
`mimeshield_require_encrypt_for_decrypted = true` the server refuses to send or save them without
encryption, including when the plugin database schema is unavailable. Such a compose is never kept
in the browser's local storage (Roundcube's `compose_save_localstorage`). The compose sidebar also
warns that decryption does not establish the original sender's identity: review recipients and
quoted content before sending.

### 3.4 Reading

Signed and encrypted messages show a status bar with icon and text (not only colour), e.g.
"S/MIME signature valid. Certificate trusted. Sender address matches.", or warnings such as
"certificate expired", "issuer not trusted", "certificate does not match the sender",
"Revocation status: not checked". *Certificate details* expands the full certificate data.
In addition, every message shows a compact S/MIME indicator in the header area, outside the message
content (also "Not signed with S/MIME"): a status bar drawn by the content of a message cannot
replace it. If revocation was not checked, the headline and header indicator explicitly warn about
that limitation even when the signature and chain are otherwise valid. For `multipart/signed`
messages only the signed first part is shown, rebuilt from the
verified bytes; the container must declare `protocol="application/pkcs7-signature"` (or the `x-`
variant) and its second part must be the signature. Downloads, inline resources and compose use
the same first-part parser even when they do not evaluate signature trust. At most 8 signed
entities are extracted or verified per request.

When the plugin offers *Save sender certificate* for a certificate whose issuer is not trusted and
`mimeshield_encrypt_untrusted = 'warn'`, the certificate is stored only after a confirmation that
shows its fingerprint (and the fingerprints of certificates it replaces).

### 3.5 Key rotation

Import the new certificate; it becomes the signing certificate of the matching identities (when it
is valid and newer). Keep the old one: it is still used to decrypt older messages. Deleting a
private key shows a warning because messages encrypted for it can no longer be decrypted.

## 4. Master key rotation

```sh
plugins/mimeshield/bin/mimeshield.sh keygen --file=/etc/roundcube/mimeshield.key --append --kid=k2
# config: $config['mimeshield_master_key_active'] = 'k2';
plugins/mimeshield/bin/mimeshield.sh rotate --dry-run
plugins/mimeshield/bin/mimeshield.sh rotate
plugins/mimeshield/bin/mimeshield.sh check-keystore
# then remove the line of the old key id from the key file (keygen's default id is k<YYYYMMDD>;
# key ids are 1-16 characters a-z0-9)
```

`--append` refuses an unreadable or empty key file, serialises concurrent runs with the lock file
`<key file>.lock` (mode 0600, may stay in place) and replaces the key file only after the new file
was completely written, synced and read back with every existing key line.

## 5. Upgrade

Replace the plugin files, then run `bin/updatedb.sh --package=mimeshield
--dir=plugins/mimeshield/SQL` and `plugins/mimeshield/bin/mimeshield.sh diag`. Read
`CHANGELOG.md`. `bin/mimeshield.sh check-keystore` reports private keys still stored in the v1 blob
format of the first builds (one data key shared by both AEAD algorithms): run `rotate` once (section
4, also with an unchanged master key) to re-encrypt them in the current per-algorithm format (audit
N-04).

**Always run the schema update.** While the plugin tables are missing or outdated, S/MIME is not
available: sending (and saving drafts) is **refused** whenever protection is expected — the user
requested it, or `mimeshield_sign_default` / `mimeshield_encrypt_default` / `mimeshield_options_lock`
require it — with "S/MIME protection is required for this message, but MIME Shield is not
available". Messages without expected protection are sent normally.

## 6. Rollback / uninstall

1. Remove `'mimeshield'` from `$config['plugins']` — Roundcube works normally again; S/MIME mail is
   then shown by Roundcube as "encrypted message" / with an `smime.p7s` attachment.
2. Optional data removal (irreversible – users lose their stored private keys; make sure they
   still have their PKCS#12 files):

   MySQL / MariaDB:
   ```sql
   DROP TABLE `mimeshield_cert_emails`, `mimeshield_certs`, `mimeshield_bindings`, `mimeshield_keys`;
   DELETE FROM `system` WHERE `name` = 'mimeshield-version';
   ```
   PostgreSQL:
   ```sql
   DROP TABLE mimeshield_cert_emails, mimeshield_certs, mimeshield_bindings, mimeshield_keys;
   DROP SEQUENCE mimeshield_keys_seq, mimeshield_certs_seq;
   DELETE FROM "system" WHERE name = 'mimeshield-version';
   ```
   SQLite:
   ```sql
   DROP TABLE mimeshield_cert_emails; DROP TABLE mimeshield_certs;
   DROP TABLE mimeshield_bindings; DROP TABLE mimeshield_keys;
   DELETE FROM system WHERE name = 'mimeshield-version';
   ```
   With `$config['db_prefix']` (e.g. `rc_`) every name gets the prefix: the tables, the `system`
   table (`rc_system`) and the PostgreSQL sequences (`rc_mimeshield_keys_seq`, ...).
3. Remove `plugins/mimeshield`, the plugin configuration and – after the data is gone – destroy
   the master key file securely.

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| "key store is not configured" | master key file missing, unreadable, world-readable or inside the web root – run `diag` |
| "database schema missing" | run `bin/initdb.sh --dir=plugins/mimeshield/SQL` |
| "S/MIME protection is required ... MIME Shield is not available" on send | schema missing or outdated after an upgrade: run `bin/updatedb.sh --package=mimeshield --dir=plugins/mimeshield/SQL` |
| Recipient shown "revocation status could not be checked" | CRL checking is on and no current CRL could be used for that certificate **or one of its intermediate CAs** (every certificate of the path is checked; a CA certificate without an http(s) CRL distribution point is undetermined) — check egress/proxy, `mimeshield_revocation_allow_hosts`; an unreachable distribution point is retried after 5 minutes; with `mimeshield_revocation_unknown = 'block'` such recipients are refused |
| "Too many attempts" | limit of key imports (10 / 5 min per session and per user), recipient checks (30 / min per session) or "save sender certificate" (20 / min per session and per user); wait and retry |
| Signature "malformed" / decryption error for a message other clients accept | the embedded certificates have risky CRL distribution points (CVE-2026-35189 pre-check) or the CMS structure cannot be read by the plugin's parser; refused deliberately before OpenSSL |
| Signature "not verified: too many signatures" | the message contains more than 8 signed parts; only the first 8 are verified |
| Valid signatures shown as "issuer not trusted" | add the CA root to `mimeshield_ca_bundle` |
| "chain incomplete" for Outlook on the web mail | OWA does not include intermediates by default – add them to `mimeshield_intermediates` |
| PFX import "outdated algorithm (RC2)" | see 3.1 |
| Signing checkbox disabled | identity has no valid certificate bound / certificate expired / address not in certificate |
| Details | `<log_dir>/mimeshield` (enable `mimeshield_debug` for more, never contains secrets) |

## 8. Security

See [SECURITY.md](SECURITY.md). In short: private keys are encrypted at rest with a master key
outside the database; they are used only on the server and never exported; an attacker who
controls the web server process can use the keys (inherent to server-side S/MIME).

## 9. Compatibility

Tested versions and the exact test results are listed in [docs/TESTING.md](docs/TESTING.md):
Roundcube 1.7.0, 1.7.1, 1.7.2, 1.7.3, 1.7.4 (git tags; 1.7.4 also as the official signed release
tarball; since the security remediation of 2026-10-02 the supported minimum was 1.7.4, since
2026-11-04 it is 1.7.5, whose changelog touches no plugin API used here), PHP 8.1, 8.2, 8.3, 8.4, 8.5, OpenSSL 3.5, MariaDB 11.8, PostgreSQL 17, SQLite 3, Chromium
154 for the browser tests. Interoperability status (NSS = Thunderbird's crypto library, gpgsm,
OpenSSL) is documented in [docs/INTEROPERABILITY.md](docs/INTEROPERABILITY.md) — Microsoft Outlook
and the Thunderbird application itself were **not** available in the test environment; a manual
checklist is provided.

## 10. Known limitations

* No RFC 9788 header protection (subjects are not encrypted); no OCSP; no opaque-signing option for
  outgoing mail; no S/MIME for skins other than Elastic; SmtpUTF8Mailbox (internationalised local
  parts) not supported.
* Encryption algorithm for new messages is global (no per-recipient capability negotiation).
* Decrypted attachments that are forwarded/re-edited are written by Roundcube core to its temp
  directory in plaintext (core `filesystem_attachments` behaviour).
* With `bcc_mode = separate`, if the delivery of the main message fails after Bcc copies were
  accepted, a retry can send duplicate Bcc copies. The error message then says that the Bcc
  recipients already have the message. Separate SMTP envelopes cannot be delivered atomically
  (accepted, audit I-07).
* When decrypting, only own keys matching a RecipientInfo are tried; if none match, at most 5 other
  keys are tried (for clients that encode the recipient identifier differently, audit I-18). A
  message naming one own key but encrypted to another does not decrypt.
* Recipient checks are limited per session and per account, key and certificate imports per
  session and atomically per user (the account quota is committed before import; a quota storage
  failure blocks imports), certificate detail pages per session (V-07); limits per IP
  and request time limits belong to the reverse proxy / WAF and PHP-FPM in front of Roundcube.
* `mimeshield_max_message_size` and `mimeshield_max_total_envelope_bytes` are capped at runtime at
  1/6 and 1/2 of PHP's `memory_limit` (a processed S/MIME part exists in several copies in memory;
  V-06): with the default `memory_limit = 128M` the effective message limit is about 21 MB, shown by
  `diag`. Raise `memory_limit` for larger encrypted messages. Decrypted or unwrapped content is
  parsed only within a structure budget (500 entities, forwarded messages 8 deep, retained nested
  bodies at most twice the size limit; V-05): a message beyond it shows "message too large" for that
  part.
* CRL transfers share a 10-second budget and an 8-download limit per request. A synchronous DNS
  lookup already in progress cannot be interrupted by the plugin; configure resolver timeouts and
  PHP-FPM's `request_terminate_timeout` as the hard request lifetime bound.
* `multipart/signed` messages without the `protocol` parameter (non-conforming senders) are not
  verified; the signature part is then shown as an attachment.

## 11. Author

**MIME Shield** was created and is maintained by **[Marek Królikowski (TaKeN)](https://github.com/takenek)**.

Business name: **TaKeN.PL Usługi Informatyczne Marek Królikowski**.

Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski.

Project repository: [github.com/takenek/mimeshield](https://github.com/takenek/mimeshield)

## 12. License

GPL-3.0-or-later (same as Roundcube; see [LICENSE](LICENSE)). Roundcube's plugin exception allows
plugins under other licenses, GPL-3.0-or-later was chosen for consistency with the ecosystem.

See [COPYRIGHT](COPYRIGHT) for the copyright holder, author attribution and narrowly scoped
additional terms under GPLv3 section 7(b) and 7(c). These preserve source attribution and require
modified versions to identify their changes; they do not prohibit forks, renaming, commercial use
or charging for distribution. Earlier releases retain the terms under which they were received.

## 13. Security review

The code was reviewed with Anthropic's Mythos 5.1 on 2026-11-04 (full source review, dependency and
platform advisory check, remediation of every accepted finding in release 1.0.3; see
[CHANGELOG.md](CHANGELOG.md) and [SECURITY.md](SECURITY.md)). An automated review is not a
certification: report anything it missed as described in SECURITY.md.
