# Security policy – MIME Shield

## Reporting a vulnerability

Please report security problems **privately**, not in public issues:

* GitHub: use "Report a vulnerability" (private security advisory) on the repository
  `takenek/mimeshield`, or
* e-mail the maintainer (address in the repository profile), preferably S/MIME-encrypted.

Include the affected version, configuration (redact secrets), steps to reproduce and impact. You
will receive an acknowledgement within 7 days. Please allow a reasonable time for a fix before
public disclosure. Never send real private keys, PKCS#12 files, master keys or mailbox content.

## Supported versions

Only the latest release receives security fixes.

## How private keys are protected

* Imported private keys are stored in the database **encrypted with authenticated encryption**:
  XChaCha20-Poly1305 (libsodium) or AES-256-GCM (OpenSSL) when libsodium is unavailable.
* The 256-bit data key is derived (HKDF-SHA256) from an **installation master key** that is kept
  outside the database, outside the web root and outside the plugin directory (key file with mode
  0400/0440, or an environment variable). The plugin refuses key files that are group-writable or
  accessible by others (mode bits 027) and key files under `public_html/`, `plugins/` or the web
  server document root.
* Every record has its own random nonce, a 128-bit authentication tag, a key identifier (for
  rotation) and a format version. The ciphertext is bound (associated data) to the user id and the
  certificate fingerprint; tampering or moving a blob to another row is detected. The stored
  certificate must match that fingerprint, and an own certificate is used as an encryption
  recipient (own addresses, encrypt-to-self) only after its key blob authenticated under the
  master key — a key row inserted or modified directly in the database cannot redirect encrypted
  mail to a foreign certificate.
* Private keys are decrypted only in PHP memory for the duration of one signing/decryption
  operation, handed to OpenSSL as PEM strings (never written to disk), and wiped afterwards (best
  effort — PHP does not guarantee memory erasure).
* Private keys are never sent to the browser and **cannot be exported** (feature intentionally not
  implemented). Public certificates can be downloaded.
* PKCS#12 passwords are used once during import and are never stored, logged or kept in the
  session. Before OpenSSL reads an uploaded PKCS#12, the plugin checks every password-based KDF
  cost parameter, including those inside encrypted layers (decrypted with the entered password for
  this check). The file is inspected along the PKCS#12 structure on exactly the bytes OpenSSL reads
  (BER segments joined); content that cannot be inspected is refused, as is a key encryption scheme
  whose cost parameters the plugin does not know. The key derivation the
  inspection runs itself is bounded by its real work, and key imports are limited per session and
  per user account (10 within 5 minutes). The account quota is reserved in a database transaction
  before import starts, across sessions and workers. Failure to store the reservation blocks import.

## Master key

* Generate: `plugins/mimeshield/bin/mimeshield.sh keygen --file=/etc/roundcube/mimeshield.key`
  (32 random bytes from `random_bytes()`, file created with `O_EXCL`, mode 0400).
* Back it up **separately** from database backups. Losing it makes all stored private keys
  unusable (users would have to re-import their PKCS#12 files). Stealing it together with a
  database dump reveals all private keys.
* Rotate: `keygen --append` → set `mimeshield_master_key_active` → `plugins/mimeshield/bin/mimeshield.sh rotate` →
  `plugins/mimeshield/bin/mimeshield.sh check-keystore` → remove the old key line. `--append`
  refuses an unreadable or empty key file, serialises concurrent runs with a lock file
  (`<key file>.lock`, mode 0600) and replaces the key file only after the new file was written
  completely, synced and read back with every existing key.
* Never commit it, never put it into `config.inc.php.dist`, never place it inside the Roundcube
  directory tree.

## Important security assumptions

* The server, the PHP process account and the Roundcube installation are trusted. Anyone who can
  execute code as the PHP user (or read its memory / the master key) can use every stored private
  key. Server-side S/MIME cannot protect against a compromised server. Users who need protection
  against the server operator must keep their keys on their own devices.
* Trust anchors (CA bundle) are chosen by the administrator. Distribution bundles usually contain
  TLS roots only; add the S/MIME roots your users need. The system (TLS) bundle is **not** trusted
  by default (`mimeshield_use_system_ca = false`), and OpenSSL's default CA directory
  (`OPENSSLDIR/certs`, `SSL_CERT_DIR`) is never consulted: a chain is trusted only when it ends in
  a configured anchor, for every key type and purpose, and OpenSSL verifies exactly that path. For EC
  recipients, every CA on the path must allow e-mail protection (EKU), as OpenSSL enforces for RSA
  recipients.
* Revocation is not checked unless `mimeshield_revocation = 'crl'` is configured (the UI says
  "Revocation status: not checked", with an explicit warning in the headline and header indicator).
  With CRL checking on, every certificate of the validated path
  below the anchor (end entity and intermediate CAs) is checked against the CRL of its issuer on
  that path. A status that cannot be determined - including a certificate or intermediate CA
  without an http(s) CRL distribution point - is never shown as fully valid; for recipients it is
  a warning (`mimeshield_revocation_unknown = 'warn'`) or refused (`'block'`).
* Signature status: a `multipart/signed` message is treated as S/MIME only when both its
  `protocol` parameter and its second part are a PKCS#7 signature; only the first part is shown,
  rebuilt from exactly the verified bytes, and the signature part never appears as content. A
  compact S/MIME indicator is also shown in the message header area (outside the message content),
  including "Not signed with S/MIME" - content of a message cannot replace it.
  Attachment downloads, inline resources and compose rebuild the same first part from raw MIME
  bytes without relying on the IMAP part tree; this alone does not claim a valid signature.
* Replies and forwards of decrypted messages are encrypted by default;
  `mimeshield_require_encrypt_for_decrypted = true` makes the server refuse to send or save them
  without encryption, including with an unavailable plugin schema (and refuse to save a draft while
  `mimeshield_encrypt_drafts = false`). A compose holding decrypted content is never saved to the
  browser's localStorage, so it cannot be restored later into an unprotected compose. Active compose sessions retain
  this protection independently of the recent-compose lookup size. The compose warning asks users
  to review recipients and quoted content because decryption alone does not authenticate the sender.
* The database schema of the plugin must be current: while it is missing or outdated, sending or
  saving a draft that is expected to be signed or encrypted is refused (fail closed).
* Decrypted HTML is rendered by Roundcube core: run a Roundcube release with current security fixes
  (≥ 1.7.4) and keep the OpenSSL library used by PHP-FPM patched. Certificates embedded in received
  signatures are parsed by OpenSSL before any plugin limit applies: use an OpenSSL library with the
  fix for CVE-2026-35189 (≥ 3.0.23, 3.4.8, 3.5.9, 3.6.5 or 4.0.3, or a distribution package with the
  backported fix); `bin/mimeshield.sh diag` warns otherwise.
* Subjects and other headers are not encrypted by S/MIME.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full threat model and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design.

## Hardening checklist for administrators

* HTTPS only, `session_samesite = 'Strict'` or `'Lax'`, `use_https = true`.
* `mimeshield_temp_dir` on a tmpfs (e.g. a dedicated directory under `/dev/shm`) owned by the PHP
  user.
* Keep `mimeshield_revocation = 'off'` unless outbound HTTP from the web server is acceptable; if
  enabled, consider `mimeshield_revocation_allow_hosts`, a proxy and `mimeshield_revocation_unknown`.
* Configure `mimeshield_ca_bundle` with S/MIME roots and keep `mimeshield_use_system_ca = false`.
* Add rate limits for the Roundcube endpoints at the reverse proxy / WAF and a request time limit
  (`request_terminate_timeout` in PHP-FPM, proxy read timeout): native OpenSSL work is not
  interrupted by `max_execution_time`. The plugin limits key imports per session and per user,
  recipient checks and "save sender certificate" requests per session, signed-entity extraction or
  verification per request (8, including clear-signed and opaque content in compose/download) and CRL downloads per request
  (8, within a shared 10-second transfer budget). Resolver timeouts and PHP-FPM must also bound
  synchronous DNS calls, which cannot be interrupted while running.
* Keep the CRL cache and its immediate parent private (PHP-owned, mode 0700, no symlinks).
  Unsafe directories disable disk caching; network retrieval and the per-request memory cache
  still work, and failed retrieval remains subject to the configured unknown-revocation policy.
  Review the directory contents and ownership before restoring permissions.
* Deny HTTP access to `plugins/mimeshield/{bin,lib,SQL,tests,docs,localization}` (see README 2.6).
* Defence in depth for administrator options: the plugin already ignores user preferences named
  `mimeshield_*` (except `mimeshield_pref_sign|encrypt`); additionally list the security-relevant
  options in Roundcube's `$config['dont_override']`, e.g. `mimeshield_ca_bundle`,
  `mimeshield_use_system_ca`, `mimeshield_intermediates`, `mimeshield_master_key_file`,
  `mimeshield_master_key_env`, `mimeshield_master_key_active`, `mimeshield_options_lock`.
* Run `plugins/mimeshield/bin/mimeshield.sh diag` after every upgrade.
* Restrict `log_dir` permissions; the plugin never logs secrets, but logs contain user ids and
  certificate fingerprints. Unexpected exceptions log their type by default; their sanitised
  messages are emitted only with `mimeshield_debug`, and may still include personal data or
  infrastructure details. Keep debug logging disabled during normal operation.
