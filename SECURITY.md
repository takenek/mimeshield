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
  0400/0440, or an environment variable). The plugin refuses world-readable key files and key files
  under `public_html/` or `plugins/`.
* Every record has its own random nonce, a 128-bit authentication tag, a key identifier (for
  rotation) and a format version. The ciphertext is bound (associated data) to the user id and the
  certificate fingerprint; tampering or moving a blob to another row is detected.
* Private keys are decrypted only in PHP memory for the duration of one signing/decryption
  operation, handed to OpenSSL as PEM strings (never written to disk), and wiped afterwards (best
  effort — PHP does not guarantee memory erasure).
* Private keys are never sent to the browser and **cannot be exported** (feature intentionally not
  implemented). Public certificates can be downloaded.
* PKCS#12 passwords are used once during import and are never stored, logged or kept in the
  session.

## Master key

* Generate: `plugins/mimeshield/bin/mimeshield.sh keygen --file=/etc/roundcube/mimeshield.key`
  (32 random bytes from `random_bytes()`, file created with `O_EXCL`, mode 0400).
* Back it up **separately** from database backups. Losing it makes all stored private keys
  unusable (users would have to re-import their PKCS#12 files). Stealing it together with a
  database dump reveals all private keys.
* Rotate: `keygen --append` → set `mimeshield_master_key_active` → `bin/mimeshield.sh rotate` →
  `bin/mimeshield.sh check-keystore` → remove the old key line.
* Never commit it, never put it into `config.inc.php.dist`, never place it inside the Roundcube
  directory tree.

## Important security assumptions

* The server, the PHP process account and the Roundcube installation are trusted. Anyone who can
  execute code as the PHP user (or read its memory / the master key) can use every stored private
  key. Server-side S/MIME cannot protect against a compromised server. Users who need protection
  against the server operator must keep their keys on their own devices.
* Trust anchors (CA bundle) are chosen by the administrator. Distribution bundles usually contain
  TLS roots only; add the S/MIME roots your users need.
* Revocation is not checked unless `mimeshield_revocation = 'crl'` is configured (the UI says
  "Revocation status: not checked").
* Subjects and other headers are not encrypted by S/MIME.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full threat model and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design.

## Hardening checklist for administrators

* HTTPS only, `session_samesite = 'Strict'` or `'Lax'`, `use_https = true`.
* `mimeshield_temp_dir` on a tmpfs (e.g. a dedicated directory under `/dev/shm`) owned by the PHP
  user.
* Keep `mimeshield_revocation = 'off'` unless outbound HTTP from the web server is acceptable; if
  enabled, consider `mimeshield_revocation_allow_hosts` and a proxy.
* Run `bin/mimeshield.sh diag` after every upgrade.
* Restrict `log_dir` permissions; the plugin never logs secrets, but logs contain user ids and
  certificate fingerprints.
