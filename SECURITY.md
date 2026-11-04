# Security policy – MIME Shield

Maintainer: **[Marek Królikowski (TaKeN)](https://github.com/takenek)**.

Business name: **TaKeN.PL Usługi Informatyczne Marek Królikowski**.

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
  (≥ 1.7.5; check <https://roundcube.net/news/> for newer ones) on a PHP patch level with current
  security fixes (≥ 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, or a distribution backport) and keep the
  OpenSSL library used by PHP-FPM patched and on a supported branch. Certificates embedded in
  received signatures or uploaded in PKCS#12 files are parsed by OpenSSL after the plugin's
  pre-check, which covers the published trigger of CVE-2026-35189 only: use an OpenSSL library with
  the fix (≥ 3.0.23, 3.4.8, 3.5.9, 3.6.5 or 4.0.3, or a distribution package with the backported
  fix); `bin/mimeshield.sh diag` warns otherwise and for end-of-life branches.
* Subjects and other headers are not encrypted by S/MIME.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full threat model and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design.

## Hardening checklist for administrators

* HTTPS only, `session_samesite = 'Strict'` or `'Lax'`, `use_https = true`.
* `mimeshield_temp_dir` on a tmpfs (e.g. a dedicated directory under `/dev/shm`) owned by the PHP
  user, mode 0700 (`diag` warns otherwise); consider `mimeshield_temp_dir_strict = true` to refuse
  S/MIME operations instead of falling back to the system temp directory (where the plugin uses a
  `mimeshield-<uid>` subdirectory, V-11).
* Enable `mimeshield_revocation = 'crl'` wherever outbound HTTP from the web server is acceptable
  (recommended); then consider `mimeshield_revocation_allow_hosts`, a proxy and
  `mimeshield_revocation_unknown`, and bound DNS (`options timeout:1 attempts:2` in
  `/etc/resolv.conf` or a local caching resolver - required, `diag` checks it). A proxy REQUIRES
  the allow-list: without it CRL checking is disabled and every status is "unknown" (V-12).
* Run a PHP branch with security support at its current patch level (PHP >= 8.3 recommended;
  `diag` warns below 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 and for unsupported branches, V-14), and
  Roundcube ≥ 1.7.5 (V-01).
* Keep the master key file, the CA bundle and intermediate bundles owned by root or the PHP user
  and not writable by others (`diag` and the log warn for foreign owners; a world-writable trust
  bundle is refused, V-10). Prefer the key file to `mimeshield_master_key_env`: an environment
  variable is inherited by every PHP-FPM worker and visible to every script of the pool (`diag`
  warns, N-09).
* Keep PHP's `memory_limit` in mind: the message and envelope size limits are capped at 1/6 and
  1/2 of it (V-06); `diag` shows the effective values.
* Configure `mimeshield_ca_bundle` with S/MIME roots and keep `mimeshield_use_system_ca = false`.
* Add rate limits for the Roundcube endpoints at the reverse proxy / WAF and a request time limit
  (`request_terminate_timeout` in PHP-FPM, proxy read timeout): native OpenSSL work is not
  interrupted by `max_execution_time`. The plugin limits key and certificate imports per session
  and per user, recipient checks per session and per account, certificate detail pages per session,
  "save sender certificate" requests per session and per account (V-07), signed-entity extraction or
  verification per request (8, including clear-signed and opaque content in compose/download), the
  structure of decrypted or unwrapped content (500 entities, 8 nested forwards, retained bodies at
  most twice the size limit, V-05) and CRL downloads per request
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
* Restrict `log_dir` permissions and limit retention; the plugin never logs secrets, but the
  `mimeshield` log records S/MIME activity: level, operation, the Roundcube user id, the user-facing
  label of a refused operation, draft/message ids, the first 16 hex digits of certificate
  fingerprints (full fingerprints and the sanitised internal exception messages only with
  `mimeshield_debug`, audit V-13), fixed context values such as algorithm names, and file paths of
  misconfigured administrator files. Unexpected exceptions log their type by default; their
  sanitised messages are emitted only with `mimeshield_debug`, and may still include personal data
  or infrastructure details. Keep debug logging disabled during normal operation.

## Design decisions and accepted risks

Decisions taken on 2026-10-03 after the security audit of that date. They are intentional; a later
audit should treat them as known and accepted, not as new findings, unless the stated rationale no
longer holds.

| Audit ID | Decision | Rationale | Administrator action |
|---|---|---|---|
| I-01 | `mimeshield_revocation = 'off'` by default; SHA-1 signatures accepted with a warning (never green). | CRL checks need outbound HTTP and tell CAs which certificates are checked; the UI says "revocation not checked". Outlook on the web signs with SHA-1. | Set `'crl'` where egress is allowed; set `mimeshield_legacy_digests = []` to reject SHA-1. |
| I-09 | SHA-1 signed CRLs follow `mimeshield_legacy_digests`. | One policy for SHA-1 in signatures and CRLs. | None (or remove `'sha1'`). |
| I-02 | Highest cRLNumber per CRL issuer/distribution point kept in Roundcube's `cache_shared`; lower numbers give "unknown". | Prevents replay of an older CRL. Since 2026-11-04 (V-02/V-04) the row is written directly as JSON inside a row-locking transaction that only ever raises the number (no `rcube_cache` serialization, no `unserialize()` of table content); the 30-day lifetime is renewed on use without touching the number. | Keep the `cache_shared` table (Roundcube schema). |
| I-14 | composer keeps `php >=8.1 <8.6`. | Roundcube 1.7 supports 8.1; a plugin cannot update the host runtime. | Use a PHP branch with security support (>= 8.3 recommended); `diag` warns. |
| I-15 | Fallback to the system temp directory stays the default; new `mimeshield_temp_dir_strict`. | Refusing by default would break mail display on a misconfigured host; the fallback is logged and reported. | Put the temp dir on tmpfs; optionally enable strict mode. |
| I-18 | Unmatched own keys are tried only when no RecipientInfo matches, at most 5. | Interoperability with clients that encode the recipient identifier differently, with bounded work. A message that lists one own key but is encrypted to another no longer decrypts. | None. |
| F-07 | No limit on the total number of MIME parts of the original message. | Work per non-S/MIME part is constant; costly work is bounded (8 signature checks, CRL budget). Content the plugin itself hands to the MIME parser (decrypted or unwrapped) is bounded since 2026-11-04 (V-05: 500 entities, 8 nested forwards, retained bodies at most twice the size limit). | **Required:** PHP-FPM `request_terminate_timeout` or a reverse-proxy timeout. |
| F-14 | DNS lookups for CRL downloads stay synchronous. | They cannot be interrupted without losing SSRF DNS pinning. | **Required with CRL:** `options timeout:1 attempts:2` (at most 6 s with 3 name servers) or a local caching resolver; `diag` warns above 10 s. |
| F-16 | `CertPrecheck` refuses certificates with risky CRL distribution points before OpenSSL, since 2026-11-04 also inside PKCS#12 uploads (V-08); OpenSSL update still required. Revised 2026-11-04 (V-14): `diag` now warns for every OpenSSL branch whose upstream security support has ended (1.1.1, 3.1-3.4, 3.6, 3.0 from 2026-09-07). | The pre-check covers the plugin's own input paths, not every libcrypto use; an unsupported branch is acceptable only as a distribution package with backported fixes, which the version number cannot show. | **Required:** OpenSSL with the CVE-2026-35189 fix on a supported branch or with distribution backports. |
| I-05 | CI with SHA-pinned actions and `docs/RELEASING.md`. | Signing tags and Packagist publication need the maintainer's credentials. | Install a tagged version once one is published; until then a reviewed, pinned commit (see README 2.1). |
| I-07 | Separate Bcc envelopes are not delivered atomically. | SMTP has no transaction across envelopes; the user is told about partial delivery. | Use `separate` Bcc mode (default) knowingly. |
| I-17 | "Save sender certificate" limited per session and per account. | An exhausted account limit also uses a session slot (same as key import). | None. |
| F-01 | A forwarded `message/rfc822` without a parsed Content-Type is matched by its second part type only. | Its status is always "partial", never green. | None. |
| F-02 | With several bundle certificates of the same subject and key, OpenSSL may pick any of them as anchor. | Not a bypass: the anchor is still in the administrator bundle. | Avoid duplicate anchors in bundles. |
| F-12 | No directory fsync after the key file rename. | After a crash the old (complete) key file survives. | Back up the master key. |

Decisions taken on 2026-11-04 after the second security review (IDs V-xx / N-xx of that review):

| Audit ID | Decision | Rationale | Administrator action |
|---|---|---|---|
| V-06 | The size limits are capped at a fraction of `memory_limit` (1/6 message, 1/2 envelopes) instead of lowering the defaults. | A processed part exists in several in-memory copies; the cap turns a fatal error into "message too large" on every installation without changing documented defaults. | Raise `memory_limit` for larger encrypted messages; `diag` shows the effective limits. |
| V-10 | Foreign ownership of the master key file or a trust bundle is a warning (log once, `diag`), not a refusal; only a world-writable trust bundle is refused. | Legitimate layouts (configuration-management owners, root-owned bundles) must keep working; the 0o027 refusal for the key file stays. | Keep the files owned by root or the PHP user. |
| V-11 | Only the fallback below the shared system temp directory gets the `-<uid>` suffix. | Configured directories are private by requirement; the shared `/tmp` is the only place another user can pre-create the name. | Configure `mimeshield_temp_dir`. |
| V-12 | A CRL proxy without `mimeshield_revocation_allow_hosts` disables CRL checking (every status "unknown") instead of checking without pinning. | Through a proxy the plugin cannot verify the connected address; failing closed under `mimeshield_revocation_unknown` is the safe default. | Set the allow-list when using a proxy. |
| N-05 / N-07 | Defaults (`mimeshield_revocation = 'off'`, SHA-1 accepted with warning, AES-256-CBC) are unchanged in 1.0.x. | Changing defaults in a patch release would alter behaviour of existing installations; `diag` and the UI already report these states. | Review the hardening checklist. |
| N-09 | `mimeshield_master_key_env` stays supported with a `diag` warning. | Some deployments can only inject secrets through the environment. | Prefer the key file. |
