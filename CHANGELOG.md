# Changelog – MIME Shield (`mimeshield`)

All notable changes are documented here. The format follows *Keep a Changelog*; versions follow
semantic versioning.

## [Unreleased]

## [1.0.2] – 2026-10-04

### Changed
- Identify the copyright holder as TaKeN.PL Usługi Informatyczne Marek Królikowski and
  the original author as Marek Królikowski (TaKeN) in source headers and project metadata.
- Add COPYRIGHT with attribution and origin notices under GPLv3 section 7(b) and 7(c),
  limited to project-owned material distributed with those notices. Previously released
  copies retain their original terms. The GPL-3.0-or-later grant and LICENSE text are unchanged.
- Bump the plugin-reported version to 1.0.2. No cryptographic, mail-processing, database
  or configuration behaviour is changed.

## [1.0.1] – 2026-10-03

### Fixed
- Removed the Composer classmap entry for the Roundcube plugin bootstrap `mimeshield.php`. Roundcube
  loads that file directly from `plugins/mimeshield/mimeshield.php`; keeping it in Composer's
  classmap caused spurious "Could not scan for classes" warnings because
  `roundcube/plugin-installer` relocates the package outside Composer's default `vendor/` path.
  PSR-4 autoloading for `MimeShield\\` classes is unchanged.

## [1.0.0] – 2026-10-03

### Security
- `CmsService::decrypt()` now verifies that the supplied private key matches the recipient certificate before calling OpenSSL CMS decryption. This avoids false-success garbage plaintext with RSA PKCS#1 v1.5 implicit rejection and unauthenticated CBC when a mismatched key is supplied.
Remediation of the final security report of 2026-10-03 (IDs F-xx of that report).
- F-01/F-13: a `multipart/signed` container is S/MIME only when both its `protocol` parameter and
  its second part name a PKCS#7 signature; data after the CMS structure of the signature part is
  refused; only the first part is displayed, rebuilt from exactly the verified bytes (the signature
  part can no longer be shown as content under a "signature valid" status). Signed envelopes are
  rebuilt before decryption; a failed rebuild clears the success status before fallback display.
  A `multipart/signed` nested inside verified content is not re-read through the IMAP parser.
  Downloaded attachments, inline resources and compose use the same first-part parser as the
  message view, even when trust evaluation is disabled.
- F-02: chain validation never consults OpenSSL's default CA directory and trusts a chain only when
  it ends in a configured anchor; OpenSSL verifies exactly that path (all key types and purposes).
- F-03: PKCS#12 KDF inspection follows the PFX structure on joined BER segments (what OpenSSL
  reads) and refuses content it cannot inspect, including an encrypted PKCS#8 PEM key, a key
  encryption scheme whose cost parameters are unknown (only PKCS#12-PBE, PKCS#5 PBES1 and PBES2 with
  PBKDF2/scrypt are accepted) and a PBKDF2 key length above 64 bytes.
- F-04/F-05: with CRL checking, every certificate of the accepted path (including intermediate
  CAs) is checked against the CRL of its issuer on that path; CA-only CRLs are used for CAs; a copy
  of an issuer without cRLSign shipped in a message can no longer hide a revocation.
- F-06: with CRL checking, a certificate without an http(s) CRL distribution point is "unknown"
  (subject to `mimeshield_revocation_unknown`), never "not checked" / fully valid.
- F-07: at most 8 signed entities are extracted or verified per request, including clear-signed
  and opaque content in compose/get. Decision: the total number of MIME parts is not limited (the
  plugin's work per non-S/MIME part is constant); a PHP-FPM `request_terminate_timeout` or proxy
  timeout is an installation requirement, shown as `[INFO]` by `diag`.
- F-08: the PHP key derivation of the PKCS#12 inspection is bounded by its real work; key imports
  are limited per user account as well as per session. Account reservations are atomic across
  concurrent sessions, committed before KDF work, and fail closed on storage errors.
- F-09: new option `mimeshield_require_encrypt_for_decrypted` (default `false`): the server refuses
  to send or save a reply/forward/draft of a decrypted message without encryption; the "send
  without encryption" dialog warns that the quoted content was encrypted. The sidebar warns about
  unverified original sender identity even with encryption selected. Enforcement survives recent
  compose lookup eviction and an unavailable plugin schema; with `mimeshield_encrypt_drafts = false`
  such a draft is refused. A compose holding decrypted content is never kept in the browser's
  localStorage (it could be restored into an unprotected compose).
- F-10: an S/MIME indicator in the message header area (outside the content), also "Not signed
  with S/MIME".
- F-11: a clear-signed message that cannot be made safe for Net_SMTP chunking is not sent.
- F-12: `keygen --append` refuses an unreadable/empty key file, serialises concurrent runs with a
  lock file and replaces the key file only after a complete, synced and verified write.
- F-14: an unavailable CRL distribution point is not requested again for 5 minutes; at most 8 CRLs
  are downloaded per request within a shared 10-second transfer budget (synchronous DNS still needs
  resolver/PHP-FPM time limits). Issuer validation failures are cached separately from URL failures;
  an outdated CRL is cached as a failure, and a transfer cut short by the budget is not.
  Disk caching is disabled if its base or `crl/` directory is a symlink, has a foreign owner
  (where ownership checking is available), or grants group/other access. Decision: synchronous DNS
  cannot be interrupted without losing SSRF pinning; with CRL checking, resolver limits (`options
  timeout:1 attempts:2` or a local caching resolver) are an installation requirement and `diag`
  warns when one lookup can exceed 10 seconds (`/etc/resolv.conf`, glibc limits applied).
- F-15: saving an untrusted sender certificate under `mimeshield_encrypt_untrusted = 'warn'` needs a
  confirmation bound to the shown fingerprint; the dialog shows old and new fingerprints.
- F-16: SECURITY.md and the threat model document the minimum OpenSSL versions with the
  CVE-2026-35189 fix (environment update; `diag` warns). New `CertPrecheck` refuses, before any
  OpenSSL call, certificates with a duplicate cRLDistributionPoints extension, more than 8 or
  relative (nameRelativeToCRLIssuer) distribution points, or an unparsable structure: in
  certificates read by the plugin, SignedData and OriginatorInfo certificates of incoming mail and
  PKCS#7 uploads (must be SignedData). Such signatures are "malformed"; such encrypted messages give
  a decryption error; unreadable envelopes are no longer passed to OpenSSL. `diag` deliberately does
  not warn for end-of-life OpenSSL branches 3.1-3.3 (the advisory lists supported branches only).
- I-05: security audit working documents (`FINAL_SECURITY_REPORT.md`, `STAGE_*.md`, `DOSTARCZONE/`)
  are excluded from release archives. CI (GitHub Actions, PHP 8.1-8.5, PHPUnit, `php -l`,
  `node --check`, PHPStan 2.x; actions pinned to commit SHAs, read-only token) and
  `docs/RELEASING.md`; signed tags and Packagist publication are done by the maintainer.
- I-17: "save sender certificate" requests are limited per session and per user account (20 per
  minute each).
- I-03/I-08: `diag` warns for a CRL proxy without `mimeshield_revocation_allow_hosts` and for
  `mimeshield_bcc_mode = 'single'`.
- I-11/I-12: decrypted content using any cipher other than AES (3DES, DES, RC2, unknown) and signatures with more than one SignerInfo
  are shown with a warning (never fully OK).
- I-16: tests now prove the isolation of the trust store from OpenSSL's default CA directory.
- I-13: README recommends the master key file over the environment variable.
- I-01: the message status headline and header indicator explicitly warn when certificate
  revocation has not been checked; algorithm defaults remain unchanged. Decision: revocation stays
  `off` by default (outbound HTTP, CA learns checked certificates; enabling `crl` is recommended
  where egress is allowed); SHA-1 signatures stay accepted with a warning, never green.
- I-04: settings import confirmation is bound to the complete pending public file; stale
  confirmations are refused, and opening an import form preserves the pending state.
- I-06: unexpected exception messages (also from incoming mail processing) are logged only in debug
  mode; normal logs retain the type.
- I-09: CRL inner and outer signature AlgorithmIdentifier values must agree. SHA-1 signed CRLs
  follow `mimeshield_legacy_digests`: without `'sha1'` they give revocation status "unknown".
- I-02: with CRL checking, the highest cRLNumber per CRL issuer/distribution point is kept in
  Roundcube's `cache_shared` table (db driver, 30-day TTL, refreshed daily on use); a CRL with a lower
  number is "unknown", is not cached, and a cached copy is refetched. Store errors are logged once
  and do not stop checks.
- I-14: `diag` warns for a PHP branch past its security support (table 8.1-8.5) and recommends
  PHP >= 8.3. Decision: composer keeps `php >=8.1 <8.6` (Roundcube 1.7 supports it; the plugin cannot
  update the host runtime).
- I-15: new option `mimeshield_temp_dir_strict` (default `false`): with an unusable configured temp
  directory, sign/encrypt/decrypt/verify are refused (`tempdirunavailable`) instead of falling back
  to the system temp directory; chain checks then fail closed. `diag` warns when the temp directory
  is not on tmpfs/ramfs.
- I-18: decryption tries only own keys matching a RecipientInfo; only when none matches, at most 5
  other keys are tried (clients encoding the recipient identifier differently).
- I-10: identity binding selections are fully validated before any write, then committed atomically.
- I-07: the Bcc delivery error says that Bcc copies delivered before the failure may have arrived;
  when every Bcc copy was delivered but the main delivery fails, the error says that the Bcc
  recipients already have the message (`message_send_error` hook). Accepted: SMTP delivery of
  separate Bcc envelopes cannot be atomic.
- Documented decisions (not defects): F-01 - a forwarded `message/rfc822` without a parsed
  Content-Type is matched by its second part type only, and its status is always "partial"; F-02 -
  with several bundle certificates of the same subject and key OpenSSL may pick another of them as
  anchor (it is still an administrator anchor); F-12 - no directory fsync after the key file rename.
- `keygen` checks every write of a new key file and removes a partial file;
  the unused `SignatureVerifier::findIssuer` was removed.

### Changed (behaviour, 2026-10-03)
- With `mimeshield_revocation = 'crl'`, signatures and recipients whose intermediate CA has no
  usable CRL now get "revocation status could not be checked" (warning / `block` policy) instead of
  a full OK.
- `multipart/signed` without a `protocol` parameter is no longer verified.

### Security (2026-10-02)
Remediation of the final security report of 2026-10-02 (IDs MS-xx / INF-xx of that report).
- MS-01: with a missing or outdated plugin database schema, sending or saving a draft that is
  expected to be signed/encrypted (user request, `mimeshield_*_default`, `mimeshield_options_lock`)
  is refused instead of being delivered in plaintext.
- MS-02: content unwrapped from a forwarded opaque-signed message (SignedData inside
  `message/rfc822`) is no longer treated as the message root: ciphertext nested in it is not
  decrypted and its signature is labelled "partial".
- MS-03: EC (keyAgreement) recipients are accepted only if every CA on the path allows e-mail
  protection (EKU), as OpenSSL already enforces for RSA recipients.
- MS-04: recipient CRL checks find the issuer also among the configured intermediates and trust
  anchors (certificates imported without their chain were silently not checked); new option
  `mimeshield_revocation_unknown` (`warn` default / `block`); compose shows "revocation status could
  not be checked".
- MS-05: PKCS#12 import inspects KDF cost parameters inside encrypted layers (decrypted with the
  entered password) before OpenSSL runs them; key imports are limited per session. The iteration
  count of an encrypted layer must be a positive INTEGER within the limit before the inspection
  derives its key (otherwise the file is refused).
- MS-06: a CRL whose IssuingDistributionPoint uses only non-URI names is no longer treated as
  unscoped.
- MS-08: signatures whose digest algorithm cannot be determined are shown with a warning ("algorithm
  could not be checked") instead of fully valid.
- MS-09: the certificate of an own key record must match its fingerprint; own certificates are used
  as encryption recipients only after the key blob authenticated with the master key, and only for
  the user's identity addresses.
- MS-10: new option `mimeshield_max_total_envelope_bytes` bounds the memory of separate Bcc
  envelopes (checked before encryption).
- MS-11: recipient status checks in compose are limited per session.
- MS-12: `keygen` checks the directory chain (symlinks, owner, group/other-writable) in every mode,
  including `--append`, and verifies the temporary file before replacing the key file.
- MS-13: trust store and master key source ignore user preferences named like administrator options.
- MS-14/MS-15: `diag` warns for Roundcube older than 1.7.4 and for an OpenSSL library without the
  CVE-2026-35189 fix (OpenSSL advisory of 2026-09-29: below 3.0.23, 3.4.8, 3.5.9, 3.6.5 or 4.0.3 on
  the respective branch, unless the distribution backported the fix) and shows the library version
  loaded by the SAPI.
- INF-02: the public certificate download uses POST (request token no longer in URLs).
- INF-03: falling back to the system temp directory is logged and reported by `diag`.
- INF-05: the legacy PKCS#12 converter writes to the `openssl` process without blocking; the
  deadline covers the whole conversion.
- INF-06: `.gitattributes` excludes tests and developer tooling from release archives; README
  documents web server deny rules.

### Changed (behaviour)
- **`mimeshield_use_system_ca` now defaults to `false`** (MS-07): the system TLS CA bundle is no
  longer trusted for S/MIME unless enabled. Configure `mimeshield_ca_bundle` with your S/MIME roots
  before upgrading, otherwise signatures may show "issuer not trusted" and encryption to such
  recipients is blocked (policy `block`).
- **Minimum Roundcube version raised to 1.7.4** (`extra.roundcube.min-version`, MS-14).
- Wrong PKCS#12 passwords may now be reported before OpenSSL reads the file (same message).

### Changed
- Settings > S/MIME certificates: the identity assignment "Save" is a primary button inside the
  identity section; while the selection differs from the saved one a warning notice ("Changes have
  not been saved yet. If the configuration is correct, click Save.") is shown; the confirmation
  ("Certificate assignment to identities saved.") stays visible after the list reload. "Save" is
  disabled while the selection equals the stored bindings (for example right after an import bound
  the key) and becomes active only after a change; reverting the change disables it again.
- A key import that assigned the certificate to matching identities says so in its confirmation
  ("Certificate and private key imported. The certificate was automatically assigned to the
  matching identity.").
- `diag` also shows the number of stored identity bindings (Database section).
- "Download public certificate" and "Delete" are buttons (delete in the danger style).
- Compose: the S/MIME options form their own section with a visible "S/MIME" heading; the
  signing certificate is shown as name / issuer / validity.

### Added
- `mimeshield.sh keygen --create-parent`: explicitly create missing parent directories of `--file`
  (mode 0700 for the current user). Every existing path component from `/` is checked with
  `lstat()`: a symbolic link anywhere in the path, a component owned by a user other than root / the
  current user, or one writable by group/others without the sticky bit makes it fail closed.

### Fixed
- `diag` checked the CVE-2026-35189 fix only for the OpenSSL 3.5 branch; 3.0, 3.4, 3.6 and 4.0
  libraries without the fix were reported as OK.
- Badges in the certificate lists were stretched to the full row width.
- `mimeshield.sh keygen` reported only "Cannot create PATH" when the parent directory of `--file`
  was missing; it now names the cause (missing / not a directory / not writable) and shows an
  `install -d` example.

### Added (initial implementation)
- S/MIME signing (clear-signed `multipart/signed`, SHA-256, intermediates embedded,
  no SMIMECapabilities), encryption (AES-256-CBC EnvelopedData, optional AES-GCM on PHP 8.5,
  RSA and ECDH recipients, encrypt-to-self, separate envelopes per Bcc recipient) and
  sign + encrypt (sign first).
- Verification of clear-signed and opaque signatures (`x-pkcs7-*` aliases, SHA-1 with warning),
  decryption of EnvelopedData / AuthEnvelopedData (incl. Exchange GCM without `aes-ICVlen`),
  nested and triple-wrapped messages; status bar with separate signature / chain / identity /
  validity / key usage / revocation information.
- PKCS#12 / PEM import with precise diagnostics (wrong password, legacy RC2, no key, mismatched
  key), optional legacy conversion via the OpenSSL CLI.
- Encrypted private key store (XChaCha20-Poly1305 / AES-256-GCM, master key outside the database,
  key ids, format version, rotation tooling).
- Recipient certificate store (import, save from verified messages, preferred certificate,
  fingerprint-change confirmation, chain re-validation on re-import).
- Certificates per identity, automatic binding on import, key rotation keeping old keys for
  decryption.
- Trust store from administrator CA bundles, chain diagnostics, optional SSRF-hardened CRL checks.
- Compose, message view and settings UI for the Elastic skin; English and Polish translations.
- `bin/mimeshield.sh` (diag, keygen, rotate, check-keystore).
- Schemas for MySQL/MariaDB, PostgreSQL, SQLite (with `db_prefix` support).
- Test suites: PHPUnit (unit + integration), E2E against a real Roundcube, CMS interoperability
  with NSS (Thunderbird), gpgsm and OpenSSL, compatibility matrix.

### Security
- Fixes for all findings of the internal 30-point security audit (see docs/TESTING.md).
