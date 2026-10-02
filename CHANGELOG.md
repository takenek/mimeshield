# Changelog – MIME Shield (`mimeshield`)

All notable changes are documented here. The format follows *Keep a Changelog*; versions follow
semantic versioning.

## [Unreleased]

### Security
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

## [1.0.0] – 2026-10-02

First release.

### Added
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
