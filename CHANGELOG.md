# Changelog – MIME Shield (`mimeshield`)

All notable changes are documented here. The format follows *Keep a Changelog*; versions follow
semantic versioning.

## [Unreleased]

### Changed
- Settings > S/MIME certificates: the identity assignment "Save" is a primary button inside the
  identity section; while the selection differs from the saved one a warning notice ("Changes have
  not been saved yet. If the configuration is correct, click Save.") is shown; the confirmation
  ("Certificate assignment to identities saved.") stays visible after the list reload.
- "Download public certificate" and "Delete" are buttons (delete in the danger style).
- Compose: the S/MIME options form their own section with a visible "S/MIME" heading; the
  signing certificate is shown as name / issuer / validity.

### Fixed
- Badges in the certificate lists were stretched to the full row width.

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
