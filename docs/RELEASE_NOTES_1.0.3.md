MIME Shield 1.0.3 is a security release: it remediates every accepted finding of the second
security review of 2026-11-04 (IDs V-01 to V-14 and N-01 to N-14 of that review).

- Supported Roundcube minimum is 1.7.5, the release that fixes remote-content blocking bypasses in
  the core HTML sanitiser the plugin relies on for decrypted mail. `diag` warns below it and notes a
  newer known release; the release checklist now includes the platform advisory check.
- The shared cRLNumber replay protection is written directly to `cache_shared` as validated JSON
  inside a row-locking transaction that only raises the number; a CRL of another scope no longer
  changes stored state and is not cached.
- Decrypted or unwrapped content is checked against a MIME structure budget before the parser runs,
  and the size limits are capped at a fraction of PHP's `memory_limit`, so oversized or deeply
  nested content yields "message too large" instead of a fatal error.
- More rate limits: recipient checks per account, certificate imports per session and account,
  certificate detail pages per session, at most 10 candidates per recipient address; key and
  certificate quotas are enforced inside one transaction.
- Certificates inside uploaded PKCS#12 files, AuthEnvelopedData nonce lengths and key-agreement
  algorithms are pre-checked before OpenSSL parses them.
- Ownership checks for the master key file and the trust bundles; a uid-specific fallback temp
  directory; a CRL proxy without an allow-list disables CRL checking instead of running unpinned;
  INFO logs carry user-facing labels only; `diag` warns for outdated PHP patch levels and
  end-of-life OpenSSL branches; SIGKILL for a stuck legacy converter.
- Housekeeping: `.htaccess` deny files in non-web directories, narrower secret-scanner exceptions,
  `composer validate --strict` in CI, PHPUnit ≥ 13.4.4 on the 13 branch.

Upgrade: replace the plugin files and run `bin/mimeshield.sh diag`. No database migration and no
configuration change is required; installations using `mimeshield_revocation_proxy` must set
`mimeshield_revocation_allow_hosts` to keep CRL checking enabled. Details: CHANGELOG.md,
docs/ARCHITECTURE.md section 8e, SECURITY.md.
