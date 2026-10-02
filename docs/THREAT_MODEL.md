# MIME Shield – Threat model

## Assets

| Asset | Where |
|---|---|
| Users' S/MIME private keys | DB `mimeshield_keys.key_blob` (AEAD-encrypted), process memory during one operation |
| Master key | key file outside the web root (or environment variable), PHP process memory |
| PKCS#12 passwords | HTTP request during import only |
| Decrypted message content | PHP memory, short-lived 0600 temp files during OpenSSL calls, browser |
| Integrity of signatures / sender authenticity | outgoing mail, verification UI |
| Correspondent certificates (who can read what I encrypt) | DB `mimeshield_certs` |
| Trust configuration | admin configuration files |

## Trust boundaries and assumptions

* The operating system account running PHP, the Roundcube installation and its configuration are
  trusted. The administrator is trusted.
* The database server and database backups may be compromised **independently** of the web server
  file system (typical: dump leaked, separate DB host, DB-level SQL injection elsewhere).
* Every logged-in user is potentially malicious towards other users.
* Every received message and every certificate (including its CN/OU/SAN/issuer text) is
  attacker-controlled.
* The IMAP server is trusted to store messages, but message contents are not.

## Threats and mitigations

### T1 Malicious logged-in user (horizontal privilege escalation, IDOR)
* All repository methods include `user_id = ?` bound to the session user (`$rcmail->user->ID`); the
  user id is never taken from GET/POST. Foreign key/cert ids simply match nothing.
* Identities are resolved with `rcube_user::get_identity()` (user-scoped) — a foreign identity id
  cannot be used for signing or binding.
* Key blobs are bound by AEAD associated data to `user_id` + certificate fingerprint: even if a
  row were copied to another user (e.g. by a SQL bug), it would not decrypt.
* Settings actions verify ownership of both key and identity before binding.
* Result: user A cannot read, use, sign with, decrypt with, rebind or delete user B's keys/certs.

### T2 Compromised database / stolen database dump
* Private keys are encrypted (XChaCha20-Poly1305 or AES-256-GCM, 256-bit key derived from the master
  key, which is **not** in the database). A dump alone does not reveal private keys.
* Tampering with blobs is detected (authentication tag; AAD binds header + user + fingerprint).
* Not protected: public certificates, e-mail addresses of correspondents, metadata (subjects,
  validity), which identity uses which certificate — these are stored in clear.
* A DB attacker could insert a rogue *correspondent certificate* for a victim; it would be blocked
  for encryption unless its chain validates to an admin trust anchor (default policy `block`), and
  the UI always shows trust status.
* Own key records cannot be used for that either (audit MS-09): the certificate of a key record
  must match the record fingerprint, and the fingerprint is bound to the key blob (AEAD). An own
  certificate is used as an encryption recipient only after its blob authenticated under the master
  key, and only for the user's identity addresses. A row inserted with a foreign certificate and a
  copied or forged blob is ignored (and logged). Integrity of the DB is otherwise trusted.

### T3 Stolen file system / backup of the web server
* If the attacker obtains **both** the master key file and a database dump, all private keys can be
  decrypted. Keep the key file out of backups that also contain the database, or back it up
  separately (offline). Using the environment variable source keeps the key out of files.
* Temp files: private keys are never written to disk; message plaintext/signatures exist in 0600
  files in a private 0700 directory only during one OpenSSL call (removed in `finally`; a tmpfs is
  recommended). Roundcube itself writes compose attachments to its temp dir (see Limitations).

### T4 Compromise of the PHP process / server account (NOT protected)
* An attacker who can execute code as the PHP user, read process memory, or modify the plugin
  code can read the master key and use or exfiltrate every private key, and can read decrypted
  mail. This is inherent to server-side S/MIME. MIME Shield does not and cannot protect against it.
* Same for a malicious Roundcube administrator or a compromised Roundcube core/plugin.

### T5 Malicious message (parser attacks, EFAIL, oracles, spoofing)
* ASN.1 is parsed by a bounded DER reader (depth/node limits, strict lengths) only for metadata;
  cryptography is done by OpenSSL. Size limits apply to S/MIME parts (`mimeshield_max_message_size`)
  and recursion is limited (depth 4).
* Decrypted HTML goes through Roundcube's standard `rcube_washtml` sanitiser; remote content is
  always blocked in decrypted parts (EFAIL exfiltration channel closed). CBC encryption without a
  valid inner signature is labelled "content may have been altered".
* Only root-level S/MIME (or S/MIME directly inside another S/MIME layer) is decrypted: an attacker
  cannot embed someone else's ciphertext in a multipart/forwarded message to get it decrypted and
  quoted back (decryption oracle, cf. CVE-2019-10740). The "root" decision follows the origin of a
  part through every unwrapped layer: content unwrapped from a forwarded opaque-signed message stays
  "forwarded" (partial signature, nested ciphertext not decrypted — audit MS-02). Replies to encrypted mail default to
  encryption and warn when switched off.
* Partial signatures (signed part inside an unsigned multipart, e.g. list footers) are shown as
  "only part of this message is signed".
* "Signature valid" is never shown as "sender trusted": chain, sender address, time validity, key
  usage and revocation are evaluated and displayed separately. From/Sender spoofing with a valid
  certificate for another address is shown in red ("certificate does not match the sender").
* Weak/unsupported algorithms: MD5 rejected, SHA-1 warned, RC2/DES not decrypted unless the admin
  enables the OpenSSL legacy provider. A signature whose digest algorithm cannot be determined by the
  plugin's parser is never shown as fully valid ("algorithm could not be checked", audit MS-08).

### T6 Malicious certificate
* All certificate strings are escaped (`rcube::Q`, `html::*`, JS `.text()`); subjects are
  length-limited in the DB. Header injection is impossible: certificate data never goes into mail
  headers; addresses are validated (`AddressMatcher`, no CR/LF, no display names).
* The ambiguous `subjectAltName` text of `openssl_x509_parse()` is not used; SAN `rfc822Name` is
  read from DER and every value must be a plain mailbox (the "victim@x, email:attacker@y" trick is
  rejected — covered by tests).
* Duplicate extensions are rejected; CA certificates are never accepted as end entities and end
  entities are never trust anchors.
* Certificates from received messages are not trusted automatically (contact store `observed` /
  `verified` flags; encryption to untrusted certificates is blocked by default).
* Purpose restrictions of CAs: for RSA recipients OpenSSL's S/MIME purpose checks the EKU of every
  CA; for EC (keyAgreement) recipients, which need OpenSSL's "any" purpose, the plugin checks that
  every CA on the path allows e-mail protection (audit MS-03). The system TLS CA bundle is not a
  trust anchor by default (`mimeshield_use_system_ca = false`, audit MS-07).

### T7 SSRF via CRL / OCSP / AIA URLs
* Revocation checking is **off by default**; AIA/OCSP URLs are never fetched.
* With `mimeshield_revocation = 'crl'`: only for certificates whose chain already validated to an
  admin trust anchor (attacker certificates cannot trigger requests); only http/https on ports
  80/443; no user info, no redirects; host allow/deny lists; the host is resolved once and **every**
  address must be public (loopback, RFC 1918, CGNAT, link-local incl. 169.254.169.254, ULA, multicast,
  documentation, IPv4-mapped/6to4/Teredo/NAT64 forms rejected); the connection is pinned to the
  checked address (`CURLOPT_RESOLVE`), host names with a trailing dot are refused, and the connected
  address is verified (before the request is sent on PHP >= 8.4, after the transfer on older PHP);
  timeouts and a hard size limit; at most 2 URLs per certificate; results cached.
* CRL scope: an IssuingDistributionPoint restricts the scope even when it uses name forms other
  than URI; such a CRL never proves "not revoked" for a certificate it does not name (MS-06). The
  issuer for recipient CRL checks is resolved like for signatures (stored chain, configured
  intermediates, anchors); an undetermined status is shown or blocks (`mimeshield_revocation_unknown`,
  MS-04).
* When `mimeshield_revocation_proxy` is set, pinning and the connected-address check are performed
  by the proxy, not by the plugin: the proxy must enforce the egress policy (or use
  `mimeshield_revocation_allow_hosts`).

### T8 XSS
* Server: every dynamic value escaped; template-object handlers return escaped HTML; status bars
  are built with `html::*`; messages are localisation labels with escaped variables.
* Client: no `eval`, no `innerHTML`/`.html()` with data; dialogs receive DOM nodes created with
  `.text()`.
* Decrypted content: standard Roundcube sanitiser (see T5).

### T9 CSRF
* All mutating actions: POST + request token (`X-Roundcube-Request` or `_token`) compared with
  `hash_equals`; GET is never mutating. This closes the gap in Roundcube's global check, which
  skips requests whose `$_POST` is empty (file-only uploads).
* No request input is processed in `init()` (before Roundcube's CSRF/auth checks).

### T10 Downgrade to plaintext
* Fail closed: if signing/encryption was requested and anything fails (missing certificate,
  OpenSSL error, key store error, other plugin interference), the request ends with an error before
  delivery; `message_before_send` re-checks that the message actually being sent is protected.
* Also when the plugin's database schema is missing or outdated (e.g. an upgrade without
  `updatedb.sh`): a send or draft that is expected to be protected (user request, administrator
  default or lock) is refused by a guard that needs no plugin tables (audit MS-01).
* Missing recipient certificates block sending and list the recipients; sending without
  encryption requires an explicit user action ("Send without encryption" switches the option off
  visibly). The plugin never unchecks encryption on its own.
* Drafts of messages marked for encryption are stored encrypted to the sender (or refused) while
  `mimeshield_encrypt_drafts = true` (default); with `false` they are stored on the IMAP server in
  plaintext.

### T11 Log leakage
* The logger redacts PEM blocks, long base64 runs and binary data, strips control characters (log
  injection), truncates values; passwords, keys, plaintext and full PKCS#12 data are never passed to
  it. Errors shown to users are generic labels; OpenSSL details go to the admin log only.

### T12 Resource exhaustion
* KDF cost parameters in uploaded PKCS#12 / PKCS#8 files are limited before OpenSSL derives keys
  (otherwise a 4 KB file with 2^31 iterations keeps a worker busy for minutes). Encrypted PKCS#12
  layers are decrypted with the entered password and inspected as well, within one total budget
  (audit MS-05; the iteration count of a layer is validated before its key is derived); key imports are limited to 10 per session within 5 minutes.
* Recipient status checks in compose are limited per session (30 per minute); the total memory of
  separate Bcc envelopes is bounded (`mimeshield_max_total_envelope_bytes`, audit MS-10/MS-11).
  Limits per user or IP across sessions belong to the reverse proxy / WAF.
* Upload size limits checked before reading; limits on keys/certificates per user, recipients per
  message, message size for S/MIME processing, ASN.1 nodes/depth, certificates per file, CRL size.

## What MIME Shield does NOT protect against

* A compromised web server / PHP process / Roundcube installation or administrator (T4).
* Theft of the master key **together with** the database.
* Users' compromised browsers or end devices (decrypted mail is displayed there).
* Metadata: subjects, sender/recipient addresses, dates and message sizes are not encrypted by
  S/MIME (header protection, RFC 9788, is not implemented — no major client emits it yet).
* Revocation when checking is disabled, and OCSP-only revocation.
* Plaintext of decrypted attachments that Roundcube writes to its temp dir when a decrypted message
  is forwarded/edited with attachments (core `filesystem_attachments` behaviour).
* Trust decisions made by the administrator's CA bundle (a malicious/compromised CA in the bundle is
  trusted).
* Correctness of the signer-claimed signing time (it is displayed as "claimed").
