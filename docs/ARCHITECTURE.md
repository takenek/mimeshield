# MIME Shield – Architecture

This document describes how MIME Shield (`mimeshield`) integrates S/MIME into Roundcube 1.7.x
**without modifying Roundcube**, and why it is built this way. All statements about Roundcube
internals were verified against the Roundcube 1.7.4 source (tag `1.7.4`, commit `0d05c37`) and,
where noted, by experiments. File/line references are relative to the Roundcube root.

## 1. Components

```
mimeshield.php                 Roundcube integration (rcube_plugin): hooks, actions, CSRF, fail-closed send
lib/MimeShield/
  Config.php                   typed configuration with safe defaults (mirrors config.inc.php.dist)
  Services.php                 per-request service graph (user id ALWAYS from the session)
  Log.php                      redacting logger (log "mimeshield")
  Exception/                   user-safe label + internal message
  Crypto/
    OpenSsl.php                central OpenSSL call wrapper (error queue draining, warnings captured)
    SecureTemp.php             private 0700 dir, 0600 files (mkstemp), cleanup in finally
    Asn1.php, Asn1Node.php     hardened DER reader (BER read-only mode, node replacement)
    CmsInspector.php           CMS metadata: content type, digests, signingTime, RecipientInfos, GCM fix
    CmsService.php             openssl_cms_* sign/verify/encrypt/decrypt on exact bytes
    SignatureCheck.php         cryptographic verification result
  Cert/
    Certificate.php            X.509 value object; SAN/KU/EKU/BC/CRLDP/AIA parsed from DER
    KeyImporter.php            PKCS#12 / PEM import with precise error classification
    KdfInspector.php           PKCS#12/PKCS#8 KDF cost limits (incl. encrypted layers), checked before OpenSSL
    ImportedKey.php            import result (transient, holds the key in memory only)
    LegacyPkcs12Converter.php  opt-in RC2 PKCS#12 conversion via openssl CLI (no shell, no disk)
    PublicCertImporter.php     PEM / DER / PKCS#7 certs-only
  KeyStore/
    MasterKeyProvider.php      master key(s) from file or environment, rotation (kid)
    KeyVault.php               AEAD blob format v1 (XChaCha20-Poly1305 / AES-256-GCM)
  Trust/
    TrustStore.php             admin-defined anchors (+ opt-in system bundle), intermediates, issuer lookup
    ChainValidator.php         OpenSSL decision + diagnostic path building (reasons), CA EKU for EC recipients
    AddressMatcher.php         e-mail normalisation / comparison
    RevocationChecker.php      opt-in CRL checking (signature, freshness, critical extensions)
    SafeHttpClient.php         SSRF-hardened HTTP GET for CRLs
    VerificationResult.php     separated crypto / chain / identity / revocation / time / policy states
    ChainResult.php, RevocationResult.php   result value objects
  Storage/                     rcube_db repositories (always scoped by user_id)
  Service/
    KeyService.php             own keys: import, unwrap, signer per identity, decryption candidates
    CertificateService.php     correspondent certificates: import, save from message, resolution
    SignatureVerifier.php      SignatureCheck -> VerificationResult
    OutgoingService.php        sign / encrypt / sign+encrypt / drafts / Bcc envelopes
  Mime/
    SmimeMessage.php           immutable-body Mail_mime subclass returned to Roundcube
    EntityBuilder.php          canonical MIME entities, multipart/signed, application/pkcs7-mime
    DotGuard.php               Net_SMTP chunk-border protection
    IncomingProcessor.php      detect / decrypt / verify / inject (message_part_structure)
    PartStatus.php             per-part S/MIME state for the UI
  Ui/                          ComposeUi, MessageUi, SettingsUi (all output escaped)
  Cli/Tool.php                 bin/mimeshield.sh: diag, keygen, rotate, check-keystore
  RateLimiter.php              per-session sliding-window limits (recipient checks, key import)
SQL/                           mysql / postgres / sqlite schemas (Roundcube conventions)
skins/elastic/                 templates + CSS
js/mimeshield.js               compose / settings / message view (no secrets, no innerHTML with data)
```

The plugin class is `class mimeshield extends rcube_plugin` in `plugins/mimeshield/mimeshield.php`:
Roundcube requires the class name to equal the directory name
(`rcube_plugin_api.php:183-213`). `$task = 'mail|settings|cli'`.

## 2. Hooks and actions used

| Task / action | Hook / action | Purpose |
|---|---|---|
| mail (all actions) | `message_part_structure` | detect, decrypt, unwrap and verify S/MIME |
| mail | `message_load` | hide `smime.p7s` from the attachment list |
| mail | `message_part_get` | no persistent thumbnails / caching of decrypted parts |
| mail | `message_part_before` | force remote-content blocking in decrypted HTML |
| mail show/preview/print | `message_body_prefix`, `template_object_messagebody`, `template_object_messageheaders` | status bar, header indicator |
| mail compose | `message_compose_body`, `template_container` (`composeoptions`) | options, env, draft restore |
| mail send | `message_ready` | sign / encrypt (and abort on error); with a missing/outdated plugin schema only `message_ready_unavailable`: refuse sends/drafts that are expected to be protected |
| mail send | `message_before_send` | fail-closed check, Bcc envelopes, dot guard |
| mail | `plugin.mimeshield-recipients`, `plugin.mimeshield-savecert` | AJAX |
| settings | `settings_actions`, `preferences_list`, `preferences_save`, `identity_delete` | settings UI |
| settings | `plugin.mimeshield*` actions | certificate management pages |
| cli | `user_delete` | cleanup in `bin/deluser.sh` |

Only hooks that exist in 1.7.x are used (verified: `message_outgoing_headers` no longer exists;
`message_part_body`'s return value is ignored by core, so it is not used).

## 3. Outgoing mail: Compose → MIME → Sign → Encrypt → SMTP

```
compose form (POST _mimeshield_sign / _mimeshield_encrypt, _from = identity id)
   │
send.php: rcmail_sendmail::create_message()  -> Mail_mime (headers incl. Bcc, bodies, attachments)
   │
hook message_ready  ───────────────►  mimeshield::message_ready()
   │                                     - draft?  (_draft && !_saveonly)  -> drafts policy
   │                                     - identity = rcube_user::get_identity((int)_from) (user scoped)
   │                                     - From header == identity e-mail
   │                                     - recipients planned & certificates checked BEFORE key use
   │                                     - EntityBuilder::prepareOriginal(): QP for all text, no file I/O,
   │                                       8-bit message/rfc822 -> base64 .eml (clear-signing only)
   │                                     - inner = Content-Type [+CTE] + CRLF + Mail_mime::get()
   │                                       canonical CRLF, "From " -> "=46rom " in QP
   │                                     - SIGN: openssl_cms_sign(DETACHED|BINARY|NOSMIMECAP, DER)
   │                                       micalg read from the DER digestAlgorithm (sha-256)
   │                                     - ENCRYPT: openssl_cms_encrypt(BINARY, DER, AES-256-CBC)
   │                                       recipients: To + Cc (+ Bcc in single mode) + self
   │                                     - return SmimeMessage (body serialised ONCE)
   │                                   on ANY error: show_message + output->send('iframe') => exit
   │                                     (nothing is sent; drafts restart autosave)
   │
rcube::deliver_message()
   hook message_before_send ─────────►  mimeshield::message_before_send()
   │                                     - message MUST be SmimeMessage with requested protection,
   │                                       otherwise abort (fail closed against other plugins)
   │                                     - DotGuard: pad preamble until no Net_SMTP chunk starts mid-line with '.'
   │                                     - Bcc 'separate': one envelope per Bcc via rcube_smtp::send_mail,
   │                                       main delivery uses a clone without the Bcc header
   │
   txtHeaders(['Bcc'=>null]) + get()  ->  Net_SMTP string path  ->  SMTP DATA
   │
rcmail_sendmail::save_message($SAME object) -> getMessage() = txtHeaders() + get() -> Sent (keeps Bcc)
```

### 3.1 Why an immutable Mail_mime subclass

* `message_ready` is the only hook that receives the final `Mail_mime` object
  (`program/actions/mail/send.php:209-210`); the returned `message` replaces it, nothing else of
  the return value is used — **a plugin cannot abort sending through the hook's return value**.
  MIME Shield therefore aborts with `$output->show_message()` + `$output->send('iframe')`, exactly
  like the official `enigma` plugin (`plugins/enigma/lib/enigma_ui.php:1201-1205`).
* Roundcube calls `get()` on the same object **twice** (SMTP at `rcube.php:1819`, Sent copy at
  `rcmail_sendmail.php:551` via `getMessage()`), and `Mail_mimePart` creates **new random nested
  boundaries on every call** (`vendor/pear/mail_mime/Mail/mimePart.php:342,453`). Re-encoding
  would break any signature. `SmimeMessage::get()` returns a string serialised once.
  (Enigma's wrapper also mutates its body inside `get()`; verified to corrupt the second copy for
  QP bodies – MIME Shield's `get()` is pure.)
* `delay_file_io` is forced off: Net_SMTP 1.12.2's file path corrupts data at 8 KiB chunk borders
  (verified: CMS verification failed in 5/5 runs with a 1.5 MB attachment). In the string path a
  mid-line `.` at a 512000-byte chunk start would be doubled; `DotGuard` moves chunk borders by
  padding the multipart/signed preamble, which is outside the signed content.
* Roundcube never declares `BODY=8BITMIME` (`rcube_smtp.php:264-280`) and uses `8bit` for
  non-ASCII text by default. RFC 8551 §3.1.3 requires 7-bit transfer encoding for clear-signed
  content; all text parts are therefore switched to quoted-printable before signing.

### 3.2 Sign + encrypt order

SIGN first, then ENCRYPT the complete `multipart/signed` entity (RFC 8551 §3.7 allows any order;
this is what Thunderbird does — `nsMsgComposeSecure.cpp` — and Outlook on the web's default
`OWATripleWrapSignedEncryptedMail=$false`). The inner signed entity keeps 7-bit transfer encoding,
so a decrypting gateway still yields a verifiable signature. Receiving supports every nesting
(signed-in-enveloped, enveloped-in-signed, triple wrap) up to depth 4.

### 3.3 Algorithms (defaults)

| Purpose | Default | Reason |
|---|---|---|
| Signature digest | SHA-256 (OpenSSL 3 default for RSA/EC; PHP has no digest parameter) | RFC 8551 §2.1; micalg is read back from the DER, MD5/SHA-1 are never emitted |
| SMIMECapabilities | omitted (`CMS_NOSMIMECAP`) | OpenSSL's default list advertises RC2/DES that OpenSSL 3 cannot decrypt |
| Content encryption | AES-256-CBC (EnvelopedData) | verified with NSS (Thunderbird's library) and gpgsm in tests/interop; per vendor documentation also used/decrypted by Outlook (OWA default AES-256) and reported for Apple Mail (not tested); Thunderbird decrypts GCM only from 154 |
| Optional | AES-256-GCM (AuthEnvelopedData) | PHP ≥ 8.5 only; admin opt-in |
| Key transport | RSA PKCS#1 v1.5; ECDH (stdDH-sha1kdf + AES key wrap) for EC certs | PHP cannot select RSA-OAEP for encryption; OAEP is not universally decryptable |
| Never for new mail | RC2, DES, 3DES, MD5, SHA-1 | RFC 8551 App. B |

On receipt: AES-CBC/GCM, 3DES (legacy mail), RSA PKCS#1 v1.5 and OAEP, ECDH; SHA-256/384/512
accepted; SHA-1 accepted **with a warning** (Outlook on the web signs with SHA-1 by default); MD5
rejected. AuthEnvelopedData whose GCMParameters omit `aes-ICVlen` (seen from Exchange) is repaired
before decryption (OpenSSL rejects it otherwise; only unauthenticated parameters are changed).

### 3.4 Drafts

`message_ready` also fires for drafts and autosaves (`send.php:48-49,209`). Drafts are **never
signed** (a signature would be invalid after the next edit and would need the private key on every
autosave). With "Encrypt" checked, the draft is encrypted to the **sender's own certificate only**
(config `mimeshield_encrypt_drafts`, default on); without an own encryption certificate saving the
encrypted draft is refused (fail closed). The checkbox state is stored in the draft header
`X-MimeShield-Options: sign=0|1; encrypt=0|1` and restored in compose (`message_compose_body`,
raw headers of the draft). The final signature/encryption is produced only on send.

### 3.5 Sent copy

The Sent copy is the same `SmimeMessage` object, i.e. byte-identical body to the SMTP copy (only
the `Bcc:` header differs, as in core). Encrypted messages include the sender's certificate as an
additional recipient (encrypt-to-self, RFC 8551 §3.3, config `mimeshield_encrypt_to_self`), so the
sender can read the Sent copy.

### 3.6 Bcc

With one envelope, every recipient sees all RecipientInfos (issuer + serial) and can infer Bcc
recipients. Default `mimeshield_bcc_mode = 'separate'`: the main envelope contains To + Cc + self;
each Bcc recipient gets a separately encrypted copy (Bcc recipient + self), delivered in
`message_before_send` through Roundcube's public `rcube_smtp::send_mail()`. The main delivery uses
a clone without the `Bcc` header; the Sent copy (original object) keeps it. A failure of a Bcc copy
aborts the whole send (but copies already accepted by the MTA cannot be recalled — documented).
If the main delivery fails after all Bcc copies were delivered, the `message_send_error` hook
replaces the SMTP error with `bccmainsendfailed` (the Bcc recipients already have the message).

## 4. Incoming mail: IMAP → Detect → Decrypt → Verify → Rendering

```
rcube_message::__construct()  (show, preview, print, get, compose (reply/forward/draft), viewsource, zipdownload ...)
   parse_structure() -> hook message_part_structure ──► IncomingProcessor::partStructure()
       application/(x-)pkcs7-mime, octet-stream *.p7m:
           bytes via storage->get_message_part(raw decode) ; type from CMS ContentInfo OID (not smime-type)
           enveloped / authEnveloped (ROOT only): try the user's keys (RecipientInfo match first),
               plaintext -> CRLF -> rcube_mime::parse_message() -> NEW part tree, ids renumbered
               under the old id, body_modified=true, encoding='stream' -> $p['structure'] replaced,
               recurse into the new root (core does not call the hook for it)
           signed-data (opaque): openssl_cms_verify -> content injected like above + VerificationResult
       multipart/signed (protocol parameter AND second part (x-)pkcs7-signature, 2 parts):
           exact bytes: storage->get_raw_body(uid, null, 'TEXT' | <id> | <id>.TEXT) or the decrypted raw
           (at most MAX_SIGNATURE_CHECKS = 8 verifications per request, others "sig_toomany")
           RFC 2046 split -> content + signature (exactly one DER/BER element, no trailing data)
           -> verifyDetached(BINARY, NOVERIFY) [text-mode retry]
           -> SignatureVerifier: chain (OpenSSL + diagnostics), identity, time, KU/EKU, revocation, policy
           -> $p['structure'] = copy of the container holding ONLY the first part, rebuilt from the
              bytes selected for verification (ids mirror part 1; compose/get use the same raw
              first-part parser without trust evaluation); the signature part never enters the displayed tree
           smime.p7s id recorded -> also hidden from the attachment list in message_load
   core renders the (new) tree normally: content parts -> print_body() -> rcube_washtml (HTML sanitiser,
   remote content blocking), attachments -> get action (re-decrypted with the same deterministic ids)
   hook message_body_prefix / template_object_messagebody -> MessageUi status bar (escaped)
   hook template_object_messageheaders -> MessageUi header indicator (outside the content, also
       "not signed")
```

Important properties (all verified in the Roundcube source):

* **Sanitisation is preserved**: injected parts are ordinary `rcube_message_part` content parts,
  rendered through `rcmail_action_mail_index::print_body()` → `wash_html()` → `rcube_washtml`
  (`program/actions/mail/index.php:1027-1093, 915-1015`). Additionally `message_part_before`
  forces `safe=false` for decrypted parts (remote resources are never loaded from decrypted HTML,
  EFAIL hardening).
* **No plaintext in caches**: `rcube_message::$mime_parts` holds references into the structure
  that `messages_cache` serialises (`rcube_imap_cache.php:1162-1220`). The original part objects
  are never modified; a new tree is created and every injected part has `body_modified=true`.
* **EFAIL / decryption-oracle hardening** (RFC 8551 §6, Thunderbird's part "1"/"1.1" rule, enigma's
  CVE-2019-10740 guard): only S/MIME at the message root, or directly inside an outer S/MIME layer,
  is decrypted or treated as covering the message. S/MIME inside multipart/mixed or forwarded
  messages is shown as "partially signed" / "encrypted part not decrypted". Replying to an
  encrypted message pre-checks "Encrypt" and warns when it is switched off.
* **Decryption is repeated per request** (no plaintext cache). Thumbnails of decrypted images are
  served without writing Roundcube's persistent thumbnail cache.
* Signature trust/identity evaluation runs only for show/preview/print (and the save-certificate
  action). Clear-signed compose/get/inline-resource requests extract the same first entity from raw
  MIME without native verification; opaque signed content needs native verification to extract its
  body. Both paths consume the same eight-entity extraction/verification budget. Signed envelopes are rebuilt from the
  verified first-part bytes before decryption; if rebuilding fails, no successful signature status
  is retained for fallback content.

## 5. Trust model

Four questions are kept separate everywhere (data model, UI, logs):

1. **Cryptographic signature** — `openssl_cms_verify(..., OPENSSL_CMS_NOVERIFY)` (signature and
   message digest; `NOSIGS` is never used). Retry without `BINARY` only for line-ending
   canonicalisation (shown as information).
2. **Certificate chain** — one path for every decision: the plugin first builds the shortest path
   from the leaf to a configured anchor (issuer name + `openssl_x509_verify`, configured
   intermediates preferred over certificates from the message, bounded search); without such a path
   nothing is trusted. OpenSSL then verifies exactly that path:
   `openssl_x509_checkpurpose(SMIME_SIGN|SMIME_ENCRYPT|ANY for EC, ca_info = admin bundle files +
   an empty plugin directory, untrusted = the intermediates of the path)` - the empty directory stops
   PHP from adding OpenSSL's default CA directory (`OPENSSLDIR/certs`, `SSL_CERT_DIR`). The path is
   returned in `ChainResult::$certs` and used for the EKU check of EC recipients and for revocation.
   Without a trusted result the same builder explains why: expired / not yet valid / untrusted root /
   incomplete / wrong purpose. Diagnostics never upgrade a failure. OpenSSL validates at the current time; an expired certificate is shown
   as "signature valid, certificate expired" (with the signer-claimed signing time).
3. **Identity** — From (and Sender) vs SAN `rfc822Name` from DER (subject `emailAddress` only as a
   labelled legacy fallback). Comparison: domain IDNA + case-insensitive, local part
   case-insensitive (RFC 8550 §3 "SHOULD"). SmtpUTF8Mailbox is not supported (never matches).
4. **Revocation** — off by default ("not checked" is displayed); optional CRL checking only for
   chains already anchored in the trust store (RFC 8550 §6), SSRF-hardened, for every certificate of
   the accepted path below the anchor against the CRL of its issuer on that path
   (`RevocationChecker::checkPath()`; CA-only CRLs for CAs, user-only CRLs never for CAs). With
   checking enabled, a missing http(s) CRL DP is "unknown" (never fully OK); a failed distribution
   point is not requested again for 5 minutes and at most 8 CRLs are fetched per request, within a
   shared 10-second transfer deadline. Transport errors are cached per URL; issuer/signature errors
   per URL and issuer fingerprint. The HTTP client caps each transfer to the remaining time and
   checks the deadline around DNS resolution; a running synchronous DNS call needs an external
   lifetime bound. Inner and outer CRL AlgorithmIdentifier fields must match.

Trust anchors are configured by the administrator only. End-entity certificates are never added
to the anchors; a certificate received in a message is never trusted because it was received — it
can be saved by the user as a *contact certificate* only if the signature is valid and matches the
sender, and is flagged `verified` (chain validated at save time) or `observed`. Encryption to
contacts whose chain does not validate is blocked by default (`mimeshield_encrypt_untrusted`).

Signing requires: certificate bound to the identity, identity e-mail contained in the certificate,
certificate time-valid, KU digitalSignature/nonRepudiation, EKU emailProtection (or none/any). The
plugin never signs with a certificate for another address.

## 6. Key storage

```
PKCS#12 upload ─► openssl_pkcs12_read (password used once, wiped, never stored/logged/sessioned)
               ─► checks (key type/size, cert match, SAN/KU/EKU/validity/fingerprint/chain)
               ─► PKCS#8 PEM (memory only)
               ─► KeyVault::encrypt(key, context = "user:<id>|fp:<sha256>")
                     data key = HKDF-SHA256(master key, info "mimeshield private key wrapping v1|alg:<alg>", salt "kid:<kid>")
                     XChaCha20-Poly1305 (libsodium; AES-256-GCM fallback), random 192/96-bit nonce,
                     AAD = blob header || context
                     blob = "MSK" | v2 | alg | kidLen | kid | nonce | ciphertext||tag  (base64 in DB)
                     (format v1 - same without "|alg:<alg>" in the HKDF info - is still read; rotate upgrades it)
               ─► mimeshield_keys.key_blob (+ key_kid, key_format)
```

The master key (32 random bytes, `kid base64` lines) lives in a file outside the web root and the
plugin directory (refused otherwise, world-readable files refused) or in an environment variable.
It is never stored in the database and never generated implicitly. Rotation: add a key
(`plugins/mimeshield/bin/mimeshield.sh keygen --append`), set `mimeshield_master_key_active`, run
`plugins/mimeshield/bin/mimeshield.sh rotate` (re-wraps every blob), then remove the old key.

Private keys are unwrapped only in memory for a single sign/decrypt operation, passed to OpenSSL
as PEM strings (verified with strace: OpenSSL writes no key file) and wiped afterwards (best effort
in PHP). They are never sent to the browser and there is no private-key export.

Roundcube's own `rcube::encrypt()` was evaluated and rejected: it uses `des_key` with the
admin-chosen `cipher_method` (default DES-EDE3-CBC, unauthenticated; `rcube.php:897-976`).

## 7. Database

Tables (prefixed with `$config['db_prefix']` by `rcube_db::table_name()`; install/update scripts
are rewritten by `rcube_db::fix_table_names()`):

| Table | Content |
|---|---|
| `mimeshield_keys` | own certificates: metadata, `cert_pem`, `chain_pem`, `key_blob` (AEAD), `key_kid`, `key_format`; `cert_pem` must match `fingerprint` (bound to `key_blob` by the AEAD context), own certificates are used for encryption only after the blob authenticated |
| `mimeshield_bindings` | (user_id, identity_id) → key_id used for signing |
| `mimeshield_certs` | correspondent certificates: metadata, `cert_pem`, `chain_pem`, `source`, `trust` |
| `mimeshield_cert_emails` | address index of `mimeshield_certs` with the `preferred` flag |

Conventions verified on MySQL/MariaDB, PostgreSQL and SQLite: binary data only as base64/PEM
(`rcube_db` truncates NUL bytes on pgsql/sqlite), PostgreSQL sequences `<table>_seq` with
`insert_id('<unprefixed table>')`, upper-case SQL keywords and no `REPLACE INTO` in scripts
(otherwise the prefix is not applied), the initial script writes `mimeshield-version`, FK cascades
to `users`/`identities`, e-mails and fingerprints lower-cased in PHP (MySQL collation is
case-insensitive, the others are not). Identity deletion is a soft delete in Roundcube, so the
`identity_delete` hook removes bindings explicitly; user deletion (`bin/deluser.sh`) is handled by
FK cascades and the `user_delete` hook. Every statement contains `user_id = ?` with the session
user id.

Settings binding updates validate the entire selection first and then commit all binds/unbinds in
one `Database::transaction()` using Roundcube's transaction API. Reads of keys/bindings use the
writer connection. Key-import quotas use the existing core `users` and `cache` tables: a no-op user
row update serialises sessions, a dedicated JSON quota row is read/written on the writer, and the
reservation is committed before KDF work. Storage failures block import; no schema migration is needed.

## 8. Web security

* Every state-changing action requires **POST + request token** compared with `hash_equals`
  (`mimeshield::requirePostToken()`), because Roundcube's global check skips GET requests and POST
  requests with an empty `$_POST` (e.g. a file-only multipart upload; `rcube.php:1052-1056`).
  The public-certificate download is a POST with the token in the body (never in a URL).
* All output is built with `html::*` and `rcube::Q()`; certificate fields are untrusted.
  Localised strings with variables are escaped after substitution. JS uses `.text()` only.
* No processing of input in `init()` (it runs before Roundcube's CSRF and auth checks).
* Uploads: `is_uploaded_file`, size limits before reading, content-based format detection, the
  client file name is never used as a path, the password is read with `allow_html=true` (no
  `strip_tags` corruption) and wiped.

## 8a. Hardening added after the security audit

* PKCS#12 / encrypted PKCS#8 KDF cost parameters (PBKDF2 / PKCS#12-PBE iterations, MAC iterations,
  scrypt N/r/p) are checked by `KdfInspector` before OpenSSL sees the file (≤ 2 000 000 iterations
  per KDF, ≤ 6 000 000 in total, scrypt N ≤ 2^20, r ≤ 32, p ≤ 4) – a tiny upload can no longer
  pin a PHP worker for minutes.
* Administrator locks (`mimeshield_options_lock`) always use the administrator value; the user's
  own default is stored separately (`mimeshield_pref_sign|encrypt`).
* Address lists are parsed strictly: an unverifiable From entry turns the identity into a
  mismatch; a recipient the plugin cannot interpret blocks encryption.
* Messages with decrypted content are never "safe" (`is_safe=false`, `show_images=0`, `_safe`
  ignored) on every path, including the `get` action and HTML reply/forward.
* AuthEnvelopedData with a GCM tag shorter than 12 bytes or inconsistent `aes-ICVlen` is rejected.
* ASN.1 nesting deeper than 32 levels and BER constructed strings nested deeper than 8 levels are
  rejected.
* CRL fetching refuses trailing-dot host names and, on PHP ≥ 8.4, verifies the connected address in
  `CURLOPT_PREREQFUNCTION` before the request is sent.
* Certificate names are neutralised for display (control, line-separator and bidi characters).

## 8b. Remediation of the final security report (2026-10-02)

* MS-01: without a current plugin schema, `init()` registers only a `message_ready` guard (no plugin
  tables needed) that refuses sends/drafts expected to be protected (request, defaults, locks).
* MS-02: `IncomingProcessor` keeps the origin of injected parts (`rootIds`) separate from the byte
  buffer of unwrapped content (`raw`); content unwrapped from a forwarded opaque SignedData never
  becomes a root, so nested EnvelopedData is not decrypted and signatures stay "partial".
* MS-03/MS-07: EC recipients (OpenSSL "any" purpose) additionally require e-mail protection in the
  EKU of every CA on the path; the system TLS bundle is no longer a default trust anchor.
* MS-04/MS-06: `TrustStore::findIssuer()` is shared by signature and recipient revocation checks;
  `mimeshield_revocation_unknown` (`warn`/`block`) decides undetermined recipient status (shown in
  compose); an IDP `fullName` in any name form restricts the CRL scope.
* MS-05: `KdfInspector` decrypts encrypted PKCS#12 layers with the entered password (PBES2/PBKDF2,
  PKCS#12-PBE per RFC 7292 B.2) and adds their KDF parameters to the same budget before OpenSSL runs;
  a layer whose iteration count is not a positive INTEGER within the limit is refused before any key
  derivation.
* MS-08: an uninspectable SignedData yields "algorithm could not be checked" (warning, never OK).
* MS-09: `KeyRecord::certificate()` checks `cert_pem` against `fingerprint`; `KeyService::encryptionCertFor()`
  authenticates the key blob; the "own" shortcut applies to identity addresses only.
* MS-10/MS-11: total envelope budget for separate Bcc copies; `RateLimiter` for recipient checks
  and key imports.
* MS-12: `keygen` checks the whole directory chain in every mode and verifies the temporary file
  (inode/device) before the `--append` rename.
* MS-13: `TrustStore` and `MasterKeyProvider` are built from `MimeShield\Config` (user preferences
  named like administrator options are ignored).
* MS-14/MS-15: `min-version` 1.7.4; `diag` reports the Roundcube release and the OpenSSL library
  loaded by the SAPI (warning below 3.5.9 on the 3.5 branch).

## 8c. Remediation of the final security report (2026-10-03, IDs F-xx)

* F-01/F-13: `IncomingProcessor::isSmimeSigned()` requires both the `protocol` parameter (for a
  forwarded `message/rfc822` its Content-Type header when available) and the type of the second part;
  `decodeSignaturePart()` refuses data after the CMS element; `handleSignedContainer()` returns a copy
  of the container with only the first part, parsed from the verified bytes.
* F-02/F-05: `TrustStore::verifyLocations()` / `isolationDir()`; `ChainValidator` builds the shortest
  anchored path (iterative deepening, budget 256 comparisons) and lets OpenSSL verify only that path;
  `TrustStore::findIssuer()` prefers administrator certificates with cRLSign;
  `TrustStore::trustedCrlIssuer()` replaces an issuer without cRLSign only by an administrator copy.
* F-04/F-06/F-14: `RevocationChecker::checkPath()`; `nocrldp` → UNKNOWN; `VerificationResult::level()`
  accepts "not checked" only for disabled checking; negative cache (memory + `<hash>.fail` marker
  file, `NEGATIVE_TTL` 300 s, separate URL/issuer validation keys), `maxFetchesPerRequest` (8) and
  `maxFetchSecondsPerRequest` (10 s, with the synchronous-DNS limitation described above).
  Disk caching validates both its base and `crl/` directory: no symlinks, no group/other access,
  PHP ownership where POSIX identity is available. Unsafe directories are left untouched and disk
  caching is disabled; the memory cache, transfer budget and UNKNOWN policy remain in effect.
* F-03/F-08: `KdfInspector` walks the PFX schema (authSafe → ContentInfo → SafeContents → bags,
  MacData incl. PBMAC1) on joined BER content, refuses uninspectable content (including unknown key
  encryption schemes and PBKDF2 key lengths above 64 bytes), and bounds the real
  PHP key-derivation work (`MAX_PHP_KDF_WORK`); `RateLimiter::allowForUser()` adds an atomic per-user
  database reservation to the per-session limit of key imports.
* F-07: `IncomingProcessor::MAX_SIGNATURE_CHECKS` (8) per request for signed-entity extraction or
  verification, status `sig_toomany`.
* F-09: `ComposeUi::markDecryptedCompose()` (session, per compose id) and the option
  `mimeshield_require_encrypt_for_decrypted`, enforced in `message_ready()` and its schema-unavailable
  guard (a draft is refused when `mimeshield_encrypt_drafts = false`); `composeBody()` sets the
  core env `save_localstorage` to false for such a compose. The flag persists in active core compose state, and the compose sidebar warns about
  unverified sender identity whenever decrypted content is quoted.
* F-10: header indicator (`template_object_messageheaders`, `MessageUi::headerBadge()`).
* F-11: `DotGuard::makeSafe()`; `message_before_send()` blocks a clear-signed message that stays
  unsafe after 8 paddings.
* F-12: `keygen --append` uses `<key file>.lock` (flock), strict read, complete write + fsync +
  fclose, read-back comparison before the rename.
* F-15: saving an untrusted certificate from a message under `encrypt_untrusted = 'warn'` needs a
  confirmation bound to the shown fingerprint (`_fingerprint`); the dialog shows old/new fingerprints.
* I-04: settings import confirmation carries `_pending_digest`, the SHA-256 of the complete public
  file retained in the server session. It must match before the single-use file is consumed. A GET
  preserves pending state, and a stale confirmation cannot acknowledge another upload.
* I-06/I-10: unexpected exception details require debug logging; identity binding batches use a
  transaction after validating every identity.
* I-01: the message UI adds an explicit warning headline and header indicator for an otherwise
  valid signature whose revocation was not checked; public verification levels and configured
  digest policies are unchanged.

## 9. Differences from the original requirements (and why)

| Requirement / assumption | Finding | Implementation |
|---|---|---|
| "message_ready can stop sending" | its return value cannot abort | `show_message` + `send('iframe')` (exit) + second check in `message_before_send` |
| sign in message_ready "and let Roundcube send" | Roundcube re-serialises the message (random boundaries), Net_SMTP file path corrupts data | immutable `SmimeMessage`, `delay_file_io` off, dot guard |
| choose SHA-256 explicitly | PHP's CMS API has no digest parameter | OpenSSL 3 default (SHA-256) + verification of the produced digest, refuses anything else |
| AES-GCM as "modern default" | Thunderbird ESR cannot decrypt GCM, Outlook undocumented, PHP < 8.5 cannot produce it | AES-256-CBC default, GCM opt-in |
| `openssl_x509_parse` for SAN | output is ambiguous (proven exploit) | DER parsing |
| PKCS#12 "standard" import | Windows "TripleDES-SHA1" exports use RC2-40, unsupported by OpenSSL 3 | precise error + optional CLI conversion |
| Roundcube secret storage | `rcube::encrypt` is unauthenticated CBC with the shared `des_key` | dedicated AEAD key store |
| OCSP | PHP has no OCSP API | CRL only (opt-in); OCSP not implemented |
| full Roundcube CSRF protection | empty-POST and GET bypass of the global check | explicit token checks in the plugin |
| private key export | not needed | not implemented at all |
