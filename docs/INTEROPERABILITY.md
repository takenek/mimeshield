# MIME Shield – Interoperability

## 1. What was actually tested (automated)

| Counterpart | How | Direction | Result |
|---|---|---|---|
| **OpenSSL 3.5 CLI** (`openssl cms`) | final SMTP DATA captured from real Roundcube 1.7.4 sends; Sent copies fetched over IMAP | MIME Shield → OpenSSL: verify, decrypt, decrypt + inner verify | pass (E2E suite) |
| OpenSSL 3.5 CLI | messages created with `openssl cms`, delivered to IMAP, opened in Roundcube | OpenSSL → MIME Shield | pass (E2E suite) |
| **Mozilla NSS 3.110 `cmsutil`** — the CMS/S/MIME library used by **Thunderbird** | `tests/interop/run.sh` | both directions: detached signature verify (+ tamper detection), envelope decrypt | 4/4 checks pass |
| **GnuPG 2.4.7 `gpgsm`** — S/MIME engine of KMail, Kleopatra, Evolution | `tests/interop/run.sh` | both directions | 4/4 checks pass |
| OpenSSL 3.5 CLI (CMS level) | `tests/interop/run.sh` | MIME Shield → OpenSSL | 3/3 checks pass (whole script: 11/11, on PHP 8.1–8.5) |
| Outlook-style structures (emulated) | crafted with OpenSSL: opaque `application/pkcs7-mime; smime-type=signed-data` (`smime.p7m`), `application/x-pkcs7-signature`, SHA-1 signatures (Outlook on the web default), enveloped data containing opaque signed data, triple wrap, AuthEnvelopedData AES-GCM **without** `aes-ICVlen` (Exchange quirk), RSA-OAEP key transport, BER/indefinite-length CMS | → MIME Shield (displayed in Roundcube, E2E I1–I9) | pass |
| Thunderbird-style structures (emulated) | enveloped data (AES-256-CBC) containing `multipart/signed; micalg=sha-256` (E2E I6); AES-128-CBC decryption (PHPUnit CmsServiceTest, and NSS-produced AES-128-CBC in tests/interop) | → MIME Shield | pass |

`application/octet-stream` + `.p7m` detection is covered by PHPUnit (IncomingProcessorTest) only.

What these automated tests prove: the CMS produced by MIME Shield is accepted by NSS (Thunderbird's
crypto), gpgsm and OpenSSL; MIME Shield accepts CMS produced by them; the MIME layout MIME Shield
emits is the standard RFC 8551 layout used by Thunderbird (clear-signed `multipart/signed`,
`application/pkcs7-signature`, `smime.p7s`, `micalg=sha-256`; `application/pkcs7-mime;
smime-type=enveloped-data`, `smime.p7m`; sign-then-encrypt).

Incoming `multipart/signed` (since the remediation of 2026-10-03, audit F-01): verified only when the
container declares `protocol="application/pkcs7-signature"` (or `application/x-pkcs7-signature`)
AND its second part has one of these types, as RFC 1847 / RFC 8551 require and Thunderbird, Outlook
and Apple Mail emit. A non-conforming sender without the `protocol` parameter is no longer verified
(the signature part is shown as an attachment). Include this case in the manual checklist below.

**Not tested automatically:** Microsoft Outlook (Windows/Mac/new Outlook/OWA) and the Thunderbird
application itself (only its crypto library NSS) — they were not available in the Linux test
environment. Use the manual checklist below before relying on them in production.

## 2. Compatibility notes (research summary, see docs/ARCHITECTURE.md §3.3)

| Topic | Outlook / Exchange | Thunderbird | MIME Shield choice |
|---|---|---|---|
| Signature format sent | clear-signed (default) or opaque | clear-signed only | sends clear-signed; receives both |
| Digest | Outlook desktop SHA-256 (configurable); **OWA default SHA-1** | SHA-256 (SHA-512 for RSA > 3072) | sends SHA-256; accepts SHA-1 **with a warning** |
| Content encryption decrypted | AES-128/192/256-CBC, 3DES; GCM undocumented | AES-CBC; GCM only from TB 154 | sends AES-256-CBC |
| Key transport | RSA PKCS#1 v1.5, OAEP (reported), ECDH (reported) | PKCS#1 v1.5, OAEP decrypt (NSS ≥ 3.100), ECDH (TB ≥ 127) | PKCS#1 v1.5 / ECDH |
| SMIMECapabilities | used to choose the reply cipher; malformed lists cause errors | used with voting | omitted (OpenSSL default list would advertise RC2/DES) → Outlook ≥ 16.8518 falls back to AES-256 |
| Intermediates in signatures | OWA omits them by default | included | included when sending; configure `mimeshield_intermediates` for OWA mail |
| Bcc | OWA: one encrypted copy per Bcc recipient | single envelope | separate envelopes (default) |
| PKCS#12 export (Windows) | "TripleDES-SHA1" (default) uses RC2-40 for the certificate bag | — | clear error + optional CLI conversion; re-export with AES256-SHA256 recommended |
| Recipient identifier in EnvelopedData | issuer+serial (default) or SKI | issuer+serial | only own keys matching a RecipientInfo are tried; if none matches, at most 5 other own keys (audit I-18 decision) |
| SHA-1 signed CRLs (older CAs) | — | — | accepted while `'sha1'` is in `mimeshield_legacy_digests` (default); otherwise revocation "unknown" (audit I-09 decision) |
| Embedded certificates with many/relative CRL distribution points | — | — | refused before OpenSSL (CVE-2026-35189 pre-check, F-16): signature "malformed", decryption error; no real CA issues such certificates |

Keeping SHA-1 signatures accepted with a warning (never green) is a deliberate decision (audit I-01,
2026-10-03): Outlook on the web signs with SHA-1 by default. Set `mimeshield_legacy_digests = []` to
reject them.

## 3. Manual interoperability checklist (Outlook and Thunderbird)

Prerequisites: a test mailbox reachable from both Roundcube and the desktop client; the real
certificate (e.g. Actalis S/MIME Mailbox Validated) imported in both; the correspondent's
certificate known on both sides; the Actalis root in `mimeshield_ca_bundle`.

Record client version, OS and result (✔/✘ + screenshot) for every line.

In the checklist, a green signature status assumes a trusted, valid certificate path and a
successful revocation check for every certificate below the trust anchor. With the default
`mimeshield_revocation = 'off'`, an otherwise valid signature shows a revocation-not-checked
warning instead. Record that warning as the expected result for that configuration.

### 3.1 Roundcube (MIME Shield) → Outlook

| # | Action in Roundcube | Expected in Outlook |
|---|---|---|
| O1 | Send **signed**, text/plain, Polish characters (ąęłńóśźż) | red rosette/"signed" icon, signature valid, signer = your address, text intact |
| O2 | Send signed **HTML** with an inline image and a PDF attachment | signature valid, image displayed, attachment opens |
| O3 | Send **encrypted** (to the Outlook user) | lock icon, opens without error |
| O4 | Send **signed + encrypted** | lock + rosette, signature valid after decryption |
| O5 | Send encrypted with **Bcc** to a second Outlook user | both can open; To recipient cannot see the Bcc recipient in message details |
| O6 | Reply in Outlook to O4 (encrypted) | Roundcube decrypts the reply and verifies Outlook's signature (see 3.2) |

### 3.2 Outlook → Roundcube (MIME Shield)

| # | Action in Outlook | Expected in Roundcube |
|---|---|---|
| O7 | Send signed (clear text signed option ON) | green bar: signature valid, certificate trusted, sender matches |
| O8 | Send signed with "Send clear text signed message" **OFF** (opaque) | green bar, message body displayed |
| O9 | Send encrypted | "decrypted (AES-…)" + "message not signed" warning |
| O10 | Send signed + encrypted | decrypted + green signature status |
| O11 | Send from OWA (Outlook on the web) signed | yellow warning "legacy digest SHA1" (default OWA setting) — or green when OWA uses SHA-256; "chain incomplete" means intermediates must be configured |
| O12 | Send a signed message, then modify it in transit (e.g. through a mailing list adding a footer) | red: modified, or "only part of the message is signed" |

### 3.3 Roundcube (MIME Shield) ↔ Thunderbird

| # | Action | Expected |
|---|---|---|
| T1 | Roundcube → TB signed (text, HTML, attachment, UTF-8) | TB shows "Digitally signed", valid |
| T2 | Roundcube → TB encrypted | TB shows "Encrypted", content readable (TB ESR decrypts AES-256-CBC) |
| T3 | Roundcube → TB signed + encrypted | encrypted + signed valid |
| T4 | TB → Roundcube signed | green bar |
| T5 | TB → Roundcube encrypted (AES-128-CBC by default for RSA-2048) | decrypted |
| T6 | TB → Roundcube signed + encrypted | decrypted + green |
| T7 | TB with an EC (P-256) certificate → Roundcube encrypted/signed | decrypted / green (ECDH) |

### 3.4 Sent folder

| # | Check | Expected |
|---|---|---|
| S1 | Open the Sent copy of O3/T2 in Roundcube | decrypts (encrypt-to-self) |
| S2 | Open the Sent copy of O3 in Outlook/TB with the same certificate | decrypts |
