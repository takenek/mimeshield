# MIME Shield – Testing

All numbers below are from the final run on 2026-10-02 (branch `feature/mimeshield`).

## 1. Test environment (actually used)

| Component | Versions |
|---|---|
| Roundcube | 1.7.0, 1.7.1, 1.7.2, 1.7.3, 1.7.4 (git tags, vendor resolved for PHP 8.1) and the **official signed release tarball** `roundcubemail-1.7.4-complete` (GPG signature of "Roundcube Developers <devs@roundcube.net>" verified) |
| PHP | 8.1.34, 8.2.34, 8.3.35, 8.4.26, 8.5.11 (Debian 13 + packages.sury.org) |
| OpenSSL | 3.5.6 (PHP 8.1 build), 3.5.7 (PHP 8.2–8.5, CLI) |
| libsodium | 1.0.18 |
| Databases | SQLite 3 (pdo_sqlite), MariaDB 11.8.6, PostgreSQL 17.11 — with and without `db_prefix` |
| IMAP / SMTP | Dovecot 2.4.1 (test users), aiosmtpd sink storing the exact SMTP DATA |
| Browser | Chromium 154 (headless) + Selenium 4.31 |
| Interop tools | Mozilla NSS 3.110 `cmsutil`, GnuPG 2.4.7 `gpgsm`, OpenSSL 3.5.7 CLI |
| Static analysis | PHPStan 2.x level 6, PHP-CS-Fixer 3.95 |

**Not available:** Microsoft Outlook (any edition), the Thunderbird application, Apple Mail, a real
Actalis PKCS#12. See docs/INTEROPERABILITY.md for the manual checklist.

## 2. Suites and how to run them

| Suite | Command | What it covers |
|---|---|---|
| PHPUnit (unit + integration) | `MIMESHIELD_RC=/path/to/roundcube vendor/bin/phpunit` | ASN.1, CMS, certificates, PKCS#12/KDF limits, key store, master keys, temp files, logging, trust/chain, revocation/SSRF, verification states, outgoing pipeline (real Mail_mime + Net_SMTP chunking + IMAP normalisation, verified with the openssl CLI), incoming processor (decrypt/verify/inject without IMAP), audit regressions |
| E2E | `python3 tests/e2e/test_e2e.py --rc <roundcube> --php php8.4 --db sqlite` | 57 cases against a real Roundcube over HTTP (login, settings, compose, send, IMAP), final SMTP DATA verified with the openssl CLI |
| E2E matrix | `tests/e2e/matrix.sh` | the E2E suite for 16 Roundcube × PHP × DB combinations |
| Browser UI | `python3 tests/ui/test_ui.py --rc <roundcube release dir> --php php8.4` | 13 cases in headless Chromium (needs the release tarball: git checkouts lack built assets) |
| Interop | `tests/interop/run.sh php8.4` | bidirectional CMS interop with NSS, gpgsm, OpenSSL |
| PHPStan | `php -d memory_limit=2G vendor/bin/phpstan analyse -c phpstan.neon.dist` | level 6 |
| Code style | `vendor/bin/php-cs-fixer fix --dry-run --config=.php-cs-fixer.dist.php` | |
| Fixtures | `tests/fixtures/generate.sh` | TEST-ONLY PKI (committed; regenerate any time) |

E2E/UI requirements: Dovecot with the users alice/bob/mallory/carol@example.test (password
`testpass`), python3-aiosmtpd, python3-requests (UI: chromium, chromium-driver, python3-selenium);
`tests/e2e/setup.sh` creates the Roundcube configuration, database, master key and SMTP sink.

## 3. Results of the final run

| Suite | Result |
|---|---|
| PHPUnit PHP 8.1 | Tests: 1005, Assertions: 11228, Failures: 0, Skipped: 1 |
| PHPUnit PHP 8.2 | Tests: 1005, Assertions: 11228, Failures: 0, Skipped: 1 |
| PHPUnit PHP 8.3 | Tests: 1005, Assertions: 11228, Failures: 0, Skipped: 1 |
| PHPUnit PHP 8.4 | Tests: 1005, Assertions: 11228, Failures: 0, Skipped: 1 |
| PHPUnit PHP 8.5 | Tests: 1007, Assertions: 11321, Failures: 0, Skipped: 1 (2 extra AES-GCM encryption cases, PHP ≥ 8.5 only) |
| PHPUnit PHP 8.1 with the Roundcube 1.7.0 library | Tests: 1005, Assertions: 11228, Failures: 0, Skipped: 1 |
| PHPStan level 6 | No errors (run on PHP ≥ 8.3: on 8.1 one notice about the PHP 8.3 constant `CURLOPT_REDIR_PROTOCOLS_STR`, used behind `defined()`) |
| PHP-CS-Fixer | 0 of 82 files need changes |
| `php -l` PHP 8.1–8.5 | 82 files, 0 errors on every version; no deprecation notices in any suite (PHPUnit fails on deprecations) |
| Browser UI PHP 8.1 / 8.5 | 12 passed, 0 failed / 12 passed, 0 failed |
| Interop PHP 8.1–8.5 | 11 passed, 0 failed on each version |
| E2E matrix | **16/16 combinations green, 57 passed / 0 failed / 0 skipped each** |

The skipped PHPUnit test (`SafeHttpClientTest::testDirectConnectionPinningToPublicAddressRequiresInternet`)
needs outbound Internet access, which the test machine does not have.

E2E matrix combinations: 1.7.4 × PHP 8.1/8.2/8.3/8.4/8.5 (SQLite); 1.7.0/1.7.1/1.7.2/1.7.3 × PHP 8.4
(SQLite); 1.7.0 × PHP 8.1 (SQLite); 1.7.4 × PHP 8.4 (MariaDB); 1.7.4 × PHP 8.4 (PostgreSQL); 1.7.4 ×
PHP 8.1 (MariaDB, `db_prefix = rc_`); 1.7.4 × PHP 8.5 (PostgreSQL, `db_prefix = rc_`); official
release 1.7.4 × PHP 8.1 (SQLite) and × PHP 8.5 (MariaDB).

## 4. The 30 mandatory functional / regression tests

| # | Requirement | Test (E2E case unless noted) | Result |
|---|---|---|---|
| 1 | import valid .p12 | 01 | PASS |
| 2 | import valid .pfx | 02 | PASS |
| 3 | wrong PKCS#12 password | 03 (+ KeyImporterTest) | PASS |
| 4 | PKCS#12 without private key | 04 | PASS |
| 5 | mismatched certificate / key | 05 | PASS |
| 6 | expired certificate | 06 | PASS |
| 7 | not-yet-valid certificate | 07 | PASS |
| 8 | certificate for another address | 08 | PASS |
| 9 | sign text/plain | 09 | PASS |
| 10 | sign HTML | 10 | PASS |
| 11 | sign UTF-8 with Polish characters | 11 | PASS |
| 12 | sign with attachment | 12 | PASS |
| 13 | sign multipart/alternative | 13 | PASS |
| 14 | sign multipart/related with inline image | 14 | PASS |
| 15 | verify valid detached signature | 15 (+ U9) | PASS |
| 16 | detect modified message | 16 | PASS |
| 17 | unknown CA | 17 | PASS |
| 18 | trusted chain | 18 | PASS |
| 19 | encrypt for one recipient | 19 | PASS |
| 20 | encrypt for several recipients | 20 | PASS |
| 21 | block encryption when a recipient certificate is missing | 21, 40 (+ U5, U6) | PASS |
| 22 | BCC | 22, 39 | PASS |
| 23 | decrypt | 23 | PASS |
| 24 | decrypt with attachment | 24 | PASS |
| 25 | sign + encrypt | 25 | PASS |
| 26 | encrypt + decrypt + verify | 26 | PASS |
| 27 | correct certificate after identity change | 27 (+ U3) | PASS |
| 28 | isolation between two users | 28 | PASS |
| 29 | logout/login and PHP restart | 29 | PASS |
| 30 | final SMTP DATA verified by an independent implementation | 30 (every captured DATA, openssl CLI) + tests/interop (NSS, gpgsm) | PASS |

Additional E2E cases: 31 encrypted draft (encrypt-to-self, never signed, options restored), 32 reply
forces encryption, 33 CSRF, 34 XSS via certificate names, 35 public-only export, 36 print view,
37 no private key in any HTTP response, 38 contact chain re-import, 41 CLI diag/keygen/rotation,
42 signed+encrypted reply, 43 forward inline/as attachment, 44 contact certificate replacement +
preferred certificate, 45 "observed" sender certificate, 46 EFAIL/sanitiser for decrypted HTML
(show, preview, `_safe=1`, get), 47 EFAIL in decrypted HTML drafts; inbound interop I1–I9 (Outlook /
OWA / Exchange / Thunderbird structures). Browser cases U1–U13 cover the compose, settings and
message-view JavaScript.

## 5. 30-point security audit

Performed by independent reviewers (first round with two adversarial verifiers per finding, then a
re-audit of every former FAIL that tried to bypass the fixes). Final state:

| # | Item | First round | Final | Evidence / fix |
|---|---|---|---|---|
| 1 | SQL injection | PASS | PASS | all SQL parameterised; constant table names via `table_name()`; session user id in every statement |
| 2 | Stored XSS through certificate data | PASS | PASS | `rcube::Q`/`html::*`, JS `.text()`; E2E 34, UI U8 |
| 3 | Reflected XSS | PASS | PASS | ids cast to int, no request value echoed |
| 4 | DOM XSS | PASS | PASS | no innerHTML/`.html()`/eval with data |
| 5 | CSRF | PASS | PASS | POST + token (`hash_equals`) in every mutating action; E2E 33 |
| 6 | IDOR between users | PASS | PASS | user-scoped repositories; E2E 28 |
| 7 | use of another user's private key | PASS | PASS | scoped lookups + AEAD context binding |
| 8 | binding a certificate to someone else's identity | PASS | PASS | `rcube_user::get_identity()` + address check |
| 9 | path traversal in uploads | PASS | PASS | upload names never used as paths |
| 10 | MIME type spoofing | PASS | PASS | content-based format detection; private keys refused in the public store |
| 11 | oversized PKCS#12 | PASS | PASS | size limits before reading; post_max_size message |
| 12 | malicious PKCS#12 | FAIL (KDF iteration DoS) | PASS | `KdfInspector` limits checked before OpenSSL (690c3ab); AuditRegressionTest; re-audit PASS |
| 13 | certificate parser DoS | PASS | PASS | bounded ASN.1 reader; fuzzing in Asn1Test/CmsInspectorTest |
| 14 | temp file races | PASS | PASS | `tempnam` (mkstemp) in a private 0700 directory |
| 15 | symlink attacks | PASS | PASS | symlinked/foreign-owned temp dir refused |
| 16 | temp file permissions | PASS | PASS | 0700 / 0600, pre-created outputs |
| 17 | private key left after errors | PASS | PASS | keys never written to disk (PEM strings to OpenSSL) |
| 18 | private key in logs | PASS | PASS | redacting logger; no key material passed |
| 19 | PFX password in logs | PASS | PASS | password removed from `$_POST`, wiped, never stored |
| 20 | master key protection | PASS | PASS | outside DB; permission and location checks |
| 21 | key store integrity | PASS | PASS | AEAD with header+context AAD; check-keystore |
| 22 | nonce/IV reuse | PASS | PASS | random 192/96-bit nonces |
| 23 | AE failure handling | FAIL (short GCM tags accepted) | PASS | tag length/ICVlen check, fail-closed positional parser (690c3ab, c396477); AuditRegressionTest incl. decoy recipient |
| 24 | downgrade to plaintext | FAIL (admin lock overridable by user preference) | PASS | admin values never from user preferences (690c3ab, c396477); AuditRegressionTest; re-audit PASS |
| 25 | sender/certificate mismatch | FAIL (unparsable extra From ignored) | PASS | strict, charset-aware address parsing (690c3ab, c396477); AuditRegressionTest |
| 26 | certificate metadata / header injection | PASS | PASS | certificate data never in headers; display-safe names |
| 27 | SSRF via CRL/OCSP/AIA | FAIL (trailing-dot host bypassed DNS pinning) | PASS | trailing-dot hosts refused, pre-request address check on PHP ≥ 8.4 (690c3ab); re-audit PASS |
| 28 | sanitiser bypass after decrypt | FAIL (remote content via get action / HTML reply; draft compose) | PASS | messages with decrypted content never "safe", draft re-wash (690c3ab, c396477); E2E 46, 47 |
| 29 | unauthorised private key export | PASS | PASS | no export path exists; E2E 35, 37 |
| 30 | corrupted S/MIME / CMS | FAIL (nested BER strings exhausted memory) | PASS | depth limits (690c3ab); AuditRegressionTest; re-audit PASS |

No FAIL remains open. Lower-severity hardening proposals from the audit that were implemented are
listed in docs/ARCHITECTURE.md §8a.

## 6. Bugs found by the test suites (all fixed)

Unit/integration tests: smime.p7s not hidden for top-level signed mail; "From " escaping stopped at a
`-- ` signature separator; CRL scope (IDP) and `onlySomeReasons` not enforced; regexes accepting a
trailing newline; lax ASN.1 times/tags; DER certificates trimmed; partial master-key load cached;
line-wrapped base64 not redacted. E2E: triple-wrapped signed(enveloped(signed)) not unwrapped;
contact chain re-import not updating trust. Browser tests: compose form permanently "changed"; export
locking the UI; "send without encryption" not sending (core TypeError); settings list widget not
loaded; long send-error text used as identity status.

## 7. UX iteration (settings bindings, compose S/MIME section)

Re-run after the UX changes on Roundcube 1.7.4 (official release tarball for the browser suite),
PHP 8.4.26: PHPUnit 1005 tests / 0 failures / 1 skipped (as above); PHPStan level 6 no errors;
PHP-CS-Fixer 0 files; `php -l` PHP 8.1/8.4/8.5 0 errors; E2E 57 passed / 0 failed; interop 11
passed; browser UI 13 passed / 0 failed (new U13: unsaved-changes notice, primary Save, confirmation
after the list reload, visible compose "S/MIME" section); `mimeshield.sh diag` Result: OK.

Known test-harness flake (also present before the UX changes): in roughly one of three runs of the
browser suite headless Chromium stops responding at the login of U10 ("Timed out receiving message
from renderer"), and U10 and every later case fail with that timeout. A re-run passes.

## 8. Security remediation run (final security report, 2026-10-02)

Re-run after the remediation of findings MS-01 – MS-15 / INF-02, -03, -05, -06 (see CHANGELOG
"Security"). Only the combinations below were run; the full E2E matrix (MariaDB, PostgreSQL,
`db_prefix`, Roundcube 1.7.0–1.7.3) was **not** re-run. Since this change the supported minimum is
Roundcube 1.7.4 (`min-version`); the older tags remain in section 3 as historical results.

| Suite | Environment | Result |
|---|---|---|
| PHPUnit | PHP 8.4.26, Roundcube 1.7.4 git library (PHPUnit 11.5) | Tests: 1036, Assertions: 11496, Failures: 0, Skipped: 1 |
| PHPUnit | PHP 8.2, 8.3 (same library) | Tests: 1036, Failures: 0, Skipped: 1 |
| PHPUnit | PHP 8.5 (same library) | Tests: 1038, Failures: 0, Skipped: 1 (AES-GCM cases) |
| PHPUnit | PHP 8.1.34, official 1.7.4 release library (PHPUnit 10.5) | Tests: 1036, Assertions: 11496, Failures: 0, Skipped: 1 |
| PHPStan level 6 | PHP 8.4 | No errors |
| PHP-CS-Fixer | dry run | 0 of 85 files need changes |
| E2E | Roundcube 1.7.4 git × PHP 8.4 × SQLite | 58 passed / 0 failed / 0 skipped (new case 48) |
| Browser UI | official 1.7.4 release × PHP 8.4, Chromium headless | 13 passed / 0 failed |
| Interop | PHP 8.4 | 11 passed / 0 failed |
| `mimeshield.sh diag` | E2E instance | Result: OK (warnings: `1.7-git` is not a release version; OpenSSL 3.5.7 below 3.5.9 on the test machine) |

New regression tests: `IncomingProcessorTest::testForwardedOpaqueSignedEnvelopeIsNotDecrypted`,
`::testForwardedNestedOpaqueSignedStaysPartial` (MS-02); `ChainValidatorTest::testEcRecipientUnderTlsOnlyIntermediateHasBadPurpose`,
`::testRsaRecipientUnderTlsOnlyIntermediateIsStillRejectedByOpenssl` (MS-03);
`OutgoingPipelineTest::testRevokedRecipientImportedWithoutChainIsBlocked`,
`::testUnknownRecipientRevocationIsSignalledOrBlockedByPolicy` (MS-04),
`::testSwappedCertificateInOwnKeyRecordIsRejected`, `::testInsertedOwnKeyRecordIsNotUsedForEncryption`,
`::testOwnStatusOnlyForIdentityAddresses` (MS-09), `::testTotalSizeOfSeparateBccEnvelopesIsBounded` (MS-10);
`AuditRegressionTest::testExpensiveKeyBagHiddenInEncryptedLayerIsRejected`,
`::testNormalKeyBagInEncryptedLayerPassesTheInspection` (MS-05),
`::testUserPreferenceCannotChangeTrustAnchorsOrMasterKeySource` (MS-13), `::testSystemCaStoreIsNotTrustedByDefault` (MS-07);
`RevocationCheckerTest::testIdpWithDirectoryNameOnlyCannotProveGood`,
`::testIdpWithMatchingUriAndAnotherNameFormIsInScope` (MS-06); `SignatureVerifierTest::testUninspectableStructureIsNeverFullyOk` (MS-08,
replaces `testUninspectableStructureMakesNoAlgorithmDecision`); `RateLimiterTest` (MS-11);
`CliKeygenTest::testDefaultModeAndAppendRefuseDirectoryWritableByOthers`,
`::testDefaultModeRefusesParentReachedThroughSymbolicLinkInThePath` (MS-12); E2E case 48 (MS-01:
outdated schema + encryption lock → send and draft refused, plain send still possible) and E2E 35
(INF-02: export only via POST). The MS-01, MS-02, MS-03, MS-05 and MS-06 tests were also run against the
code before the fix and failed there (the defects were reproducible).

Remediation verification run (same day, after the follow-up fix in `KdfInspector`: the iteration
count of an encrypted PKCS#12 layer is validated before the inspection derives its key — new test
`AuditRegressionTest::testEncryptedLayerWithNonIntegerIterationCountIsRejected`, MS-05): PHPUnit
PHP 8.4.26 / Roundcube 1.7.4 git library 1037 tests / 0 failures / 1 skipped; PHP 8.5 1039 / 0 / 1;
PHP 8.1.34 with the official 1.7.4 release library (PHPUnit 10.5) 1037 / 0 / 1; PHPStan level 6
(`phpstan.neon.dist`, without the strict-rules extension) no errors; PHP-CS-Fixer 0 of 85 files;
`php -l` 0 errors; E2E 1.7.4 git × PHP 8.4 × SQLite 58 passed / 0 failed; interop 11 passed. The
browser UI suite and the full E2E matrix were not re-run. Before the fix, the same synthetic layer
structures made the inspection loop without bound (PKCS#12 PBE) or end with an uncaught `ValueError`
(PBES2).

## 9. Security remediation run (final security report, 2026-10-03, IDs F-xx)

Environment of this run: Debian 13, PHP 8.4.26 CLI (Debian packages), OpenSSL 3.5.7 (CLI and
library), PHPUnit 11.5.56, Roundcube 1.7.4 library from Composer (`roundcube/roundcubemail`, pulled in
by `roundcube/plugin-installer`) used as `MIMESHIELD_RC`.

| Suite | Result |
|---|---|
| PHPUnit with `MIMESHIELD_RC` (unit + integration) | Tests: 1102, Assertions: 11958, Failures: 0, Skipped: 1 (needs Internet) |
| PHPUnit without `MIMESHIELD_RC` (unit only) | Tests: 1102, Failures: 0, Skipped: 151 (integration tests need Roundcube) |
| `php -l` (PHP 8.4) | all PHP and localization files, 0 errors |
| `node --check js/mimeshield.js` | OK |

**Not run in this pass:** PHP 8.1/8.2/8.3/8.5, PHPStan, PHP-CS-Fixer (not installed), E2E and the
E2E matrix (need Dovecot, SMTP sink, real Roundcube instances), browser UI tests (Chromium), interop
(NSS, gpgsm). They must be run before a release, in particular the browser suite for the header
indicator (F-10) and the compose dialog (F-09, F-15).

New or changed regression tests:
`IncomingProcessorTest::testContainerWithNonSignatureSecondPartIsNotTreatedAsSmime`,
`::testContainerWithoutProtocolParameterIsNotTreatedAsSmime`, `::testTrailingDataAfterSignatureDerIsRejected`,
`::testClearSignedTopLevelIsVerifiedAndSignaturePartHidden` (changed: only the verified first part is
displayed) (F-01); `::testDisplayedContentIsTheVerifiedBytesWithBoundaryPrefixLine` (F-13);
`::testSignatureVerificationsPerMessageAreBounded` (F-07);
`RevocationPathTest` (new, throw-away PKI with CRL DPs on every level):
`::testCaInTheOpenSslDefaultDirectoryIsNeverTrusted`, `::testNonEmptyIsolationDirectoryFailsClosed`
(F-02, also closes INF note I-16), `::testWholePathGoodIsGood`, `::testRevokedIntermediateRevokesTheLeaf`,
`::testIntermediateWithoutUsableCrlIsUnknownNotGood`, `::testCaOnlyCrlCoversCasButNotEndEntities`,
`::testEndEntityOnlyCrlNeverCoversACa` (F-04), `::testShippedIssuerCopyWithoutCrlSignNeverHidesTheRevocation`,
`::testIssuerWithoutCrlSignIsReplacedOnlyByAnAdministratorCertificate`,
`::testFindIssuerPrefersAdministratorCertificatesThatMaySignCrls` (F-05);
`RevocationCheckerTest::testCheckWithoutHttpDistributionPointIsUnknown` (F-06, replaces
`…IsNotChecked`), `::testUnreachableCrlIsNotRequestedAgainWithinTheNegativeTtl`, `::testFetchBudgetPerRequest`,
`::testCacheDirectoryIsCreatedPrivately` (changed) (F-14);
`SignatureVerifierTest::testGoodSignerWithUncheckableIntermediateIsUnknown` (replaces
`testGoodSignerFromCachedCrl`), `::testExpiredChainIsStillCheckedForRevocation` (changed),
`OutgoingPipelineTest::testRevokedRecipientImportedWithoutChainIsBlocked` (changed: the TEST
intermediate has no CRL DP, so the path is "unknown") (F-04/F-06);
`AuditRegressionTest::testSegmentedBerAuthSafeIsInspectedOnTheJoinedContent`,
`::testUnparsableAuthSafeContentIsRefused` (F-03), `::testPhpKeyDerivationWorkIsBounded` (F-08);
`RateLimiterTest::testPersistentLimitIsSharedAcrossSessions` (historical Stage 5 mock, replaced by
`AccountRateLimiterTest` during the second verification pass below) (F-08); `ComposeDecryptedTest` (F-09);
`MessageHeaderBadgeTest` (F-10); `DotGuardTest::testMakeSafePadsUntilSafe`,
`::testMakeSafeReportsAnUnfixablePayload` (F-11); `CliKeygenTest::testAppendRefusesAnEmptyKeyFile`,
`::testConcurrentAppendsAreSerialisedAndKeepEveryKey` (F-12);
`OutgoingPipelineTest::testUntrustedCertificateFromMessageNeedsConfirmationUnderWarnPolicy`,
`::testUntrustedCertificateFromMessageUnderBlockPolicyIsStoredButNeverUsable` (F-15);
`VerificationResultTest::testNotCheckedIsOkOnlyWhenCheckingIsDisabled` (F-06),
`::testMultipleSignersAreAWarning` (I-12); `MessageHeaderBadgeTest::testOutdatedCipherIsAWarning` (I-11).
The `diag` warnings for I-03/I-08 and the "save sender certificate" limit (I-17) are covered by
`php -l` only (no automated test in this run).
The F-03 and F-08 tests were also run against the code before the fix and failed there.

**Verification pass (same environment):** PHPUnit with `MIMESHIELD_RC`: Tests: 1106, Assertions:
11996, Failures: 0, Skipped: 1 (needs Internet); without `MIMESHIELD_RC`: Tests: 1106, Skipped: 155.
Added regression tests that run the real plugin hooks instead of copies of their code:
`OutgoingPipelineTest::testMessageBeforeSendHookBlocksAPayloadThatCannotBeMadeTransportSafe` and the
real `mimeshield::message_before_send` call in
`::testLargeClearSignedMessageWithDotsSurvivesNetSmtpChunkingWithDotGuard` (F-11; the delivery
emulation now uses `DotGuard::makeSafe()` like the hook); `DecryptedReplyPolicyTest` runs
`mimeshield::message_ready` with `mimeshield_require_encrypt_for_decrypted` (send and draft refused for a
compose holding decrypted content, other composes and the default `false` unaffected) (F-09). Both
new tests were checked to fail when the respective check in `mimeshield.php` is disabled.

**Second independent verification pass (2026-10-03):** the final unchanged code/test snapshot passed
PHPUnit **1138 tests / 12226 assertions / 0 failures / 0 errors / 1 skipped** on PHP 8.4.26,
OpenSSL 3.5.7 and the existing Roundcube 1.7.4 libraries. The skipped test requires a direct
connection to a public Internet address; it was not enabled. A temporary Roundcube directory links
to the already installed library and Composer autoloader; no dependencies were installed.
PHP syntax checks passed for 93 source/test/config/localisation files, `node --check` passed,
and Python AST parsing passed for the edited E2E/UI scripts. E2E, browser rendering, interop,
PHPStan/PHP-CS-Fixer and the other PHP/database versions were not run.

Additional regression coverage:

- `IncomingProcessorTest`: signed/enveloped data is rebuilt from verified bytes before unwrap;
  rebuild failure clears success; opaque verification without a trust verifier consumes the budget.
- `RevocationPathTest`: all RSA-sign, RSA-encrypt and EC-encrypt cases first demonstrate native
  default-directory trust and then rejection with the isolated CA locations.
- `AuditRegressionTest`: ordinary-cost segmented BER (definite/indefinite) is inspected and imported
  by the real native PKCS#12 parser, with the expected public certificate.
- `AccountRateLimiterTest`: committed quota across connections, account isolation, failed-write
  rollback, clock rollback and two concurrent processes competing for the final reservation.
- `ComposeWarningTest`, `ComposeDecryptedTest`, `DecryptedReplyPolicyTest`: warning before send,
  retained protection for active compose sessions, send/draft rejection with missing schema.
- `RevocationCheckerTest`, `SafeHttpClientTest`: issuer-specific failure isolation, shared transfer
  deadline, remaining cURL timeout, DNS deadline checks and valid cached data after budget expiry.
- `SettingsActionsTest`: absent/stale/replayed confirmation, GET preservation, binding success,
  validation before writes, transaction-start failure and actual SQLite rollback after a write error.
- `CliKeygenTest`: failed read and short write followed by failure preserve the original key file.
- `LogTest`, `MessageSaveCertLimitTest`, `MessageHeaderBadgeTest`: exception details only in debug,
  rate-limit gate before storage, explicit warning when revocation has not been checked.

Third verification pass (2026-10-03) additions: `DecryptedReplyPolicyTest` (draft refused with
`mimeshield_encrypt_drafts = false`), `ComposeWarningTest` (no localStorage copy of a decrypted
compose), `IncomingProcessorTest` (a `multipart/signed` nested in verified content is not re-read
through IMAP), `RevocationCheckerTest` (no negative-cache marker for a budget-limited failure;
outdated CRL negatively cached), `KeyImporterTest` (uninspectable encrypted PKCS#8 PEM refused),
`MessageHeaderBadgeTest` (non-AES content cipher warns). Each new test was checked to fail without
its fix where the fix is a behaviour change.

The E2E/UI expectations now include the revocation-disabled warning and decrypted-compose warning;
syntax validation is not evidence that those browser flows passed. Before release, run the existing
reference-stack matrix, especially the new transactional paths on MySQL/MariaDB and PostgreSQL.
The synchronous DNS call and native OpenSSL work still require resolver/PHP-FPM lifetime limits.

**Fourth verification pass (2026-10-03):** PHP 8.4.26, OpenSSL 3.5.7, PHPUnit 11.5.56,
the existing Roundcube 1.7.4 libraries and SQLite. The post-change suite passed **1147 tests /
11555 assertions / 0 failures / 0 errors / 1 skipped** using
`MIMESHIELD_RC=/tmp/mimeshield-stage6-02-rc vendor/bin/phpunit --filter '^(?!.*::testFuzz)'`.
The temporary Roundcube directory links to the existing local installation; substitute its path
when reproducing the run. Nine fuzzing data sets were explicitly excluded by the passive
verification scope. The one skipped test needs direct Internet access. No dependencies were
installed and no external service was contacted.

- `IncomingProcessorTest` now checks that compose/download rebuild clear-signed content and
  attachments with the same parser as the message view, without a signature claim. Size, failed
  extraction and the shared eight-entity budget are covered.
- `RevocationCheckerTest` checks both the cache base and `crl/` directory for unsafe permissions,
  foreign ownership and symlinks. Neither a cached CRL nor a failure marker in an unsafe directory
  is trusted; directory permissions are left unchanged.

E2E/browser rendering, the PHP/database matrix, interop and PHPStan/PHP-CS-Fixer were not run in
this pass. Local passing tests do not replace those release checks.

**Fifth verification pass (2026-10-03):** same local stack (PHP 8.4.26, OpenSSL 3.5.7,
PHPUnit 11.5.56, Roundcube 1.7.4 libraries, SQLite). Before any change the suite gave the
fourth-pass result (1147 / 11555 / 1 skipped, fuzzing data sets excluded). After the changes:
**1150 tests / 11588 assertions / 0 failures / 0 errors / 1 skipped** with the same
`--filter '^(?!.*::testFuzz)'`. One earlier run of this pass also included the nine local fuzzing
data sets (1156 tests / 12404 assertions, all passing); they test only the plugin's own parser on
generated input and contact nothing.

- `AuditRegressionTest::testUninspectableKeyEncryptionSchemesAreRefused`: PBES1 with MD2 counts its
  iterations; an unknown scheme, PBES2 with an unknown key derivation function and a PBKDF2 key
  length above 64 bytes are refused; ordinary PBES2/PBKDF2 still passes.
- `AuditRegressionTest::testUnknownSchemeInPkcs12KeyBagIsNotPassedToOpenSsl`: a shrouded key bag
  with an unknown scheme gives `p12legacy` instead of reaching `openssl_pkcs12_read()`.
- `OutgoingPipelineTest::testMainDeliveryFailureAfterBccEnvelopesIsReported`: runs the real
  `message_before_send` and `message_send_error` hooks with a stub SMTP client.

Each new test was checked to fail without its fix. E2E/browser rendering, the PHP/database matrix,
interop and PHPStan/PHP-CS-Fixer were not run in this pass.

## 10. Remediation decisions (2026-10-03)

Implementation of the operator decisions on the remaining audit items (rationale: SECURITY.md,
"Design decisions and accepted risks"). Local stack as above (PHP 8.4.26, OpenSSL 3.5.7, Roundcube
1.7.4 libraries, SQLite). Full suite with `--filter '^(?!.*::testFuzz)'`:
**1218 tests / 11895 assertions / 0 failures / 0 errors / 1 skipped** (the SafeHttpClient
direct-connection test, needs internet). `php -l` clean on all changed files. PHPStan was not
installed locally; it now runs in CI (`.github/workflows/ci.yml`), which has not yet run on GitHub.

New or changed tests ("fails without fix" = checked against the code without the change):

- I-09/I-02 (`RevocationCheckerTest`): `testSha1CrlIsUnknownWhenSha1IsNoLegacyDigest`,
  `testServicesWireTheCrlPolicy`, `testHigherCrlNumberIsStoredAndEqualIsAccepted`,
  `testLowerCrlNumberThanPreviouslySeenIsUnknown`, `testCrlWithoutNumberIsAcceptedWhenANumberWasSeen`,
  `testCrlNumberStoreFailureDoesNotBreakChecks`, `testReplayedOlderCrlIsNeitherUsedNorCached`,
  `testOlderCachedCrlIsReplacedByAFreshFetch` (all fail without fix); guards
  `testSha1CrlIsAcceptedByDefault`, `testCrlNumberComparisonIsNumeric`,
  `testCrlNumbersAreTrackedPerIssuerAndDistributionPoint`. `SharedCacheCrlNumberStoreTest` (new,
  4 tests: immediate write to `cache_shared`, invalid entries, daily rewrite, no store without CRL).
- I-18 (`SignatureVerifierTest`): `testDecryptionCandidatesAreOnlyTheMatchingKeysWhenOneMatches`,
  `testDecryptionCandidatesWithoutAnyMatchAreBoundedToFive`, changed
  `testRotationSwitchesSigningKeyAndOldKeyStillDecrypts` (all fail without fix); `testFindIssuer`
  removed with the dead method.
- F-16 (`CertPrecheckTest`, 11 tests): 8 fail without the pre-check (more than 8 points, relative
  name, duplicate extension, unparsable value, verifyDetached/verifyOpaque/decrypt with an unsafe
  embedded certificate, PKCS#7 bundle refused before OpenSSL); 3 positive controls (all fixture
  certificates pass, 8 full-name points accepted, certificate choices of fixtures).
- I-14/I-15/F-14 (`DiagChecksTest`, new): PHP security support (12 cases), PHP 8.1 warning text,
  temp dir file system (9 cases), later mount wins, unknown mount table is informational, resolver
  worst case (9 cases). They test new helpers, so they were not run against the old code.
- keygen (`CliKeygenTest::testNewKeyFileWriteIsCheckedAndPartialFileRemoved`): short and failing
  writes of a new key file; fails without fix.
- I-15 (`TempDirStrictTest`, new): strict mode refuses sign/encrypt/decrypt/verify, non-strict falls
  back, send aborted with the temp-dir message (each fails without fix); usable directory and
  localisation guards.
- I-17 (`MessageSaveCertLimitTest::testAccountLimitAppliesAcrossSessions`): fails without the
  per-account limit.

Not run in this pass: E2E/browser rendering, the PHP/database matrix, interop, PHPStan, CI on GitHub.

## 11. v1.0.0 release verification (2026-10-03)

Release-candidate verification was completed before tagging `v1.0.0`.

Tested production snapshot: `6bf09b52ae23f7caeec8d524e5dc0e8deb0b2dc1` on `main` after PR #5. PR #5 changed only the Python
E2E harness so that its confirmation requests match the security-hardened browser protocol
(`_pending_digest` for certificate replacement and `_fingerprint` for save-sender-certificate);
it did not change plugin runtime or cryptographic code.

| Check | Environment | Result |
|---|---|---|
| GitHub CI | `main`, PHP 8.1 / 8.2 / 8.3 / 8.4 / 8.5 + PHPStan | **PASS** |
| Interoperability | PHP 8.4.26, OpenSSL CLI, NSS `cmsutil`, GnuPG `gpgsm` | **11 passed / 0 failed** |
| Browser UI | official signed Roundcube 1.7.4 complete release, PHP 8.4.26, Chromium 154 / Selenium 4.31.1 | **13 passed / 0 failed** |
| End-to-end | official signed Roundcube 1.7.4 complete release, PHP 8.4.26, SQLite, Dovecot 2.4.1, SMTP sink | **58 passed / 0 failed / 0 skipped** |

The Roundcube test package `roundcubemail-1.7.4-complete.tar.gz` was independently verified before
use:

- SHA-256: `2c6c878f0093f1bf7fb6086781d2dd9269d652c016b86939c157c5f1729139a2`;
- detached GPG signature: **good signature** from
  `Roundcube Developers <devs@roundcube.net>`;
- signing subkey fingerprint:
  `8970 E37A 698A F775 D87D 590D C294 6A96 09CD 56B4`;
- primary key fingerprint:
  `F3E4 C04B B3DB 5D42 15C4 5F7F 5AB2 BAA1 41C4 F7D5`.

The full E2E run included certificate import and replacement confirmation, signing, encryption,
decryption, Bcc handling, drafts, identity isolation, CSRF/XSS checks, Outlook/OWA/Thunderbird
message structures, RSA-OAEP, AES-GCM, BER streaming, key rotation, schema-failure fail-closed
behaviour, and independent OpenSSL verification/decryption of every captured protected SMTP DATA.

The browser suite covered all 13 UI cases, including identity switching, recipient status,
missing-certificate confirmation, explicit plaintext fallback, certificate settings, malicious
certificate-name escaping, save-sender-certificate, key deletion warning, encrypted replies, and
identity binding save-state behaviour.

