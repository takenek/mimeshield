<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Cert\Certificate;
use MimeShield\Crypto\CmsService;
use MimeShield\Crypto\SignatureCheck;
use MimeShield\Service\SignatureVerifier;
use MimeShield\Tests\TestPki;
use MimeShield\Trust\ChainResult;
use MimeShield\Trust\ChainValidator;
use MimeShield\Trust\RevocationChecker;
use MimeShield\Trust\RevocationResult;
use MimeShield\Trust\SafeHttpClient;
use MimeShield\Trust\TrustStore;
use MimeShield\Trust\VerificationResult;
use PHPUnit\Framework\TestCase;

final class SignatureVerifierTest extends TestCase
{
    private const CONTENT = "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\nHello from the test suite.\r\n";
    private const CRL_URL = 'http://crl.example.test/int.crl';

    private string $tmp;

    /** @var list<string> hosts passed to the DNS resolver test hook */
    private array $resolved = [];

    protected function setUp(): void
    {
        $this->tmp = TestPki::tempDir();
        $this->resolved = [];
        $GLOBALS['mimeshield_test_log'] = [];
    }

    protected function tearDown(): void
    {
        self::rmTree($this->tmp);
    }

    // --- builders ------------------------------------------------------------------------------

    private function store(): TrustStore
    {
        return new TrustStore([TestPki::path('root.crt')], false, []);
    }

    private function revocationOff(): RevocationChecker
    {
        return new RevocationChecker(RevocationChecker::MODE_OFF, null, '');
    }

    /**
     * CRL checker that never touches the network: DNS resolution goes to a hook that records the host
     * and returns a private address (which SafeHttpClient refuses before connecting).
     */
    private function revocationCrl(bool $seedCache): RevocationChecker
    {
        $cacheDir = $this->tmp . '/cache';
        if ($seedCache) {
            mkdir($cacheDir . '/crl', 0700, true);
            file_put_contents($cacheDir . '/crl/' . hash('sha256', self::CRL_URL) . '.crl', TestPki::read('int.crl'));
        }
        $http = new SafeHttpClient(2, 1, [80, 443], [], [], '', function (string $host): array {
            $this->resolved[] = $host;
            return ['10.11.12.13'];
        });
        return new RevocationChecker(RevocationChecker::MODE_CRL, $http, $cacheDir);
    }

    private function verifier(?RevocationChecker $rev = null, bool $subjectFallback = true): SignatureVerifier
    {
        $store = $this->store();
        return new SignatureVerifier(new ChainValidator($store, $this->tmp), $store, $rev ?? $this->revocationOff(),
            ['sha256', 'sha384', 'sha512'], ['sha1', 'sha224'], $subjectFallback, 2048);
    }

    private function cms(): CmsService
    {
        return new CmsService($this->tmp);
    }

    /**
     * Sign with the plugin's own CmsService (intermediate embedded) and verify.
     */
    private function signedByService(string $name, bool $embedIntermediate = true): SignatureCheck
    {
        $der = $this->cms()->signDetached(self::CONTENT, TestPki::cert($name), TestPki::key($name), $embedIntermediate ? [TestPki::read('int.crt')] : []);
        return $this->cms()->verifyDetached(self::CONTENT, $der);
    }

    /**
     * Sign with the openssl CLI (any digest, any signer, no validity checks) and verify $verifyContent.
     *
     * @param list<string> $extraCerts fixture file names to embed
     */
    private function signedByCli(string $name, array $extraCerts = ['int.crt'], string $md = 'sha256', ?string $verifyContent = null, ?string $certFile = null, ?string $keyFile = null): SignatureCheck
    {
        $in = $this->tmp . '/in-' . bin2hex(random_bytes(4));
        $out = $in . '.der';
        file_put_contents($in, self::CONTENT);
        $cmd = ['/usr/bin/openssl', 'cms', '-sign', '-binary', '-md', $md, '-in', $in,
            '-signer', $certFile ?? TestPki::path($name . '.crt'), '-inkey', $keyFile ?? TestPki::path($name . '.key'), '-outform', 'DER', '-out', $out];
        if ($extraCerts !== []) {
            $chain = $in . '.chain';
            file_put_contents($chain, implode("\n", array_map(static fn (string $f) => TestPki::read($f), $extraCerts)));
            array_push($cmd, '-certfile', $chain);
        }
        self::sh($cmd);
        return $this->cms()->verifyDetached($verifyContent ?? self::CONTENT, (string) file_get_contents($out));
    }

    /**
     * @return array<string, array{0: array<string, string>, 1: string}>
     */
    private static function linesByLabel(VerificationResult $r): array
    {
        $out = [];
        foreach ($r->lines() as [$label, $vars, $severity]) {
            $out[$label] = [$vars, $severity];
        }
        return $out;
    }

    private static function assertLine(VerificationResult $r, string $label, string $severity, ?array $vars = null): void
    {
        $lines = self::linesByLabel($r);
        self::assertArrayHasKey($label, $lines, 'missing line ' . $label . ' in ' . implode(',', array_keys($lines)));
        self::assertSame($severity, $lines[$label][1], 'severity of ' . $label);
        if ($vars !== null) {
            self::assertSame($vars, $lines[$label][0], 'vars of ' . $label);
        }
    }

    private static function assertNoLine(VerificationResult $r, string $label): void
    {
        self::assertArrayNotHasKey($label, self::linesByLabel($r));
    }

    // --- happy path ----------------------------------------------------------------------------

    public function testValidTrustedMatchingSignatureIsOk(): void
    {
        $check = $this->signedByService('alice');
        self::assertTrue($check->valid);
        $r = $this->verifier()->evaluate($check, ['alice@example.test'], []);

        self::assertNotNull($r->signer);
        self::assertSame(TestPki::cert('alice')->fingerprint, $r->signer->fingerprint);
        self::assertTrue($r->cryptoValid());
        self::assertSame(ChainResult::TRUSTED, $r->chain?->status);
        self::assertSame(VerificationResult::IDENTITY_MATCH, $r->identity);
        self::assertSame(VerificationResult::TIME_VALID, $r->certTime);
        self::assertTrue($r->purposeOk);
        self::assertSame(RevocationResult::NOT_CHECKED, $r->revocation->status);
        self::assertSame('disabled', $r->revocation->reason);
        self::assertFalse($r->weakDigest);
        self::assertFalse($r->forbiddenDigest);
        self::assertFalse($r->smallKey);
        self::assertFalse($r->legacyEmail);
        self::assertSame(VerificationResult::LEVEL_OK, $r->level());
        self::assertSame('status_sig_ok', $r->headline());
        self::assertLine($r, 'sig_cryptovalid', VerificationResult::LEVEL_OK, []);
        self::assertLine($r, 'chain_trusted', VerificationResult::LEVEL_OK, ['issuer' => 'MIME Shield Test Intermediate CA']);
        self::assertLine($r, 'identity_match', VerificationResult::LEVEL_OK, ['email' => 'alice@example.test']);
        self::assertLine($r, 'revocation_notchecked', VerificationResult::LEVEL_WARNING);
    }

    public function testEcSignerIsOk(): void
    {
        $r = $this->verifier()->evaluate($this->signedByService('carol'), ['carol@example.test'], []);
        self::assertSame(VerificationResult::LEVEL_OK, $r->level());
        self::assertSame('status_sig_ok', $r->headline());
    }

    public function testSignOnlyCertificateHasValidPurpose(): void
    {
        $r = $this->verifier()->evaluate($this->signedByCli('signonly'), ['signonly@example.test'], []);
        self::assertTrue($r->purposeOk);
        self::assertSame(VerificationResult::LEVEL_OK, $r->level());
    }

    public function testMissingIntermediateGivesUntrustedWarning(): void
    {
        $r = $this->verifier()->evaluate($this->signedByService('alice', false), ['alice@example.test'], []);
        self::assertTrue($r->cryptoValid());
        self::assertSame(ChainResult::INCOMPLETE, $r->chain?->status);
        self::assertSame(VerificationResult::LEVEL_WARNING, $r->level());
        self::assertSame('status_sig_untrusted', $r->headline());
        self::assertLine($r, 'chain_incomplete', VerificationResult::LEVEL_WARNING, ['issuer' => 'MIME Shield Test Intermediate CA']);
    }

    // --- identity ------------------------------------------------------------------------------

    public function testFromMismatchIsError(): void
    {
        $r = $this->verifier()->evaluate($this->signedByService('alice'), ['mallory@example.test'], []);
        self::assertTrue($r->cryptoValid());
        self::assertSame(ChainResult::TRUSTED, $r->chain?->status);
        self::assertSame(VerificationResult::IDENTITY_MISMATCH, $r->identity);
        self::assertSame(VerificationResult::LEVEL_ERROR, $r->level());
        self::assertSame('status_sig_mismatch', $r->headline());
        self::assertLine($r, 'identity_mismatch', VerificationResult::LEVEL_ERROR, ['email' => 'alice@example.test', 'from' => 'mallory@example.test']);
    }

    public function testEveryFromAddressMustMatch(): void
    {
        $r = $this->verifier()->evaluate($this->signedByService('alice'), ['alice@example.test', 'mallory@example.test'], []);
        self::assertSame(VerificationResult::IDENTITY_MISMATCH, $r->identity);
        self::assertSame(VerificationResult::LEVEL_ERROR, $r->level());
    }

    public function testSenderMatchWithForeignFromIsWarning(): void
    {
        $r = $this->verifier()->evaluate($this->signedByService('alice'), ['boss@example.test'], ['alice@example.test']);
        self::assertSame(VerificationResult::IDENTITY_SENDER, $r->identity);
        self::assertSame(VerificationResult::LEVEL_WARNING, $r->level());
        self::assertSame('status_sig_warning', $r->headline());
        self::assertLine($r, 'identity_senderonly', VerificationResult::LEVEL_WARNING, ['email' => 'alice@example.test']);
    }

    public function testSenderThatDoesNotMatchEitherIsMismatch(): void
    {
        $r = $this->verifier()->evaluate($this->signedByService('alice'), ['boss@example.test'], ['mallory@example.test']);
        self::assertSame(VerificationResult::IDENTITY_MISMATCH, $r->identity);
        self::assertSame(VerificationResult::LEVEL_ERROR, $r->level());
    }

    public function testNoFromIsWarning(): void
    {
        $r = $this->verifier()->evaluate($this->signedByService('alice'), [], ['alice@example.test']);
        self::assertSame(VerificationResult::IDENTITY_NOFROM, $r->identity);
        self::assertSame(VerificationResult::LEVEL_WARNING, $r->level());
        self::assertLine($r, 'identity_nofrom', VerificationResult::LEVEL_WARNING, []);
    }

    public function testWrongMailCertificateIsMismatch(): void
    {
        $r = $this->verifier()->evaluate($this->signedByCli('wrongmail'), ['alice@example.test'], []);
        self::assertSame(VerificationResult::IDENTITY_MISMATCH, $r->identity);
        self::assertSame(VerificationResult::LEVEL_ERROR, $r->level());
        self::assertSame('status_sig_mismatch', $r->headline());
        self::assertLine($r, 'identity_mismatch', VerificationResult::LEVEL_ERROR, ['email' => 'someone-else@example.test', 'from' => 'alice@example.test']);
    }

    public function testInjectedSanIsNeverMatched(): void
    {
        $check = $this->signedByCli('evil');
        foreach (['victim@example.test', 'attacker@evil.test'] as $from) {
            $r = $this->verifier()->evaluate($check, [$from], []);
            self::assertSame(VerificationResult::IDENTITY_NOEMAIL, $r->identity, $from);
            self::assertNotSame(VerificationResult::LEVEL_OK, $r->level(), $from);
        }
    }

    public function testLegacySubjectEmailMatchesWithFlag(): void
    {
        $r = $this->verifier()->evaluate($this->signedByCli('legacyemail'), ['legacy@example.test'], []);
        self::assertSame(VerificationResult::IDENTITY_MATCH, $r->identity);
        self::assertTrue($r->legacyEmail);
        self::assertSame(VerificationResult::LEVEL_OK, $r->level());
        self::assertLine($r, 'identity_match', VerificationResult::LEVEL_OK, ['email' => 'legacy@example.test']);
        self::assertLine($r, 'identity_legacyemail', VerificationResult::LEVEL_WARNING, []);
    }

    public function testLegacySubjectEmailIgnoredWhenFallbackDisabled(): void
    {
        $r = $this->verifier(null, false)->evaluate($this->signedByCli('legacyemail'), ['legacy@example.test'], []);
        self::assertSame(VerificationResult::IDENTITY_NOEMAIL, $r->identity);
        self::assertFalse($r->legacyEmail);
        self::assertSame(VerificationResult::LEVEL_WARNING, $r->level());
        self::assertSame('status_sig_warning', $r->headline());
        self::assertLine($r, 'identity_noemail', VerificationResult::LEVEL_WARNING, []);
        self::assertNoLine($r, 'identity_legacyemail');
    }

    // --- time / chain / purpose ----------------------------------------------------------------

    public function testExpiredSigner(): void
    {
        $r = $this->verifier()->evaluate($this->signedByCli('expired'), ['expired@example.test'], []);
        self::assertTrue($r->cryptoValid());
        self::assertSame(VerificationResult::TIME_EXPIRED, $r->certTime);
        self::assertSame(ChainResult::EXPIRED, $r->chain?->status);
        self::assertSame(VerificationResult::LEVEL_WARNING, $r->level());
        self::assertSame('status_sig_expired', $r->headline());
        self::assertLine($r, 'chain_expiredpath', VerificationResult::LEVEL_WARNING, []);
        // signingTime (= now, set by the CLI) is after notAfter: plain "expired"
        self::assertLine($r, 'cert_expired', VerificationResult::LEVEL_WARNING, ['date' => '2021-01-01']);
        self::assertNoLine($r, 'cert_expired_signedwhilevalid');
    }

    public function testNotYetValidSigner(): void
    {
        $r = $this->verifier()->evaluate($this->signedByCli('notyet'), ['notyet@example.test'], []);
        self::assertSame(VerificationResult::TIME_NOTYET, $r->certTime);
        self::assertSame(ChainResult::NOT_YET_VALID, $r->chain?->status);
        self::assertSame(VerificationResult::LEVEL_WARNING, $r->level());
        self::assertSame('status_sig_notyet', $r->headline());
        self::assertLine($r, 'cert_notyetvalid', VerificationResult::LEVEL_WARNING, ['date' => '2035-01-01']);
        self::assertLine($r, 'chain_notyetpath', VerificationResult::LEVEL_WARNING, []);
    }

    public function testValidSignatureFromRogueCaIsNotOk(): void
    {
        foreach ([['rogue.crt'], []] as $embedded) {
            $r = $this->verifier()->evaluate($this->signedByCli('untrusted', $embedded), ['alice@example.test'], []);
            self::assertTrue($r->cryptoValid());
            self::assertSame(VerificationResult::IDENTITY_MATCH, $r->identity);
            self::assertSame($embedded === [] ? ChainResult::INCOMPLETE : ChainResult::UNTRUSTED_ROOT, $r->chain?->status);
            self::assertSame(VerificationResult::LEVEL_WARNING, $r->level());
            self::assertSame('status_sig_untrusted', $r->headline());
        }
        $r = $this->verifier()->evaluate($this->signedByCli('untrusted', ['rogue.crt']), ['alice@example.test'], []);
        self::assertLine($r, 'chain_untrusted', VerificationResult::LEVEL_WARNING, ['issuer' => 'Rogue Test CA']);
    }

    public function testValidSelfSignedSignatureIsNotOk(): void
    {
        $r = $this->verifier()->evaluate($this->signedByCli('selfsigned', []), ['alice@example.test'], []);
        self::assertTrue($r->cryptoValid());
        self::assertSame(ChainResult::UNTRUSTED_ROOT, $r->chain?->status);
        self::assertSame(VerificationResult::LEVEL_WARNING, $r->level());
        self::assertSame('status_sig_untrusted', $r->headline());
    }

    public function testServerAuthSignerHasBadPurpose(): void
    {
        $r = $this->verifier()->evaluate($this->signedByCli('server'), ['server@example.test'], []);
        self::assertTrue($r->cryptoValid());
        self::assertFalse($r->purposeOk);
        self::assertSame(ChainResult::BAD_PURPOSE, $r->chain?->status);
        self::assertSame(VerificationResult::LEVEL_ERROR, $r->level());
        self::assertSame('status_sig_badcert', $r->headline());
        self::assertLine($r, 'cert_badpurpose', VerificationResult::LEVEL_ERROR, []);
        self::assertLine($r, 'chain_badpurpose', VerificationResult::LEVEL_WARNING, []);
    }

    public function testCaCertificateAsSignerHasBadPurpose(): void
    {
        $r = $this->verifier()->evaluate($this->signedByCli('int', []), [], []);
        self::assertTrue($r->cryptoValid());
        self::assertFalse($r->purposeOk);
        self::assertSame(VerificationResult::LEVEL_ERROR, $r->level());
        self::assertSame('status_sig_badcert', $r->headline());
    }

    public function testSmallRsaKeyIsWarning(): void
    {
        [$cert, $key] = $this->makeRsaCert(1024, 'small@example.test');
        $r = $this->verifier()->evaluate($this->signedByCli('', ['int.crt'], 'sha256', null, $cert, $key), ['small@example.test'], []);
        self::assertSame(ChainResult::TRUSTED, $r->chain?->status);
        self::assertTrue($r->smallKey);
        self::assertSame(VerificationResult::LEVEL_WARNING, $r->level());
        self::assertSame('status_sig_warning', $r->headline());
        self::assertLine($r, 'cert_smallkey', VerificationResult::LEVEL_WARNING, ['bits' => '1024']);
    }

    public function testPartialSignatureIsWarning(): void
    {
        $r = $this->verifier()->evaluate($this->signedByService('alice'), ['alice@example.test'], [], true);
        self::assertTrue($r->partial);
        self::assertSame(VerificationResult::LEVEL_WARNING, $r->level());
        self::assertLine($r, 'sig_partial', VerificationResult::LEVEL_WARNING, []);
    }

    // --- algorithms / integrity ----------------------------------------------------------------

    public function testSha1SignatureIsWeak(): void
    {
        $r = $this->verifier()->evaluate($this->signedByCli('alice', ['int.crt'], 'sha1'), ['alice@example.test'], []);
        self::assertSame('sha1', $r->check->digest());
        self::assertTrue($r->weakDigest);
        self::assertFalse($r->forbiddenDigest);
        self::assertTrue($r->cryptoValid());
        self::assertSame(VerificationResult::LEVEL_WARNING, $r->level());
        self::assertSame('status_sig_warning', $r->headline());
        self::assertLine($r, 'sig_weakdigest', VerificationResult::LEVEL_WARNING, ['digest' => 'SHA1']);
    }

    public function testSha224SignatureIsWeakByDefaultPolicy(): void
    {
        $r = $this->verifier()->evaluate($this->signedByCli('alice', ['int.crt'], 'sha224'), ['alice@example.test'], []);
        self::assertTrue($r->weakDigest);
        self::assertSame(VerificationResult::LEVEL_WARNING, $r->level());
    }

    public function testSha512SignatureIsAccepted(): void
    {
        $r = $this->verifier()->evaluate($this->signedByCli('alice', ['int.crt'], 'sha512'), ['alice@example.test'], []);
        self::assertFalse($r->weakDigest);
        self::assertSame(VerificationResult::LEVEL_OK, $r->level());
    }

    public function testMd5SignatureIsForbidden(): void
    {
        $check = $this->signedByCli('alice', ['int.crt'], 'md5');
        // OpenSSL itself accepts the MD5 signature: the policy must reject it
        self::assertTrue($check->valid);
        self::assertSame('md5', $check->digest());
        $r = $this->verifier()->evaluate($check, ['alice@example.test'], []);
        self::assertTrue($r->forbiddenDigest);
        self::assertFalse($r->cryptoValid());
        self::assertSame(VerificationResult::LEVEL_ERROR, $r->level());
        self::assertSame('status_sig_invalid', $r->headline());
        self::assertLine($r, 'sig_forbiddendigest', VerificationResult::LEVEL_ERROR, ['digest' => 'md5']);
        self::assertNoLine($r, 'sig_cryptovalid');
    }

    public function testSha1IsForbiddenWhenNotInLegacyList(): void
    {
        $store = $this->store();
        $v = new SignatureVerifier(new ChainValidator($store, $this->tmp), $store, $this->revocationOff(), ['sha256'], []);
        $r = $v->evaluate($this->signedByCli('alice', ['int.crt'], 'sha1'), ['alice@example.test'], []);
        self::assertTrue($r->forbiddenDigest);
        self::assertSame(VerificationResult::LEVEL_ERROR, $r->level());
    }

    /**
     * Audit MS-08: when the local parser cannot inspect the structure, the digest policy cannot be
     * applied - the signature is not rejected, but never shown as fully OK either.
     */
    public function testUninspectableStructureIsNeverFullyOk(): void
    {
        $check = new SignatureCheck(true, SignatureCheck::FAIL_NONE, [TestPki::read('alice.crt')], [TestPki::read('int.crt')], null, null, false);
        $r = $this->verifier()->evaluate($check, ['alice@example.test'], []);
        self::assertFalse($r->forbiddenDigest);
        self::assertTrue($r->weakDigest);
        self::assertTrue($r->cryptoValid());
        self::assertSame(VerificationResult::LEVEL_WARNING, $r->level());
        self::assertLine($r, 'sig_digestunverified', VerificationResult::LEVEL_WARNING, []);
        self::assertNoLine($r, 'sig_weakdigest');
    }

    public function testModifiedContentIsInvalid(): void
    {
        $check = $this->signedByCli('alice', ['int.crt'], 'sha256', str_replace('Hello', 'Hellp', self::CONTENT));
        self::assertFalse($check->valid);
        self::assertSame(SignatureCheck::FAIL_MODIFIED, $check->failure);
        $r = $this->verifier()->evaluate($check, ['alice@example.test'], []);
        self::assertFalse($r->cryptoValid());
        self::assertSame(VerificationResult::LEVEL_ERROR, $r->level());
        self::assertSame('status_sig_invalid', $r->headline());
        self::assertSame(['sig_modified', [], VerificationResult::LEVEL_ERROR], $r->lines()[0]);
        self::assertNoLine($r, 'sig_cryptovalid');
    }

    public function testCanonicalisedLineEndingsStillOk(): void
    {
        // signed in text mode (CRLF canonical form), received with bare LF
        $lf = str_replace("\r\n", "\n", self::CONTENT);
        $in = $this->tmp . '/lf.txt';
        $out = $this->tmp . '/lf.der';
        file_put_contents($in, $lf);
        self::sh(['/usr/bin/openssl', 'cms', '-sign', '-md', 'sha256', '-in', $in, '-signer', TestPki::path('alice.crt'),
            '-inkey', TestPki::path('alice.key'), '-certfile', TestPki::path('int.crt'), '-outform', 'DER', '-out', $out]);
        $check = $this->cms()->verifyDetached($lf, (string) file_get_contents($out));
        self::assertTrue($check->valid);
        self::assertTrue($check->canonicalized);
        $r = $this->verifier()->evaluate($check, ['alice@example.test'], []);
        self::assertSame(VerificationResult::LEVEL_OK, $r->level());
        self::assertLine($r, 'sig_canonicalized', VerificationResult::LEVEL_OK, []);
    }

    public function testNoSignerCertificateIsError(): void
    {
        $info = ['detached' => true, 'digests' => ['sha256'], 'signers' => [['digest' => 'sha256', 'signature' => 'rsaEncryption', 'signingTime' => null, 'sid' => []]], 'certificates' => 0];
        $check = new SignatureCheck(false, SignatureCheck::FAIL_NO_SIGNER, [], [], $info, null, false);
        $r = $this->verifier()->evaluate($check, ['alice@example.test'], []);
        self::assertNull($r->signer);
        self::assertNull($r->chain);
        self::assertSame(VerificationResult::LEVEL_ERROR, $r->level());
        self::assertSame('status_sig_invalid', $r->headline());
        self::assertSame([['sig_nosigner', [], VerificationResult::LEVEL_ERROR]], $r->lines());
    }

    public function testUnparsableSignerPemIsTreatedAsNoSigner(): void
    {
        $check = new SignatureCheck(true, SignatureCheck::FAIL_NONE, ["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"], [], null, null, false);
        $r = $this->verifier()->evaluate($check, ['alice@example.test'], []);
        self::assertNull($r->signer);
        self::assertSame(VerificationResult::LEVEL_ERROR, $r->level());
        self::assertSame('status_sig_badcert', $r->headline());
    }

    // --- revocation ----------------------------------------------------------------------------

    public function testRevokedSignerFromCachedCrlIsError(): void
    {
        $r = $this->verifier($this->revocationCrl(true))->evaluate($this->signedByCli('revoked'), ['revoked@example.test'], []);
        self::assertSame(ChainResult::TRUSTED, $r->chain?->status);
        self::assertSame(RevocationResult::REVOKED, $r->revocation->status);
        self::assertSame('keyCompromise', $r->revocation->reason);
        self::assertSame(VerificationResult::LEVEL_ERROR, $r->level());
        self::assertSame('status_sig_revoked', $r->headline());
        self::assertNotNull($r->revocation->revokedAt);
        self::assertLessThanOrEqual(time(), $r->revocation->revokedAt);
        self::assertGreaterThan(TestPki::cert('revoked')->notBefore - 86400, $r->revocation->revokedAt);
        $date = gmdate('Y-m-d', $r->revocation->revokedAt);
        self::assertLine($r, 'revocation_revoked', VerificationResult::LEVEL_ERROR, ['date' => $date, 'reason' => 'keyCompromise']);
        self::assertSame([], $this->resolved, 'cached CRL must not trigger a fetch');
    }

    /**
     * The signer is not on its CRL, but the TEST intermediate has no CRL distribution point: with
     * checking enabled the path status is undetermined (audit F-04/F-06), never a full OK. A path
     * that is GOOD at every level is covered by RevocationPathTest.
     */
    public function testGoodSignerWithUncheckableIntermediateIsUnknown(): void
    {
        $r = $this->verifier($this->revocationCrl(true))->evaluate($this->signedByService('alice'), ['alice@example.test'], []);
        self::assertSame(RevocationResult::UNKNOWN, $r->revocation->status);
        self::assertSame('nocrldp', $r->revocation->reason);
        self::assertSame(VerificationResult::LEVEL_WARNING, $r->level());
        self::assertLine($r, 'revocation_unknown', VerificationResult::LEVEL_WARNING, []);
        self::assertSame([], $this->resolved, 'the leaf CRL came from the cache');
    }

    public function testExpiredChainIsStillCheckedForRevocation(): void
    {
        $r = $this->verifier($this->revocationCrl(true))->evaluate($this->signedByCli('expired'), ['expired@example.test'], []);
        self::assertSame(ChainResult::EXPIRED, $r->chain?->status);
        self::assertSame(RevocationResult::UNKNOWN, $r->revocation->status);
        self::assertSame('nocrldp', $r->revocation->reason, 'leaf GOOD on the cached CRL, intermediate without CRL DP');
        self::assertSame(VerificationResult::LEVEL_WARNING, $r->level());
    }

    public function testUntrustedChainNeverTriggersRevocationFetch(): void
    {
        $r = $this->verifier($this->revocationCrl(false))->evaluate($this->signedByCli('untrusted', ['rogue.crt']), ['alice@example.test'], []);
        self::assertSame(RevocationResult::NOT_CHECKED, $r->revocation->status);
        self::assertSame('untrusted', $r->revocation->reason);
        self::assertSame([], $this->resolved, 'attacker supplied certificate must not cause network access');
        self::assertFalse(is_dir($this->tmp . '/cache/crl'));
    }

    public function testUnreachableCrlIsUnknownWarning(): void
    {
        $r = $this->verifier($this->revocationCrl(false))->evaluate($this->signedByService('alice'), ['alice@example.test'], []);
        self::assertSame(['crl.example.test'], $this->resolved);
        self::assertSame(RevocationResult::UNKNOWN, $r->revocation->status);
        self::assertSame(VerificationResult::LEVEL_WARNING, $r->level());
        self::assertSame('status_sig_warning', $r->headline());
        self::assertLine($r, 'revocation_unknown', VerificationResult::LEVEL_WARNING, []);
    }

    // --- helpers -------------------------------------------------------------------------------

    /**
     * @return array{0: string, 1: string} certificate and key file
     */
    private function makeRsaCert(int $bits, string $email): array
    {
        $d = $this->tmp . '/rsa-' . bin2hex(random_bytes(4));
        mkdir($d, 0700);
        file_put_contents($d . '/ext.cnf', "[e]\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature, keyEncipherment\n"
            . "extendedKeyUsage = emailProtection\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid:always\nsubjectAltName = email:" . $email . "\n");
        self::sh(['/usr/bin/openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:' . $bits, '-out', $d . '/k.pem']);
        self::sh(['/usr/bin/openssl', 'req', '-new', '-key', $d . '/k.pem', '-subj', '/CN=small (TEST ONLY)', '-out', $d . '/r.csr']);
        self::sh(['/usr/bin/openssl', 'x509', '-req', '-in', $d . '/r.csr', '-CA', TestPki::path('int.crt'), '-CAkey', TestPki::path('int.key'),
            '-set_serial', '0x' . bin2hex(random_bytes(8)), '-days', '30', '-extfile', $d . '/ext.cnf', '-extensions', 'e', '-out', $d . '/c.pem']);
        return [$d . '/c.pem', $d . '/k.pem'];
    }

    /**
     * @param list<string> $cmd
     */
    private static function sh(array $cmd): void
    {
        exec(implode(' ', array_map('escapeshellarg', $cmd)) . ' 2>&1', $out, $rc);
        if ($rc !== 0) {
            self::fail('command failed: ' . implode(' ', $cmd) . "\n" . implode("\n", $out));
        }
    }

    private static function rmTree(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) {
            $f->isDir() && !$f->isLink() ? rmdir($f->getPathname()) : unlink($f->getPathname());
        }
        rmdir($dir);
    }
}
