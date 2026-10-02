<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Cert\Certificate;
use MimeShield\Exception\ValidationException;
use MimeShield\Tests\TestPki;
use MimeShield\Trust\RevocationChecker;
use MimeShield\Trust\RevocationResult;
use MimeShield\Trust\SafeHttpClient;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * CRL evaluation (signature, issuer, validity window, extensions) and the cached check() flow.
 *
 * CRLs are taken from the fixtures, generated at runtime with "openssl ca -gencrl" (delta, IDP,
 * unknown critical extension, short-lived, huge, CA without cRLSign, EC CA), or crafted in PHP and
 * signed with the TEST-ONLY intermediate key for precise control over single fields.
 */
final class RevocationCheckerTest extends TestCase
{
    private const URL = 'http://crl.example.test/int.crl';

    private const OID_SHA256_RSA = '1.2.840.113549.1.1.11';

    private static string $work = '';

    /** @var array<string, string> generated CRLs (DER) */
    private static array $gen = [];

    /** @var array<string, Certificate> generated CA certificates */
    private static array $genCa = [];

    /** @var resource|null */
    private static $server = null;

    private static int $port = 0;

    /** @var list<string> */
    private array $temp = [];

    public static function setUpBeforeClass(): void
    {
        self::$work = TestPki::tempDir();
    }

    public static function tearDownAfterClass(): void
    {
        if (is_resource(self::$server)) {
            proc_terminate(self::$server);
            proc_close(self::$server);
        }
        self::$server = null;
        if (self::$work !== '') {
            self::rmTree(self::$work);
        }
        self::$work = '';
        self::$gen = [];
        self::$genCa = [];
    }

    protected function setUp(): void
    {
        $GLOBALS['mimeshield_test_log'] = [];
    }

    protected function tearDown(): void
    {
        foreach ($this->temp as $d) {
            if (is_dir($d)) {
                self::rmTree($d);
            }
        }
        $this->temp = [];
    }

    // ================================================================== evaluate(): fixtures

    public function testFixtureCrlReportsRevokedCertificateWithReasonAndDate(): void
    {
        $revoked = TestPki::cert('revoked');
        $now = time();
        $r = self::checker()->evaluate(TestPki::read('int.crl'), $revoked, TestPki::cert('int'), $now);
        self::assertSame(RevocationResult::REVOKED, $r->status);
        self::assertSame('keyCompromise', $r->reason);
        self::assertIsInt($r->revokedAt);
        // revocation date is close to the issuance of the fixture (both made by generate.sh)
        self::assertLessThan(86400 * 2, abs($r->revokedAt - $revoked->notBefore - 86400));
        self::assertLessThanOrEqual($now, $r->revokedAt);
    }

    public function testFixtureCrlReportsGoodForUnlistedCertificate(): void
    {
        $now = time();
        foreach (['alice', 'bob', 'carol', 'alice2'] as $name) {
            $r = self::checker()->evaluate(TestPki::read('int.crl'), TestPki::cert($name), TestPki::cert('int'), $now);
            self::assertSame(RevocationResult::GOOD, $r->status, $name);
            self::assertSame('', $r->reason);
            self::assertNull($r->revokedAt);
            self::assertIsInt($r->nextUpdate);
            self::assertGreaterThan($now, $r->nextUpdate);
        }
    }

    public function testEmptyRootCrlIsGoodForIntermediate(): void
    {
        $r = self::checker()->evaluate(TestPki::read('root.crl'), TestPki::cert('int'), TestPki::cert('root'), time());
        self::assertSame(RevocationResult::GOOD, $r->status);
    }

    public function testRootCrlAgainstAliceWithIntermediateIssuerIsRejected(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('CRL signature invalid');
        self::checker()->evaluate(TestPki::read('root.crl'), TestPki::cert('alice'), TestPki::cert('int'), time());
    }

    public function testCrlFromUnrelatedCaIsRejected(): void
    {
        // int.crl checked with the rogue CA as issuer
        $this->expectException(ValidationException::class);
        self::checker()->evaluate(TestPki::read('int.crl'), TestPki::cert('untrusted'), TestPki::cert('rogue'), time());
    }

    public function testIssuerNameMismatchIsRejectedEvenWithValidSignature(): void
    {
        // signed with the intermediate key, but claims to be issued by the root
        $crl = self::craft(['issuer' => TestPki::cert('root')->subjectNameDer]);
        $this->expectExceptionMessage('CRL issuer mismatch');
        self::checker()->evaluate($crl, TestPki::cert('alice'), TestPki::cert('int'), time());
    }

    public function testCrlSignedByWrongKeyIsRejected(): void
    {
        $crl = self::craft(['key' => TestPki::key('mallory')]);
        $this->expectExceptionMessage('CRL signature invalid');
        self::checker()->evaluate($crl, TestPki::cert('alice'), TestPki::cert('int'), time());
    }

    public function testTamperedSignatureIsRejected(): void
    {
        $der = TestPki::read('int.crl');
        $der[strlen($der) - 1] = chr(ord($der[strlen($der) - 1]) ^ 0x01);
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('CRL signature invalid');
        self::checker()->evaluate($der, TestPki::cert('alice'), TestPki::cert('int'), time());
    }

    public function testTamperedRevokedSerialInTbsIsRejected(): void
    {
        // flip the last byte of the revoked serial: an attacker "un-revoking" the certificate
        $der = TestPki::read('int.crl');
        $serialBin = (string) hex2bin(TestPki::cert('revoked')->serialHex);
        $pos = strpos($der, $serialBin);
        self::assertIsInt($pos, 'revoked serial present in fixture CRL');
        $pos += strlen($serialBin) - 1;
        $der[$pos] = chr(ord($der[$pos]) ^ 0x01);
        try {
            self::checker()->evaluate($der, TestPki::cert('revoked'), TestPki::cert('int'), time());
            self::fail('tampered CRL accepted');
        } catch (ValidationException $e) {
            self::assertSame('CRL signature invalid', $e->getMessage());
        }
    }

    public function testTamperedNextUpdateInTbsIsRejected(): void
    {
        // change one digit of a time value inside tbsCertList (UTCTime "YYMMDD...Z")
        $der = TestPki::read('int.crl');
        self::assertSame(1, preg_match('/\x17\x0d(\d{12})Z/', $der, $m, PREG_OFFSET_CAPTURE));
        $pos = $m[1][1]; // first year digit
        $der[$pos] = $der[$pos] === '9' ? '8' : chr(ord($der[$pos]) + 1);
        $this->expectExceptionMessage('CRL signature invalid');
        self::checker()->evaluate($der, TestPki::cert('alice'), TestPki::cert('int'), time());
    }

    public function testPemCrlIsNotAcceptedByEvaluate(): void
    {
        // evaluate() takes DER; PEM is decoded by the fetch path (see testCheckFetchesPemCrlViaProxyAndCachesDer)
        $this->expectException(ValidationException::class);
        self::checker()->evaluate(TestPki::read('int.crl.pem'), TestPki::cert('alice'), TestPki::cert('int'), time());
    }

    public function testPemFixtureMatchesDerFixture(): void
    {
        $pem = TestPki::read('int.crl.pem');
        self::assertSame(1, preg_match('/-----BEGIN X509 CRL-----(.+)-----END X509 CRL-----/s', $pem, $m));
        $der = base64_decode((string) preg_replace('/\s+/', '', $m[1]), true);
        self::assertSame(TestPki::read('int.crl'), $der);
        $r = self::checker()->evaluate((string) $der, TestPki::cert('revoked'), TestPki::cert('int'), time());
        self::assertSame(RevocationResult::REVOKED, $r->status);
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function malformedInputs(): iterable
    {
        yield 'empty' => [''];
        yield 'garbage' => ['not a crl'];
        yield 'truncated' => [substr((string) file_get_contents(TestPki::dir() . '/int.crl'), 0, 200)];
        yield 'trailing data' => [file_get_contents(TestPki::dir() . '/int.crl') . "\x00"];
        yield 'certificate instead of CRL' => [(string) file_get_contents(TestPki::dir() . '/bob.der')];
        yield 'empty sequence' => ["\x30\x00"];
    }

    #[DataProvider('malformedInputs')]
    public function testMalformedCrlThrowsValidationException(string $der): void
    {
        $this->expectException(ValidationException::class);
        self::checker()->evaluate($der, TestPki::cert('alice'), TestPki::cert('int'), time());
    }

    public function testMaximumCrlSizeIsEnforced(): void
    {
        $der = TestPki::read('int.crl');
        $c = new RevocationChecker(RevocationChecker::MODE_CRL, null, '', strlen($der) - 1);
        $this->expectExceptionMessage('CRL size out of range');
        $c->evaluate($der, TestPki::cert('alice'), TestPki::cert('int'), time());
    }

    // ================================================================== evaluate(): validity window

    public function testFixtureCrlNotYetValidWhenNowIsInThePast(): void
    {
        $this->expectExceptionMessage('CRL not yet valid');
        self::checker()->evaluate(TestPki::read('int.crl'), TestPki::cert('alice'), TestPki::cert('int'), 1600000000);
    }

    public function testFixtureCrlExpiredWhenNowIsFarInTheFuture(): void
    {
        $this->expectExceptionMessage('CRL expired');
        self::checker()->evaluate(TestPki::read('int.crl'), TestPki::cert('revoked'), TestPki::cert('int'), 2300000000);
    }

    /**
     * @return iterable<string, array{0: int, 1: ?string}>
     */
    public static function windowCases(): iterable
    {
        $t = 2000000000;
        $next = $t + 86400;
        yield 'inside' => [$t + 3600, null];
        yield 'at thisUpdate' => [$t, null];
        yield 'skew tolerated before thisUpdate' => [$t - 300, null];
        yield 'beyond skew before thisUpdate' => [$t - 301, 'CRL not yet valid'];
        yield 'at nextUpdate' => [$next, null];
        yield 'skew tolerated after nextUpdate' => [$next + 300, null];
        yield 'beyond skew after nextUpdate' => [$next + 301, 'CRL expired'];
        yield 'long after nextUpdate' => [$next + 86400 * 30, 'CRL expired'];
    }

    #[DataProvider('windowCases')]
    public function testValidityWindowWithClockSkew(int $now, ?string $error): void
    {
        $crl = self::craft(['thisUpdate' => 2000000000, 'nextUpdate' => 2000086400]);
        if ($error !== null) {
            $this->expectExceptionMessage($error);
        }
        $r = self::checker()->evaluate($crl, TestPki::cert('alice'), TestPki::cert('int'), $now);
        self::assertSame(RevocationResult::GOOD, $r->status);
        self::assertSame(2000086400, $r->nextUpdate);
    }

    public function testCrlWithoutNextUpdateIsTreatedAsExpired(): void
    {
        $crl = self::craft(['nextUpdate' => null]);
        $this->expectExceptionMessage('CRL expired');
        self::checker()->evaluate($crl, TestPki::cert('alice'), TestPki::cert('int'), time());
    }

    public function testGeneralizedTimeIsSupported(): void
    {
        // RFC 5280: dates from 2050 on use GeneralizedTime
        $t1 = 2600000000; // 2052
        $crl = self::craft([
            'thisUpdate' => $t1,
            'nextUpdate' => $t1 + 86400,
            'entries' => [[TestPki::cert('revoked')->serialHex, $t1 - 10, []]],
        ]);
        $r = self::checker()->evaluate($crl, TestPki::cert('revoked'), TestPki::cert('int'), $t1 + 10);
        self::assertSame(RevocationResult::REVOKED, $r->status);
        self::assertSame($t1 - 10, $r->revokedAt);
        self::assertSame('unspecified', $r->reason);
    }

    public function testShortLivedCrlFromOpensslExpires(): void
    {
        $der = self::opensslCrl('short', [], '-crlsec', '1');
        $now = time();
        $r = self::checker()->evaluate($der, TestPki::cert('alice'), TestPki::cert('int'), $now);
        self::assertSame(RevocationResult::GOOD, $r->status);
        self::assertLessThanOrEqual($now + 2, $r->nextUpdate);
        $this->expectExceptionMessage('CRL expired');
        self::checker()->evaluate($der, TestPki::cert('alice'), TestPki::cert('int'), $now + 600);
    }

    // ================================================================== evaluate(): entries

    /**
     * @return iterable<string, array{0: int, 1: string}>
     */
    public static function reasonCodes(): iterable
    {
        yield 'unspecified' => [0, 'unspecified'];
        yield 'keyCompromise' => [1, 'keyCompromise'];
        yield 'cACompromise' => [2, 'cACompromise'];
        yield 'affiliationChanged' => [3, 'affiliationChanged'];
        yield 'superseded' => [4, 'superseded'];
        yield 'cessationOfOperation' => [5, 'cessationOfOperation'];
        yield 'certificateHold' => [6, 'certificateHold'];
        yield 'privilegeWithdrawn' => [9, 'privilegeWithdrawn'];
        yield 'aACompromise' => [10, 'aACompromise'];
    }

    #[DataProvider('reasonCodes')]
    public function testReasonCodes(int $code, string $name): void
    {
        $serial = TestPki::cert('bob')->serialHex;
        $crl = self::craft(['entries' => [
            [TestPki::cert('alice')->serialHex, 1700000000, [self::ext('2.5.29.21', self::tlv(0x0A, chr(4)))]],
            [$serial, 1700000100, [self::ext('2.5.29.21', self::tlv(0x0A, chr($code)))]],
        ]]);
        $r = self::checker()->evaluate($crl, TestPki::cert('bob'), TestPki::cert('int'), time());
        self::assertSame(RevocationResult::REVOKED, $r->status);
        self::assertSame($name, $r->reason);
        self::assertSame(1700000100, $r->revokedAt);
    }

    public function testSerialMatchingIsExact(): void
    {
        $serial = TestPki::cert('alice')->serialHex;
        // a serial that differs only in the last byte, and one that is a prefix
        $near = substr($serial, 0, -2) . sprintf('%02X', (hexdec(substr($serial, -2)) + 1) % 256);
        $crl = self::craft(['entries' => [[$near, 1700000000, []], [substr($serial, 0, -2), 1700000000, []]]]);
        $r = self::checker()->evaluate($crl, TestPki::cert('alice'), TestPki::cert('int'), time());
        self::assertSame(RevocationResult::GOOD, $r->status);
    }

    public function testNonCriticalInvalidityDateAndUnknownNonCriticalEntryExtensionsAreAccepted(): void
    {
        $serial = TestPki::cert('alice')->serialHex;
        $crl = self::craft(['entries' => [[$serial, 1700000000, [
            self::ext('2.5.29.24', self::tlv(0x18, '20231101000000Z'), true), // critical invalidityDate is understood
            self::ext('1.3.6.1.4.1.99999.7', "\x05\x00"),
            self::ext('2.5.29.21', self::tlv(0x0A, "\x05")),
        ]]]]);
        $r = self::checker()->evaluate($crl, TestPki::cert('alice'), TestPki::cert('int'), time());
        self::assertSame(RevocationResult::REVOKED, $r->status);
        self::assertSame('cessationOfOperation', $r->reason);
    }

    public function testUnknownCriticalEntryExtensionIsRejected(): void
    {
        $crl = self::craft(['entries' => [[TestPki::cert('bob')->serialHex, 1700000000, [self::ext('1.3.6.1.4.1.99999.7', "\x05\x00", true)]]]]);
        $this->expectExceptionMessage('unknown critical CRL entry extension');
        // must fail even for a certificate that is NOT the listed one: the whole CRL is unusable
        self::checker()->evaluate($crl, TestPki::cert('alice'), TestPki::cert('int'), time());
    }

    public function testIndirectCrlEntryIsRejected(): void
    {
        $gn = self::tlv(0x30, self::tlv(0xA4, TestPki::cert('root')->subjectNameDer)); // GeneralNames { directoryName }
        $crl = self::craft(['entries' => [[TestPki::cert('bob')->serialHex, 1700000000, [self::ext('2.5.29.29', $gn, true)]]]]);
        $this->expectExceptionMessage('indirect CRL not supported');
        self::checker()->evaluate($crl, TestPki::cert('alice'), TestPki::cert('int'), time());
    }

    public function testVersion1CrlWithoutExtensionsIsAccepted(): void
    {
        $crl = self::craft(['version' => false, 'entries' => [[TestPki::cert('bob')->serialHex, 1700000000, []]]]);
        self::assertSame(RevocationResult::REVOKED, self::checker()->evaluate($crl, TestPki::cert('bob'), TestPki::cert('int'), time())->status);
        self::assertSame(RevocationResult::GOOD, self::checker()->evaluate($crl, TestPki::cert('alice'), TestPki::cert('int'), time())->status);
    }

    // ================================================================== evaluate(): signature algorithms / issuers

    /**
     * @return iterable<string, array{0: string, 1: int}>
     */
    public static function rsaAlgorithms(): iterable
    {
        yield 'sha256WithRSA' => ['1.2.840.113549.1.1.11', OPENSSL_ALGO_SHA256];
        yield 'sha384WithRSA' => ['1.2.840.113549.1.1.12', OPENSSL_ALGO_SHA384];
        yield 'sha512WithRSA' => ['1.2.840.113549.1.1.13', OPENSSL_ALGO_SHA512];
    }

    #[DataProvider('rsaAlgorithms')]
    public function testRsaSignatureAlgorithms(string $oid, int $algo): void
    {
        $crl = self::craft(['sigOid' => $oid, 'algo' => $algo]);
        self::assertSame(RevocationResult::GOOD, self::checker()->evaluate($crl, TestPki::cert('alice'), TestPki::cert('int'), time())->status);
    }

    public function testAlgorithmOidMustMatchTheDigestActuallyUsed(): void
    {
        // signed with SHA-256 but labelled SHA-512
        $crl = self::craft(['sigOid' => '1.2.840.113549.1.1.13', 'algo' => OPENSSL_ALGO_SHA256]);
        $this->expectExceptionMessage('CRL signature invalid');
        self::checker()->evaluate($crl, TestPki::cert('alice'), TestPki::cert('int'), time());
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function unsupportedAlgorithms(): iterable
    {
        yield 'md5WithRSA' => ['1.2.840.113549.1.1.4'];
        yield 'rsassa-pss' => ['1.2.840.113549.1.1.10'];
        yield 'ed25519' => ['1.3.101.112'];
        yield 'nonsense' => ['1.2.3.4'];
    }

    #[DataProvider('unsupportedAlgorithms')]
    public function testUnsupportedSignatureAlgorithmIsRejected(string $oid): void
    {
        $crl = self::craft(['sigOid' => $oid]);
        $this->expectExceptionMessage('unsupported CRL signature algorithm');
        self::checker()->evaluate($crl, TestPki::cert('alice'), TestPki::cert('int'), time());
    }

    public function testEcdsaCaCrlIsVerified(): void
    {
        [$ca, $der] = self::genCa('ec_crl', 'keyCertSign, cRLSign', [self::serialOf('revoked')]);
        self::assertSame('EC', $ca->keyType);
        $r = self::checker()->evaluate($der, TestPki::cert('revoked'), $ca, time());
        self::assertSame(RevocationResult::REVOKED, $r->status);
        self::assertSame('keyCompromise', $r->reason);
        self::assertSame(RevocationResult::GOOD, self::checker()->evaluate($der, TestPki::cert('alice'), $ca, time())->status);
    }

    public function testIssuerWithoutCrlSignKeyUsageIsRejected(): void
    {
        [$ca, $der] = self::genCa('no_crlsign', 'keyCertSign', [self::serialOf('revoked')]);
        self::assertFalse($ca->hasKeyUsage(Certificate::KU_CRL_SIGN));
        try {
            self::checker()->evaluate($der, TestPki::cert('alice'), $ca, time());
            self::fail('CRL from an issuer without cRLSign accepted');
        } catch (ValidationException $e) {
            self::assertSame('issuer may not sign CRLs', $e->getMessage());
        }
    }

    public function testIssuerWithoutKeyUsageExtensionMaySignCrls(): void
    {
        [$ca, $der] = self::genCa('no_ku', null, []);
        self::assertNull($ca->keyUsage);
        self::assertSame(RevocationResult::GOOD, self::checker()->evaluate($der, TestPki::cert('alice'), $ca, time())->status);
    }

    // ================================================================== evaluate(): CRL extensions

    public function testDeltaCrlFromOpensslIsRejected(): void
    {
        $der = self::opensslCrl('delta', ['2.5.29.27 = critical, DER:02:02:0F:FF']);
        try {
            self::checker()->evaluate($der, TestPki::cert('alice'), TestPki::cert('int'), time());
            self::fail('delta CRL accepted');
        } catch (ValidationException $e) {
            self::assertSame('delta CRL not supported', $e->getMessage());
        }
    }

    public function testNonCriticalDeltaIndicatorIsRejectedToo(): void
    {
        $crl = self::craft(['exts' => [self::ext('2.5.29.27', "\x02\x01\x05")]]);
        $this->expectExceptionMessage('delta CRL not supported');
        self::checker()->evaluate($crl, TestPki::cert('alice'), TestPki::cert('int'), time());
    }

    public function testUnknownCriticalCrlExtensionIsRejected(): void
    {
        $der = self::opensslCrl('unknown_critical', ['1.3.6.1.4.1.99999.1 = critical, DER:05:00']);
        $this->expectExceptionMessage('unknown critical CRL extension');
        self::checker()->evaluate($der, TestPki::cert('alice'), TestPki::cert('int'), time());
    }

    public function testKnownCriticalCrlNumberAndAkiAndUnknownNonCriticalAreAccepted(): void
    {
        $crl = self::craft(['exts' => [
            self::ext('2.5.29.20', "\x02\x02\x10\x00", true),
            self::ext('2.5.29.35', self::tlv(0x30, self::tlv(0x80, str_repeat("\x11", 20))), true),
            self::ext('1.3.6.1.4.1.99999.2', "\x05\x00"),
        ]]);
        self::assertSame(RevocationResult::GOOD, self::checker()->evaluate($crl, TestPki::cert('alice'), TestPki::cert('int'), time())->status);
    }

    /**
     * @return iterable<string, array{0: string, 1: ?string}>
     */
    public static function idpFlags(): iterable
    {
        yield 'onlyContainsUserCerts' => ["\x81\x01\xff", null];
        yield 'onlyContainsCACerts' => ["\x82\x01\xff", 'CA-only CRL'];
        yield 'indirectCRL' => ["\x84\x01\xff", 'indirect or attribute CRL not supported'];
        yield 'onlyContainsAttributeCerts' => ["\x85\x01\xff", 'indirect or attribute CRL not supported'];
    }

    #[DataProvider('idpFlags')]
    public function testIssuingDistributionPointFlags(string $field, ?string $error): void
    {
        $crl = self::craft(['exts' => [self::ext('2.5.29.28', self::tlv(0x30, $field), true)]]);
        if ($error !== null) {
            $this->expectExceptionMessage($error);
        }
        $r = self::checker()->evaluate($crl, TestPki::cert('alice'), TestPki::cert('int'), time());
        self::assertSame(RevocationResult::GOOD, $r->status);
    }

    public function testIdpMatchingTheCertificatesDistributionPointIsAccepted(): void
    {
        $der = self::opensslCrl('idp_same', ['issuingDistributionPoint = critical, @idp'], null, null, "[idp]\nfullname = URI:" . self::URL . "\n");
        self::assertSame(RevocationResult::GOOD, self::checker()->evaluate($der, TestPki::cert('alice'), TestPki::cert('int'), time())->status);
    }

    /**
     * A CRL partitioned by reason (IDP onlySomeReasons = keyCompromise) does not cover the other
     * reasons, so it can never prove that a certificate is "good" (RFC 5280 6.3.3: reasons mask
     * incomplete => status undetermined).
     */
    public function testReasonPartitionedCrlCannotProveGood(): void
    {
        $der = self::opensslCrl('idp_reasons', ['issuingDistributionPoint = critical, @idp'], null, null,
            "[idp]\nfullname = URI:" . self::URL . "\nonlysomereasons = keyCompromise\n");
        try {
            $r = self::checker()->evaluate($der, TestPki::cert('alice'), TestPki::cert('int'), time());
            self::assertNotSame(RevocationResult::GOOD, $r->status, 'partial (onlySomeReasons) CRL reported GOOD');
        } catch (ValidationException $e) {
            self::assertSame('revocationunavailable', $e->getUserLabel());
        }
    }

    /**
     * A CRL whose IDP distributionPoint names a different partition than the certificate's CRL
     * distribution point is out of scope for that certificate (RFC 5280 6.3.3 (b)(2)(i)); an attacker
     * on the (plain http) path could substitute such a CRL to hide a revocation.
     */
    public function testCrlForOtherDistributionPointCannotProveGood(): void
    {
        $der = self::opensslCrl('idp_other', ['issuingDistributionPoint = critical, @idp'], null, null,
            "[idp]\nfullname = URI:http://crl.example.test/other-partition.crl\n");
        try {
            $r = self::checker()->evaluate($der, TestPki::cert('alice'), TestPki::cert('int'), time());
            self::assertNotSame(RevocationResult::GOOD, $r->status, 'CRL of another distribution point reported GOOD');
        } catch (ValidationException $e) {
            self::assertSame('revocationunavailable', $e->getUserLabel());
        }
    }

    // ================================================================== evaluate(): large CRL

    public function testLargeCrlWith20000EntriesIsHandledQuickly(): void
    {
        $revokedSerial = self::serialOf('revoked');
        $lines = '';
        for ($i = 1; $i <= 20000; $i++) {
            $lines .= sprintf("R\t351231235959Z\t260101000000Z,superseded\t%06X\tunknown\t/CN=bulk%d\n", 0x100000 + $i, $i);
        }
        // the interesting entry comes last
        $lines .= sprintf("R\t351231235959Z\t260102000000Z,keyCompromise\t%s\tunknown\t/CN=revoked\n", $revokedSerial);
        $der = self::opensslCrl('large', [], null, null, '', $lines);
        self::assertGreaterThan(500000, strlen($der));

        if (function_exists('memory_reset_peak_usage')) {
            memory_reset_peak_usage();
        }
        $before = memory_get_usage();
        $t = microtime(true);
        $c = self::checker();
        $r = $c->evaluate($der, TestPki::cert('revoked'), TestPki::cert('int'), time());
        $good = $c->evaluate($der, TestPki::cert('alice'), TestPki::cert('int'), time());
        $elapsed = microtime(true) - $t;

        self::assertSame(RevocationResult::REVOKED, $r->status);
        self::assertSame('keyCompromise', $r->reason);
        self::assertSame(gmmktime(0, 0, 0, 1, 2, 2026), $r->revokedAt);
        self::assertSame(RevocationResult::GOOD, $good->status);
        self::assertLessThan(10.0, $elapsed, 'two evaluations of a 20000 entry CRL');
        self::assertLessThan(128 * 1024 * 1024, memory_get_peak_usage() - (function_exists('memory_reset_peak_usage') ? $before : 0));
    }

    // ================================================================== check()

    public function testCheckDisabledModes(): void
    {
        $http = self::failingHttp($calls);
        foreach ([
            new RevocationChecker(RevocationChecker::MODE_OFF, $http, ''),
            new RevocationChecker(RevocationChecker::MODE_CRL, null, ''),
            new RevocationChecker('ocsp', $http, ''),
        ] as $c) {
            self::assertFalse($c->isEnabled());
            $r = $c->check(TestPki::cert('revoked'), TestPki::cert('int'));
            self::assertSame(RevocationResult::NOT_CHECKED, $r->status);
            self::assertSame('disabled', $r->reason);
        }
        self::assertTrue((new RevocationChecker(RevocationChecker::MODE_CRL, $http, ''))->isEnabled());
        self::assertSame(0, $calls);
    }

    public function testCheckWithoutIssuerIsUnknown(): void
    {
        $c = new RevocationChecker(RevocationChecker::MODE_CRL, self::failingHttp($calls), '');
        $r = $c->check(TestPki::cert('alice'), null);
        self::assertSame(RevocationResult::UNKNOWN, $r->status);
        self::assertSame('noissuer', $r->reason);
        self::assertSame(0, $calls);
    }

    public function testCheckWithoutHttpDistributionPointIsNotChecked(): void
    {
        // carol has no CRL DP; the intermediate has none either
        $c = new RevocationChecker(RevocationChecker::MODE_CRL, self::failingHttp($calls), '');
        foreach (['carol', 'signonly', 'int'] as $name) {
            $cert = TestPki::cert($name);
            self::assertSame([], array_filter($cert->crlUrls, static fn ($u) => str_starts_with(strtolower($u), 'http')), $name);
            $r = $c->check($cert, TestPki::cert($name === 'int' ? 'root' : 'int'));
            self::assertSame(RevocationResult::NOT_CHECKED, $r->status);
            self::assertSame('nocrldp', $r->reason);
        }
        self::assertSame(0, $calls);
    }

    public function testCheckUsesCachedCrlWithoutNetwork(): void
    {
        $cache = $this->cacheWith(TestPki::read('int.crl'));
        $c = new RevocationChecker(RevocationChecker::MODE_CRL, self::failingHttp($calls), $cache);

        $r = $c->check(TestPki::cert('revoked'), TestPki::cert('int'), time());
        self::assertSame(RevocationResult::REVOKED, $r->status);
        self::assertSame('keyCompromise', $r->reason);
        self::assertIsInt($r->revokedAt);

        $g = $c->check(TestPki::cert('alice'), TestPki::cert('int'), time());
        self::assertSame(RevocationResult::GOOD, $g->status);
        self::assertGreaterThan(time(), $g->nextUpdate);
        self::assertSame(0, $calls, 'the network must not be used while a valid cached CRL exists');
    }

    public function testCheckKeepsCrlInMemoryForTheRequest(): void
    {
        $cache = $this->cacheWith(TestPki::read('int.crl'));
        $c = new RevocationChecker(RevocationChecker::MODE_CRL, self::failingHttp($calls), $cache);
        self::assertSame(RevocationResult::GOOD, $c->check(TestPki::cert('alice'), TestPki::cert('int'))->status);
        unlink(self::cacheFile($cache));
        self::assertSame(RevocationResult::REVOKED, $c->check(TestPki::cert('revoked'), TestPki::cert('int'))->status);
        self::assertSame(0, $calls);
    }

    public function testStaleCacheTriggersRefetchWhichIsSsrfChecked(): void
    {
        $cache = $this->cacheWith(TestPki::read('int.crl'), time() - 7200);
        $calls = 0;
        $http = new SafeHttpClient(resolver: static function (string $h) use (&$calls): array {
            $calls++;
            return ['10.0.0.1'];
        });
        $c = new RevocationChecker(RevocationChecker::MODE_CRL, $http, $cache, 10485760, 3600);
        $r = $c->check(TestPki::cert('revoked'), TestPki::cert('int'), time());
        self::assertSame(RevocationResult::UNKNOWN, $r->status, 'a stale cache entry must not be used');
        self::assertSame('revocationunavailable', $r->reason);
        self::assertSame(1, $calls);
        self::assertStringContainsString('CRL check failed: non-public address', implode("\n", $GLOBALS['mimeshield_test_log']));
    }

    public function testCacheEntryFromTheFutureIsNotTrusted(): void
    {
        $cache = $this->cacheWith(TestPki::read('int.crl'), time() + 3600);
        $c = new RevocationChecker(RevocationChecker::MODE_CRL, self::refusingHttp($calls), $cache);
        self::assertSame(RevocationResult::UNKNOWN, $c->check(TestPki::cert('revoked'), TestPki::cert('int'), time())->status);
        self::assertSame(1, $calls);
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function badCacheContents(): iterable
    {
        yield 'garbage' => ['garbage'];
        yield 'pem instead of der' => [(string) file_get_contents(TestPki::dir() . '/int.crl.pem')];
        yield 'crl of another issuer' => [(string) file_get_contents(TestPki::dir() . '/root.crl')];
        yield 'empty' => [''];
    }

    #[DataProvider('badCacheContents')]
    public function testInvalidCacheContentIsIgnoredAndRefetched(string $content): void
    {
        $cache = $this->cacheWith($content);
        $c = new RevocationChecker(RevocationChecker::MODE_CRL, self::refusingHttp($calls), $cache);
        $r = $c->check(TestPki::cert('alice'), TestPki::cert('int'), time());
        self::assertSame(RevocationResult::UNKNOWN, $r->status);
        self::assertSame(1, $calls);
    }

    public function testTamperedCachedCrlIsNotUsed(): void
    {
        $der = TestPki::read('int.crl');
        $der[strlen($der) - 1] = chr(ord($der[strlen($der) - 1]) ^ 0x80);
        $cache = $this->cacheWith($der);
        $c = new RevocationChecker(RevocationChecker::MODE_CRL, self::refusingHttp($calls), $cache);
        self::assertSame(RevocationResult::UNKNOWN, $c->check(TestPki::cert('revoked'), TestPki::cert('int'), time())->status);
        self::assertSame(1, $calls);
    }

    public function testCachedCrlPastNextUpdateIsRefetched(): void
    {
        $der = self::opensslCrl('short_cache', [], '-crlsec', '1');
        $cache = $this->cacheWith($der);
        $c = new RevocationChecker(RevocationChecker::MODE_CRL, self::refusingHttp($calls), $cache);
        $r = $c->check(TestPki::cert('alice'), TestPki::cert('int'), time() + 120);
        self::assertSame(RevocationResult::UNKNOWN, $r->status);
        self::assertSame(1, $calls);
    }

    public function testSymlinkedCacheFileIsIgnored(): void
    {
        $cache = TestPki::tempDir();
        $this->temp[] = $cache;
        mkdir($cache . '/crl', 0700);
        file_put_contents($cache . '/target.crl', TestPki::read('int.crl'));
        symlink($cache . '/target.crl', self::cacheFile($cache));
        $c = new RevocationChecker(RevocationChecker::MODE_CRL, self::refusingHttp($calls), $cache);
        self::assertSame(RevocationResult::UNKNOWN, $c->check(TestPki::cert('revoked'), TestPki::cert('int'), time())->status);
        self::assertSame(1, $calls);
    }

    public function testCacheDirectoryIsCreatedPrivately(): void
    {
        $cache = TestPki::tempDir();
        $this->temp[] = $cache;
        $c = new RevocationChecker(RevocationChecker::MODE_CRL, self::refusingHttp($calls), $cache);
        $c->check(TestPki::cert('alice'), TestPki::cert('int'), time());
        self::assertDirectoryExists($cache . '/crl');
        self::assertSame(0700, fileperms($cache . '/crl') & 0777);
        self::assertSame(['.', '..'], scandir($cache . '/crl'), 'nothing cached after a failed fetch');
    }

    public function testCheckFetchesPemCrlViaProxyAndCachesDer(): void
    {
        $cache = TestPki::tempDir();
        $this->temp[] = $cache;
        self::serve('pem');
        $c = new RevocationChecker(RevocationChecker::MODE_CRL, self::proxyHttp(), $cache);
        $r = $c->check(TestPki::cert('revoked'), TestPki::cert('int'), time());
        self::assertSame(RevocationResult::REVOKED, $r->status);
        self::assertSame('keyCompromise', $r->reason);
        self::assertSame([self::URL], self::requests());

        $file = self::cacheFile($cache);
        self::assertFileExists($file);
        self::assertSame(TestPki::read('int.crl'), file_get_contents($file), 'cache stores the decoded DER');
        self::assertSame(0600, fileperms($file) & 0777);

        // a fresh checker (next request) uses the cache and does not contact the server again
        $c2 = new RevocationChecker(RevocationChecker::MODE_CRL, self::failingHttp($calls), $cache);
        self::assertSame(RevocationResult::GOOD, $c2->check(TestPki::cert('alice'), TestPki::cert('int'), time())->status);
        self::assertSame(0, $calls);
        self::assertCount(1, self::requests());
    }

    public function testCheckFetchesDerCrlViaProxy(): void
    {
        self::serve('der');
        $c = new RevocationChecker(RevocationChecker::MODE_CRL, self::proxyHttp(), '');
        self::assertSame(RevocationResult::GOOD, $c->check(TestPki::cert('alice'), TestPki::cert('int'), time())->status);
        self::assertSame(RevocationResult::REVOKED, $c->check(TestPki::cert('revoked'), TestPki::cert('int'), time())->status);
        self::assertCount(1, self::requests(), 'second check served from memory');
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function badServerResponses(): iterable
    {
        yield 'garbage body' => ['garbage'];
        yield 'broken PEM' => ['badpem'];
        yield 'CRL of another CA' => ['wrongca'];
        yield 'tampered CRL' => ['tampered'];
        yield 'HTTP 404' => ['404'];
        yield 'redirect' => ['redirect'];
    }

    #[DataProvider('badServerResponses')]
    public function testUnusableDownloadedCrlYieldsUnknownAndIsNotCached(string $mode): void
    {
        $cache = TestPki::tempDir();
        $this->temp[] = $cache;
        self::serve($mode);
        $c = new RevocationChecker(RevocationChecker::MODE_CRL, self::proxyHttp(), $cache);
        $r = $c->check(TestPki::cert('revoked'), TestPki::cert('int'), time());
        self::assertSame(RevocationResult::UNKNOWN, $r->status);
        self::assertContains($r->reason, ['revocationunavailable', 'malformed']);
        self::assertFileDoesNotExist(self::cacheFile($cache));
        self::assertSame([self::URL], self::requests(), 'exactly one request, redirects not followed');
    }

    public function testDownloadLargerThanLimitIsAborted(): void
    {
        self::serve('der');
        $c = new RevocationChecker(RevocationChecker::MODE_CRL, self::proxyHttp(), '', strlen(TestPki::read('int.crl')) - 1);
        $r = $c->check(TestPki::cert('revoked'), TestPki::cert('int'), time());
        self::assertSame(RevocationResult::UNKNOWN, $r->status);
        self::assertStringContainsString('response exceeds size limit', implode("\n", $GLOBALS['mimeshield_test_log']));
    }

    // ================================================================== helpers: HTTP

    private static function failingHttp(?int &$calls): SafeHttpClient
    {
        $calls = 0;
        return new SafeHttpClient(resolver: static function (string $h) use (&$calls): array {
            $calls++;
            throw new \LogicException('network access attempted for ' . $h);
        });
    }

    /** Resolver answering with a private address: every fetch attempt is counted and refused. */
    private static function refusingHttp(?int &$calls): SafeHttpClient
    {
        $calls = 0;
        return new SafeHttpClient(resolver: static function (string $h) use (&$calls): array {
            $calls++;
            return ['127.0.0.1'];
        });
    }

    private static function proxyHttp(): SafeHttpClient
    {
        $port = self::server();
        return new SafeHttpClient(5, 3, [80, 443], [], [], 'http://127.0.0.1:' . $port, static fn (string $h): array => ['8.8.8.8']);
    }

    private static function serve(string $mode): void
    {
        self::server();
        file_put_contents(self::$work . '/www/mode.txt', $mode);
        @unlink(self::$work . '/www/requests.log');
    }

    /**
     * @return list<string>
     */
    private static function requests(): array
    {
        $f = self::$work . '/www/requests.log';
        return is_file($f) ? (file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: []) : [];
    }

    private static function server(): int
    {
        if (is_resource(self::$server)) {
            return self::$port;
        }
        $www = self::$work . '/www';
        mkdir($www, 0700);
        $tampered = TestPki::read('int.crl');
        $tampered[strlen($tampered) - 1] = chr(ord($tampered[strlen($tampered) - 1]) ^ 0x01);
        file_put_contents($www . '/int.crl', TestPki::read('int.crl'));
        file_put_contents($www . '/int.crl.pem', TestPki::read('int.crl.pem'));
        file_put_contents($www . '/root.crl', TestPki::read('root.crl'));
        file_put_contents($www . '/tampered.crl', $tampered);
        file_put_contents($www . '/router.php', <<<'PHP'
<?php
file_put_contents(__DIR__ . '/requests.log', $_SERVER['REQUEST_URI'] . "\n", FILE_APPEND | LOCK_EX);
$mode = trim((string) @file_get_contents(__DIR__ . '/mode.txt'));
switch ($mode) {
    case 'der': echo file_get_contents(__DIR__ . '/int.crl'); break;
    case 'pem': echo "\n", file_get_contents(__DIR__ . '/int.crl.pem'); break;
    case 'badpem': echo "-----BEGIN X509 CRL-----\n%%%%\n-----END X509 CRL-----\n"; break;
    case 'wrongca': echo file_get_contents(__DIR__ . '/root.crl'); break;
    case 'tampered': echo file_get_contents(__DIR__ . '/tampered.crl'); break;
    case 'redirect': header('Location: http://crl.example.test/elsewhere.crl', true, 302); break;
    case '404': http_response_code(404); echo 'no'; break;
    default: echo 'garbage';
}
PHP);
        $sock = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertIsResource($sock, $errstr);
        $name = (string) stream_socket_get_name($sock, false);
        fclose($sock);
        self::$port = (int) substr($name, strrpos($name, ':') + 1);
        $proc = proc_open(
            [PHP_BINARY, '-n', '-S', '127.0.0.1:' . self::$port, '-t', $www, $www . '/router.php'],
            [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes,
        );
        self::assertIsResource($proc);
        self::$server = $proc;
        $deadline = microtime(true) + 10;
        while (microtime(true) < $deadline) {
            $fp = @fsockopen('127.0.0.1', self::$port, $errno, $errstr, 0.2);
            if (is_resource($fp)) {
                fclose($fp);
                return self::$port;
            }
            usleep(50000);
        }
        self::fail('local test server did not start');
    }

    // ================================================================== helpers: cache

    private function cacheWith(string $content, ?int $mtime = null): string
    {
        $cache = TestPki::tempDir();
        $this->temp[] = $cache;
        mkdir($cache . '/crl', 0700);
        $f = self::cacheFile($cache);
        file_put_contents($f, $content);
        touch($f, $mtime ?? time());
        clearstatcache();
        return $cache;
    }

    private static function cacheFile(string $cache): string
    {
        return $cache . '/crl/' . hash('sha256', self::URL) . '.crl';
    }

    private static function checker(): RevocationChecker
    {
        return new RevocationChecker(RevocationChecker::MODE_CRL, null, '');
    }

    private static function serialOf(string $name): string
    {
        return TestPki::cert($name)->serialHex;
    }

    // ================================================================== helpers: openssl

    /**
     * Generate a CRL of the TEST intermediate with "openssl ca -gencrl".
     *
     * @param list<string> $crlExts lines of the crl_extensions section
     */
    private static function opensslCrl(string $name, array $crlExts, ?string $opt = null, ?string $optVal = null, string $extraConf = '', string $index = ''): string
    {
        if (isset(self::$gen[$name])) {
            return self::$gen[$name];
        }
        return self::$gen[$name] = self::gencrl($name, TestPki::path('int.crt'), TestPki::path('int.key'), $crlExts, $opt, $optVal, $extraConf, $index);
    }

    /**
     * @param list<string> $crlExts
     */
    private static function gencrl(string $name, string $caCrt, string $caKey, array $crlExts, ?string $opt, ?string $optVal, string $extraConf, string $index): string
    {
        $d = self::$work . '/ca-' . $name;
        mkdir($d, 0700);
        file_put_contents($d . '/index.txt', $index);
        file_put_contents($d . '/index.txt.attr', "unique_subject = no\n");
        file_put_contents($d . '/crlnumber', "1000\n");
        $conf = "[ca]\ndefault_ca = c\n[c]\ndatabase = $d/index.txt\ncrlnumber = $d/crlnumber\ncertificate = $caCrt\n"
            . "private_key = $caKey\ndefault_md = sha256\ndefault_crl_days = 30\n";
        if ($crlExts !== []) {
            $conf .= "crl_extensions = crlext\n[crlext]\n" . implode("\n", $crlExts) . "\n";
        }
        $conf .= $extraConf;
        file_put_contents($d . '/ca.cnf', $conf);
        $args = ['ca', '-config', $d . '/ca.cnf', '-gencrl', '-batch', '-out', $d . '/crl.pem'];
        if ($opt !== null) {
            $args[] = $opt;
            $args[] = (string) $optVal;
        }
        self::openssl($args);
        self::openssl(['crl', '-in', $d . '/crl.pem', '-outform', 'DER', '-out', $d . '/crl.der']);
        return (string) file_get_contents($d . '/crl.der');
    }

    /**
     * Throw-away EC P-256 CA with the given keyUsage (null = no KU extension) and its CRL.
     *
     * @param list<string> $revokedSerials
     *
     * @return array{0: Certificate, 1: string}
     */
    private static function genCa(string $name, ?string $keyUsage, array $revokedSerials): array
    {
        if (isset(self::$genCa[$name])) {
            return [self::$genCa[$name], self::$gen['ca_' . $name]];
        }
        $d = self::$work . '/rootca-' . $name;
        mkdir($d, 0700);
        $ext = "basicConstraints = critical, CA:TRUE\nsubjectKeyIdentifier = hash\n";
        if ($keyUsage !== null) {
            $ext .= "keyUsage = critical, $keyUsage\n";
        }
        file_put_contents($d . '/req.cnf', "[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = Throwaway $name CA (TEST ONLY)\n[ext]\n$ext");
        self::openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', $d . '/ca.key']);
        self::openssl(['req', '-new', '-x509', '-key', $d . '/ca.key', '-out', $d . '/ca.crt', '-days', '30', '-sha256',
            '-config', $d . '/req.cnf', '-extensions', 'ext']);
        $index = '';
        foreach ($revokedSerials as $i => $s) {
            $index .= sprintf("R\t351231235959Z\t260101000000Z,keyCompromise\t%s\tunknown\t/CN=r%d\n", $s, $i);
        }
        $crl = self::gencrl('of-' . $name, $d . '/ca.crt', $d . '/ca.key', [], null, null, '', $index);
        self::$genCa[$name] = Certificate::fromString((string) file_get_contents($d . '/ca.crt'));
        self::$gen['ca_' . $name] = $crl;
        return [self::$genCa[$name], $crl];
    }

    /**
     * @param list<string> $args
     */
    private static function openssl(array $args): void
    {
        $proc = proc_open(array_merge(['/usr/bin/openssl'], $args), [
            0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w'],
        ], $pipes, null, ['OPENSSL_CONF' => '/dev/null', 'PATH' => '/usr/bin:/bin']);
        self::assertIsResource($proc);
        $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $rc = proc_close($proc);
        self::assertSame(0, $rc, 'openssl ' . implode(' ', $args) . ': ' . $out);
    }

    // ================================================================== helpers: DER crafting

    /**
     * Craft a CRL signed with the TEST intermediate key (or $o['key']).
     *
     * @param array<string, mixed> $o
     */
    private static function craft(array $o = []): string
    {
        $issuer = $o['issuer'] ?? TestPki::cert('int')->subjectNameDer;
        $sigOid = $o['sigOid'] ?? self::OID_SHA256_RSA;
        $algSeq = self::tlv(0x30, self::oid($sigOid) . "\x05\x00");
        $thisUpdate = $o['thisUpdate'] ?? time() - 3600;
        $nextUpdate = array_key_exists('nextUpdate', $o) ? $o['nextUpdate'] : $thisUpdate + 86400 * 7;
        $tbs = (($o['version'] ?? true) ? "\x02\x01\x01" : '') . $algSeq . $issuer . self::time($thisUpdate);
        if ($nextUpdate !== null) {
            $tbs .= self::time($nextUpdate);
        }
        $entries = '';
        foreach ($o['entries'] ?? [] as [$serial, $date, $exts]) {
            $e = self::integer($serial) . self::time($date);
            if ($exts !== []) {
                $e .= self::tlv(0x30, implode('', $exts));
            }
            $entries .= self::tlv(0x30, $e);
        }
        if ($entries !== '') {
            $tbs .= self::tlv(0x30, $entries);
        }
        if (!empty($o['exts'])) {
            $tbs .= self::tlv(0xA0, self::tlv(0x30, implode('', $o['exts'])));
        }
        $tbs = self::tlv(0x30, $tbs);
        $key = openssl_pkey_get_private($o['key'] ?? TestPki::key('int'));
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $key);
        self::assertTrue(openssl_sign($tbs, $sig, $key, $o['algo'] ?? OPENSSL_ALGO_SHA256));
        return self::tlv(0x30, $tbs . $algSeq . self::tlv(0x03, "\x00" . $sig));
    }

    private static function ext(string $oid, string $valueDer, bool $critical = false): string
    {
        return self::tlv(0x30, self::oid($oid) . ($critical ? "\x01\x01\xff" : '') . self::tlv(0x04, $valueDer));
    }

    private static function tlv(int $tag, string $content): string
    {
        $len = strlen($content);
        if ($len < 0x80) {
            $l = chr($len);
        } else {
            $b = ltrim(pack('N', $len), "\x00");
            $l = chr(0x80 | strlen($b)) . $b;
        }
        return chr($tag) . $l . $content;
    }

    private static function oid(string $dotted): string
    {
        $arcs = array_map('intval', explode('.', $dotted));
        $out = '';
        $first = array_shift($arcs) * 40 + array_shift($arcs);
        foreach (array_merge([$first], $arcs) as $arc) {
            $chunk = chr($arc & 0x7F);
            $arc >>= 7;
            while ($arc > 0) {
                $chunk = chr(0x80 | ($arc & 0x7F)) . $chunk;
                $arc >>= 7;
            }
            $out .= $chunk;
        }
        return self::tlv(0x06, $out);
    }

    private static function integer(string $hex): string
    {
        $bin = (string) hex2bin(strlen($hex) % 2 ? '0' . $hex : $hex);
        if (ord($bin[0]) & 0x80) {
            $bin = "\x00" . $bin;
        }
        return self::tlv(0x02, $bin);
    }

    private static function time(int $ts): string
    {
        $y = (int) gmdate('Y', $ts);
        return $y >= 2050 ? self::tlv(0x18, gmdate('YmdHis', $ts) . 'Z') : self::tlv(0x17, gmdate('ymdHis', $ts) . 'Z');
    }

    private static function rmTree(string $dir): void
    {
        foreach (scandir($dir) ?: [] as $f) {
            if ($f === '.' || $f === '..') {
                continue;
            }
            $p = $dir . '/' . $f;
            is_dir($p) && !is_link($p) ? self::rmTree($p) : unlink($p);
        }
        rmdir($dir);
    }
}
