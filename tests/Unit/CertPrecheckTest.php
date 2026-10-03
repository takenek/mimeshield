<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Cert\CertPrecheck;
use MimeShield\Cert\Certificate;
use MimeShield\Cert\PublicCertImporter;
use MimeShield\Crypto\Asn1;
use MimeShield\Crypto\CmsInspector;
use MimeShield\Crypto\CmsService;
use MimeShield\Crypto\SignatureCheck;
use MimeShield\Exception\CryptoException;
use MimeShield\Exception\ValidationException;
use MimeShield\Tests\TestPki;
use PHPUnit\Framework\TestCase;

/**
 * CVE-2026-35189 pre-check (lib/MimeShield/Cert/CertPrecheck.php, audit F-16): certificates with
 * relative / too many CRL distribution points never reach OpenSSL - neither as a certificate, nor
 * embedded in SignedData, EnvelopedData OriginatorInfo or a PKCS#7 bundle. The certificates are
 * synthetic: a real test certificate with a spliced cRLDistributionPoints extension (the pre-check
 * and openssl_x509_read do not verify the issuer signature).
 */
final class CertPrecheckTest extends TestCase
{
    private const OID_CRLDP = '2.5.29.31';
    private const CONTENT = "Content-Type: text/plain\r\n\r\nhello\r\n";

    private string $base;

    protected function setUp(): void
    {
        $this->base = TestPki::tempDir();
    }

    protected function tearDown(): void
    {
        foreach (glob($this->base . '/{,.}*', GLOB_BRACE) ?: [] as $f) {
            if (is_file($f)) {
                unlink($f);
            }
        }
        @rmdir($this->base);
    }

    // ------------------------------------------------------------------ CertPrecheck / Certificate

    public function testFixtureCertificatesPass(): void
    {
        $files = glob(TestPki::dir() . '/*.crt') ?: [];
        self::assertNotEmpty($files);
        foreach ($files as $file) {
            CertPrecheck::assertSafe(Certificate::fromString((string) file_get_contents($file))->der);
        }
    }

    public function testEightFullNamePointsAccepted(): void
    {
        $der = self::aliceWith([self::crlDpExt(array_fill(0, 8, self::fullPoint('http://crl.example.test/x.crl')))]);
        CertPrecheck::assertSafe($der);
        $c = Certificate::fromDer($der);
        self::assertCount(8, $c->crlUrls);
    }

    public function testMoreThanEightPointsRefused(): void
    {
        $der = self::aliceWith([self::crlDpExt(array_fill(0, 9, self::fullPoint('http://crl.example.test/x.crl')))]);
        self::assertRefusedByPrecheck(static fn () => Certificate::fromDer($der), 'too many CRL distribution points');
    }

    public function testRelativeNameRefused(): void
    {
        $der = self::aliceWith([self::crlDpExt([self::fullPoint('http://crl.example.test/x.crl'), self::relativePoint()])]);
        // without the pre-check OpenSSL reads this certificate and parseDer ignores the relative name
        self::assertRefusedByPrecheck(static fn () => Certificate::fromDer($der), 'nameRelativeToCRLIssuer');
    }

    public function testDuplicateExtensionRefusedBeforeOpenSsl(): void
    {
        $ext = self::crlDpExt([self::fullPoint('http://crl.example.test/x.crl')]);
        $der = self::aliceWith([$ext, $ext]);
        // Certificate::parseDer refuses duplicates too, but only after openssl_x509_read
        self::assertRefusedByPrecheck(static fn () => Certificate::fromDer($der), 'duplicate cRLDistributionPoints');
    }

    public function testUnparsableExtensionValueRefused(): void
    {
        $bad = self::seq(self::oid(self::OID_CRLDP) . Asn1::encode("\x04", "\x30\x05\x30\x00"));
        self::assertRefusedByPrecheck(static fn () => CertPrecheck::assertSafe(self::aliceWith([$bad])), 'pre-check');
        self::assertRefusedByPrecheck(static fn () => CertPrecheck::assertSafe("\x30\x03\x02\x01\x00"), 'pre-check');
    }

    // ------------------------------------------------------------------ CMS

    public function testCertificateChoicesOfFixtures(): void
    {
        $cms = new CmsService($this->base);
        $alice = TestPki::cert('alice');
        $sig = $cms->signDetached(self::CONTENT, $alice, TestPki::key('alice'), [TestPki::read('int.crt')]);
        $r = CmsInspector::certificateChoices($sig);
        self::assertSame(0, $r['other']);
        self::assertContains($alice->der, $r['certificates']);
        self::assertCount(2, $r['certificates']);

        $env = $cms->encrypt(self::CONTENT, [TestPki::cert('bob')]);
        self::assertSame(['certificates' => [], 'other' => 0], CmsInspector::certificateChoices($env));
        $withOi = self::withOriginatorCerts($env, [$alice->der, "\xA1\x03\x02\x01\x00"]);
        self::assertSame(['certificates' => [$alice->der], 'other' => 1], CmsInspector::certificateChoices($withOi));

        $this->expectException(ValidationException::class);
        CmsInspector::certificateChoices(substr($sig, 0, -10));
    }

    public function testVerifyDetachedRefusesUnsafeEmbeddedCertificate(): void
    {
        $cms = new CmsService($this->base);
        $sig = $cms->signDetached(self::CONTENT, TestPki::cert('alice'), TestPki::key('alice'));
        self::assertTrue($cms->verifyDetached(self::CONTENT, $sig)->valid);

        // same key, spliced certificate: valid for OpenSSL (NOVERIFY), refused by the pre-check
        $bad = self::replaceSignedDataCert($sig, self::aliceWith([self::crlDpExt([self::relativePoint()])]));
        $check = $cms->verifyDetached(self::CONTENT, $bad);
        self::assertFalse($check->valid);
        self::assertSame(SignatureCheck::FAIL_MALFORMED, $check->failure);
        self::assertSame([], $check->signerPems);
        self::assertSame([], $check->embeddedPems);
        self::assertSame([], CmsService::embeddedCertificates($bad));
    }

    public function testVerifyOpaqueRefusesUnsafeEmbeddedCertificate(): void
    {
        $opaque = $this->signOpaque();
        $cms = new CmsService($this->base);
        self::assertTrue($cms->verifyOpaque($opaque)->valid);

        $bad = self::replaceSignedDataCert($opaque, self::aliceWith([self::crlDpExt(array_fill(0, 9, self::fullPoint('http://a.test/c')))]));
        $check = $cms->verifyOpaque($bad);
        self::assertFalse($check->valid);
        self::assertSame(SignatureCheck::FAIL_MALFORMED, $check->failure);
        self::assertNull($check->content);
        // display path of IncomingProcessor: the content is still available, unverified
        self::assertSame(self::CONTENT, $cms->extractOpaqueContent($bad));
    }

    public function testDecryptRefusesUnsafeOriginatorCertificate(): void
    {
        $cms = new CmsService($this->base);
        $bob = TestPki::cert('bob');
        $env = $cms->encrypt(self::CONTENT, [$bob]);

        // OpenSSL accepts OriginatorInfo certificates: a safe one decrypts normally
        $ok = self::withOriginatorCerts($env, [TestPki::cert('alice')->der]);
        self::assertSame(self::CONTENT, $cms->decrypt($ok, $bob, TestPki::key('bob')));

        $bad = self::withOriginatorCerts($env, [self::aliceWith([self::crlDpExt([self::relativePoint()])])]);
        try {
            $cms->decrypt($bad, $bob, TestPki::key('bob'));
            self::fail('unsafe OriginatorInfo certificate must be refused');
        } catch (CryptoException $e) {
            self::assertSame('certinvalid', $e->getUserLabel());
        }
    }

    // ------------------------------------------------------------------ PKCS#7 import

    public function testPkcs7BundleRefusedBeforeOpenSsl(): void
    {
        $good = $this->bundle([TestPki::cert('alice')->der]);
        $r = (new PublicCertImporter())->parse($good);
        self::assertCount(1, $r['entities']);

        $bad = $this->bundle([self::aliceWith([self::crlDpExt([self::relativePoint()])])]);
        try {
            (new PublicCertImporter())->parse($bad);
            self::fail('unsafe bundle certificate must be refused');
        } catch (ValidationException $e) {
            self::assertSame('certinvalid', $e->getUserLabel());
            // refused in readPkcs7 (before openssl_pkcs7_read), not only later by Certificate
            $frames = array_map(static fn (array $f) => ($f['class'] ?? '') . '::' . $f['function'], $e->getTrace());
            self::assertContains(PublicCertImporter::class . '::readPkcs7', $frames);
            self::assertNotContains(Certificate::class . '::__construct', $frames);
        }
        $pem = "-----BEGIN PKCS7-----\n" . chunk_split(base64_encode($bad), 64, "\n") . "-----END PKCS7-----\n";
        $this->expectException(ValidationException::class);
        (new PublicCertImporter())->parse($pem);
    }

    // ------------------------------------------------------------------ helpers

    private static function assertRefusedByPrecheck(callable $fn, string $needle): void
    {
        try {
            $fn();
            self::fail('certificate must be refused');
        } catch (ValidationException $e) {
            self::assertSame('certinvalid', $e->getUserLabel());
            self::assertStringContainsString('pre-check', $e->getMessage());
            self::assertStringContainsString($needle, $e->getMessage());
        }
    }

    private static function seq(string $content): string
    {
        return Asn1::encode("\x30", $content);
    }

    private static function oid(string $dotted): string
    {
        $arcs = array_map('intval', explode('.', $dotted));
        $out = chr(40 * $arcs[0] + $arcs[1]);
        foreach (array_slice($arcs, 2) as $a) {
            $enc = chr($a & 0x7F);
            while ($a >>= 7) {
                $enc = chr(0x80 | ($a & 0x7F)) . $enc;
            }
            $out .= $enc;
        }
        return Asn1::encode("\x06", $out);
    }

    private static function fullPoint(string $uri): string
    {
        // DistributionPoint { distributionPoint [0] { fullName [0] { uniformResourceIdentifier [6] } } }
        return self::seq(Asn1::encode("\xA0", Asn1::encode("\xA0", Asn1::encode("\x86", $uri))));
    }

    private static function relativePoint(): string
    {
        // nameRelativeToCRLIssuer [1] IMPLICIT RelativeDistinguishedName (SET OF AttributeTypeAndValue)
        $atv = self::seq(self::oid('2.5.4.3') . Asn1::encode("\x0C", 'crl'));
        return self::seq(Asn1::encode("\xA0", Asn1::encode("\xA1", $atv)));
    }

    /**
     * @param list<string> $points
     */
    private static function crlDpExt(array $points): string
    {
        return self::seq(self::oid(self::OID_CRLDP) . Asn1::encode("\x04", self::seq(implode('', $points))));
    }

    /**
     * alice.crt with its cRLDistributionPoints replaced by $exts (issuer signature no longer valid).
     *
     * @param list<string> $exts
     */
    private static function aliceWith(array $exts): string
    {
        $cert = Asn1::parse(TestPki::cert('alice')->der);
        [$tbs, $alg, $sig] = $cert->children();
        $fields = '';
        foreach ($tbs->children() as $f) {
            if (!$f->isContext(3)) {
                $fields .= $f->raw();
                continue;
            }
            $list = '';
            foreach (Asn1::parseContent($f)->children() as $e) {
                if (Asn1::oid($e->child(0)) !== self::OID_CRLDP) {
                    $list .= $e->raw();
                }
            }
            $fields .= Asn1::encode("\xA3", self::seq($list . implode('', $exts)));
        }
        return self::seq(self::seq($fields) . $alg->raw() . $sig->raw());
    }

    private static function replaceSignedDataCert(string $cms, string $certDer): string
    {
        $root = Asn1::parse($cms);
        foreach ($root->child(1)->child(0)->children() as $i => $f) {
            if ($i >= 3 && $f->isContext(0)) {
                return Asn1::replaceAt($root, [1, 0, $i], Asn1::encode("\xA0", $certDer));
            }
        }
        self::fail('no certificates in SignedData');
    }

    /**
     * EnvelopedData with OriginatorInfo { certs [0] } inserted (version 2, RFC 5652 6.1).
     *
     * @param list<string> $choices
     */
    private static function withOriginatorCerts(string $env, array $choices): string
    {
        $root = Asn1::parse($env);
        $f = $root->child(1)->child(0)->children();
        $ed = "\x02\x01\x02" . Asn1::encode("\xA0", Asn1::encode("\xA0", implode('', $choices)));
        foreach (array_slice($f, 1) as $n) {
            $ed .= $n->raw();
        }
        return self::seq($root->child(0)->raw() . Asn1::encode("\xA0", self::seq($ed)));
    }

    private function signOpaque(): string
    {
        $in = $this->base . '/in';
        $out = $this->base . '/out';
        file_put_contents($in, self::CONTENT);
        self::assertTrue(openssl_cms_sign($in, $out, TestPki::read('alice.crt'), TestPki::key('alice'), null, OPENSSL_CMS_BINARY, OPENSSL_ENCODING_DER));
        return (string) file_get_contents($out);
    }

    /**
     * PKCS#7 certs-only SignedData (DER).
     *
     * @param list<string> $certs
     */
    private function bundle(array $certs): string
    {
        $sd = "\x02\x01\x01" . "\x31\x00" . self::seq(self::oid(CmsInspector::OID_DATA))
            . Asn1::encode("\xA0", implode('', $certs)) . "\x31\x00";
        return self::seq(self::oid(CmsInspector::OID_SIGNED_DATA) . Asn1::encode("\xA0", self::seq($sd)));
    }
}
