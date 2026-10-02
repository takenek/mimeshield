<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Cert\Certificate;
use MimeShield\Crypto\CmsInspector;
use MimeShield\Crypto\CmsService;
use MimeShield\Crypto\OpenSsl;
use MimeShield\Crypto\SignatureCheck;
use MimeShield\Exception\CryptoException;
use MimeShield\Tests\TestPki;
use PHPUnit\Framework\TestCase;

/**
 * CmsService against independent OpenSSL CLI operations (TEST-ONLY PKI).
 */
final class CmsServiceTest extends TestCase
{
    private const OPENSSL = '/usr/bin/openssl';

    /** Binary content: bare LF, bare CR, NUL, 8-bit bytes, trailing whitespace. */
    private const BINARY_CONTENT = "Content-Type: text/plain\r\n\r\nline one \r\nbare-lf\nbare-cr\rnul\x00 8bit \xC5\xBC\xFF\r\n.\r\nFrom x\r\n";

    private string $base;

    private string $work;

    protected function setUp(): void
    {
        $this->base = TestPki::tempDir();
        $this->work = TestPki::tempDir();
    }

    protected function tearDown(): void
    {
        self::rmTree($this->base);
        self::rmTree($this->work);
    }

    // ------------------------------------------------------------------ signing

    public function testSignDetachedProducesDerSignatureOverExactBytes(): void
    {
        $cms = new CmsService($this->base);
        $der = $cms->signDetached(self::BINARY_CONTENT, TestPki::cert('alice'), TestPki::key('alice'), [TestPki::read('int.crt')]);
        $this->assertTempEmpty();

        // DER ContentInfo (SEQUENCE), signed-data, detached
        self::assertSame("\x30", $der[0]);
        self::assertSame(CmsInspector::OID_SIGNED_DATA, CmsInspector::contentType($der));
        $info = CmsInspector::signedData($der);
        self::assertTrue($info['detached']);
        self::assertSame(['sha256'], $info['digests']);
        self::assertCount(1, $info['signers']);
        self::assertSame('sha256', $info['signers'][0]['digest']);
        self::assertSame(2, $info['certificates']);

        // independent verification: full chain to the test root, exact (binary) content
        $sig = $this->put('sig.der', $der);
        $content = $this->put('content.bin', self::BINARY_CONTENT);
        [$rc, , $err] = self::openssl(['cms', '-verify', '-binary', '-inform', 'DER', '-in', $sig, '-content', $content,
            '-CAfile', TestPki::path('root.crt'), '-purpose', 'smimesign', '-out', '/dev/null']);
        self::assertSame(0, $rc, $err);

        // the same signature must NOT verify over canonicalised (altered) bytes
        $altered = $this->put('altered.bin', str_replace("\n", "\r\n", str_replace("\r\n", "\n", self::BINARY_CONTENT)));
        [$rc2] = self::openssl(['cms', '-verify', '-binary', '-inform', 'DER', '-in', $sig, '-content', $altered, '-noverify', '-out', '/dev/null']);
        self::assertNotSame(0, $rc2);
    }

    public function testNoSmimeCapabilitiesAttributeByDefault(): void
    {
        $der = (new CmsService($this->base))->signDetached("abc\r\n", TestPki::cert('alice'), TestPki::key('alice'));
        $this->assertTempEmpty();
        $print = $this->cmsPrint($der);
        self::assertStringContainsString('messageDigest (1.2.840.113549.1.9.4)', $print);
        self::assertStringContainsString('sha256 (2.16.840.1.101.3.4.2.1)', $print);
        self::assertStringNotContainsString('1.2.840.113549.1.9.15', $print);
        self::assertStringNotContainsString('S/MIME Capabilities', $print);
    }

    public function testSmimeCapabilitiesAttributePresentWhenEnabled(): void
    {
        $der = (new CmsService($this->base, true))->signDetached("abc\r\n", TestPki::cert('alice'), TestPki::key('alice'));
        $this->assertTempEmpty();
        self::assertStringContainsString('S/MIME Capabilities (1.2.840.113549.1.9.15)', $this->cmsPrint($der));
    }

    public function testChainIsEmbeddedOnlyWhenGiven(): void
    {
        $cms = new CmsService($this->base);
        $alice = TestPki::cert('alice');
        $int = TestPki::cert('int');

        $with = $cms->signDetached('x', $alice, TestPki::key('alice'), [TestPki::read('int.crt')]);
        $this->assertTempEmpty();
        $fps = array_map(static fn (string $p) => Certificate::fromString($p)->fingerprint, CmsService::embeddedCertificates($with));
        sort($fps);
        $expected = [$alice->fingerprint, $int->fingerprint];
        sort($expected);
        self::assertSame($expected, $fps);

        $without = $cms->signDetached('x', $alice, TestPki::key('alice'));
        $this->assertTempEmpty();
        $only = CmsService::embeddedCertificates($without);
        self::assertCount(1, $only);
        self::assertSame($alice->fingerprint, Certificate::fromString($only[0])->fingerprint);
        self::assertSame(1, CmsInspector::signedData($without)['certificates']);
    }

    public function testSignWithEcKey(): void
    {
        $cms = new CmsService($this->base);
        $der = $cms->signDetached(self::BINARY_CONTENT, TestPki::cert('carol'), TestPki::key('carol'));
        $this->assertTempEmpty();
        $check = $cms->verifyDetached(self::BINARY_CONTENT, $der);
        $this->assertTempEmpty();
        self::assertTrue($check->valid);
        self::assertSame('sha256', $check->digest());
        self::assertStringStartsWith('ecdsa', $check->signatureAlgorithm());
    }

    public function testSignWithMismatchedKeyFails(): void
    {
        $cms = new CmsService($this->base);
        try {
            $cms->signDetached('x', TestPki::cert('alice'), TestPki::key('bob'));
            self::fail('signing with a key that does not match the certificate must fail');
        } catch (CryptoException $e) {
            self::assertSame('signfailed', $e->getUserLabel());
        }
        $this->assertTempEmpty();
    }

    // ------------------------------------------------------------------ verifying

    public function testVerifyDetachedValid(): void
    {
        $cms = new CmsService($this->base);
        $alice = TestPki::cert('alice');
        $der = $cms->signDetached(self::BINARY_CONTENT, $alice, TestPki::key('alice'), [TestPki::read('int.crt')]);

        $check = $cms->verifyDetached(self::BINARY_CONTENT, $der);
        $this->assertTempEmpty();

        self::assertTrue($check->valid);
        self::assertSame(SignatureCheck::FAIL_NONE, $check->failure);
        self::assertFalse($check->canonicalized);
        self::assertNull($check->content);
        self::assertCount(1, $check->signerPems);
        self::assertSame($alice->fingerprint, Certificate::fromString($check->signerPems[0])->fingerprint);
        self::assertCount(2, $check->embeddedPems);
        self::assertSame('sha256', $check->digest());
        self::assertSame(1, $check->signerCount());
        $t = $check->signingTime();
        self::assertNotNull($t);
        self::assertLessThan(300, abs(time() - $t));
    }

    public function testVerifyDetachedModifiedContent(): void
    {
        $cms = new CmsService($this->base);
        $alice = TestPki::cert('alice');
        $der = $cms->signDetached(self::BINARY_CONTENT, $alice, TestPki::key('alice'));

        $tampered = self::BINARY_CONTENT;
        $tampered[30] = $tampered[30] === 'X' ? 'Y' : 'X';
        $check = $cms->verifyDetached($tampered, $der);
        $this->assertTempEmpty();

        self::assertFalse($check->valid);
        self::assertSame(SignatureCheck::FAIL_MODIFIED, $check->failure);
        self::assertFalse($check->canonicalized);
        // signer identified from the embedded certificates for display
        self::assertCount(1, $check->signerPems);
        self::assertSame($alice->fingerprint, Certificate::fromString($check->signerPems[0])->fingerprint);
        self::assertCount(1, $check->embeddedPems);

        // appending one byte is a modification too
        $check2 = $cms->verifyDetached(self::BINARY_CONTENT . "\r\n", $der);
        $this->assertTempEmpty();
        self::assertFalse($check2->valid);
        self::assertSame(SignatureCheck::FAIL_MODIFIED, $check2->failure);
    }

    public function testVerifyDetachedAcceptsLfConvertedContentAsCanonicalized(): void
    {
        $cms = new CmsService($this->base);
        $crlf = "Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nHello\r\nZa=C5=BC\r\n";
        $der = $cms->signDetached($crlf, TestPki::cert('alice'), TestPki::key('alice'));

        $lf = str_replace("\r\n", "\n", $crlf);
        $check = $cms->verifyDetached($lf, $der);
        $this->assertTempEmpty();
        self::assertTrue($check->valid);
        self::assertTrue($check->canonicalized);
        self::assertSame(SignatureCheck::FAIL_NONE, $check->failure);
        self::assertCount(1, $check->signerPems);

        // canonicalisation disabled: the LF form is a modification
        $strict = $cms->verifyDetached($lf, $der, false);
        $this->assertTempEmpty();
        self::assertFalse($strict->valid);
        self::assertSame(SignatureCheck::FAIL_MODIFIED, $strict->failure);
        self::assertFalse($strict->canonicalized);

        // canonicalisation must not make real modifications pass
        $modified = $cms->verifyDetached(str_replace('Hello', 'Hellx', $lf), $der);
        $this->assertTempEmpty();
        self::assertFalse($modified->valid);
        self::assertSame(SignatureCheck::FAIL_MODIFIED, $modified->failure);
    }

    public function testVerifyDetachedMalformedSignature(): void
    {
        $cms = new CmsService($this->base);
        $check = $cms->verifyDetached('content', "\x30\x03\x02\x01\x01");
        $this->assertTempEmpty();
        self::assertFalse($check->valid);
        self::assertNotSame(SignatureCheck::FAIL_NONE, $check->failure);
        self::assertSame([], $check->signerPems);
        self::assertSame([], $check->embeddedPems);
    }

    public function testVerifyOpaqueReturnsExactContent(): void
    {
        $content = self::BINARY_CONTENT . 'OPAQUE-MARKER-0123456789';
        $der = $this->cliSignOpaque($content);
        $cms = new CmsService($this->base);

        $check = $cms->verifyOpaque($der);
        $this->assertTempEmpty();
        self::assertTrue($check->valid);
        self::assertSame(SignatureCheck::FAIL_NONE, $check->failure);
        self::assertSame($content, $check->content);
        self::assertCount(1, $check->signerPems);
        self::assertSame(TestPki::cert('alice')->fingerprint, Certificate::fromString($check->signerPems[0])->fingerprint);
        self::assertFalse(CmsInspector::signedData($der)['detached']);
        self::assertSame($content, $cms->extractOpaqueContent($der));
    }

    public function testVerifyOpaqueTampered(): void
    {
        $content = self::BINARY_CONTENT . 'OPAQUE-MARKER-0123456789';
        $der = $this->cliSignOpaque($content);
        $pos = strpos($der, 'OPAQUE-MARKER');
        self::assertIsInt($pos);
        $der[$pos] = 'Q';

        $check = (new CmsService($this->base))->verifyOpaque($der);
        $this->assertTempEmpty();
        self::assertFalse($check->valid);
        self::assertSame(SignatureCheck::FAIL_MODIFIED, $check->failure);
        self::assertNull($check->content);
        self::assertCount(1, $check->signerPems);
    }

    public function testVerifySha1SignatureFromCli(): void
    {
        $content = self::BINARY_CONTENT;
        $in = $this->put('sha1-in.bin', $content);
        $out = $this->work . '/sha1.der';
        [$rc, , $err] = self::openssl(['cms', '-sign', '-binary', '-md', 'sha1', '-in', $in, '-signer', TestPki::path('alice.crt'),
            '-inkey', TestPki::path('alice.key'), '-outform', 'DER', '-out', $out]);
        self::assertSame(0, $rc, $err);
        $der = (string) file_get_contents($out);

        $cms = new CmsService($this->base);
        $check = $cms->verifyDetached($content, $der);
        $this->assertTempEmpty();
        self::assertTrue($check->valid);
        self::assertSame('sha1', $check->digest());
        self::assertSame(['sha1'], CmsInspector::signedData($der)['digests']);

        $bad = $cms->verifyDetached($content . 'x', $der);
        $this->assertTempEmpty();
        self::assertFalse($bad->valid);
        self::assertSame(SignatureCheck::FAIL_MODIFIED, $bad->failure);
    }

    public function testEmbeddedCertificates(): void
    {
        self::assertSame([], CmsService::embeddedCertificates(''));
        self::assertSame([], CmsService::embeddedCertificates('not a cms structure'));

        $der = (new CmsService($this->base))->signDetached('x', TestPki::cert('bob'), TestPki::key('bob'), [TestPki::read('int.crt')]);
        $certs = CmsService::embeddedCertificates($der);
        self::assertCount(2, $certs);
        foreach ($certs as $pem) {
            self::assertStringStartsWith('-----BEGIN CERTIFICATE-----', $pem);
        }
        // enveloped data carries no certificates
        $env = (new CmsService($this->base))->encrypt('x', [TestPki::cert('bob')]);
        self::assertSame([], CmsService::embeddedCertificates($env));
        $this->assertTempEmpty();
    }

    // ------------------------------------------------------------------ encryption

    public function testEncryptToOneRecipient(): void
    {
        $cms = new CmsService($this->base);
        $der = $cms->encrypt(self::BINARY_CONTENT, [TestPki::cert('alice')]);
        $this->assertTempEmpty();

        $env = CmsInspector::envelopedData($der);
        self::assertSame('enveloped-data', $env['type']);
        self::assertSame('aes-256-cbc', $env['cipher']);
        self::assertCount(1, $env['recipients']);
        self::assertStringNotContainsString('8bit', $der);

        self::assertSame(self::BINARY_CONTENT, $cms->decrypt($der, TestPki::cert('alice'), TestPki::key('alice')));
        $this->assertTempEmpty();

        // independent decryption with the CLI
        $in = $this->put('one.der', $der);
        [$rc, $out, $err] = self::openssl(['cms', '-decrypt', '-binary', '-inform', 'DER', '-in', $in,
            '-recip', TestPki::path('alice.crt'), '-inkey', TestPki::path('alice.key')]);
        self::assertSame(0, $rc, $err);
        self::assertSame(self::BINARY_CONTENT, $out);
    }

    public function testEncryptAes128Cbc(): void
    {
        $cms = new CmsService($this->base);
        $der = $cms->encrypt('hello', [TestPki::cert('bob')], CmsService::CIPHER_AES_128_CBC);
        self::assertSame('aes-128-cbc', CmsInspector::envelopedData($der)['cipher']);
        self::assertSame('hello', $cms->decrypt($der, TestPki::cert('bob'), TestPki::key('bob')));
        $this->assertTempEmpty();
    }

    public function testEncryptToThreeRecipientsIncludingEc(): void
    {
        $cms = new CmsService($this->base);
        $content = str_repeat(self::BINARY_CONTENT, 50);
        $der = $cms->encrypt($content, [TestPki::cert('alice'), TestPki::cert('bob'), TestPki::cert('carol')]);
        $this->assertTempEmpty();

        $env = CmsInspector::envelopedData($der);
        self::assertCount(3, $env['recipients']);
        $types = array_column($env['recipients'], 'type');
        sort($types);
        self::assertSame(['kari', 'ktri', 'ktri'], $types);

        foreach (['alice', 'bob', 'carol'] as $who) {
            self::assertSame($content, $cms->decrypt($der, TestPki::cert($who), TestPki::key($who)), $who);
            $this->assertTempEmpty();
        }

        // not a recipient
        self::assertNull($cms->decrypt($der, TestPki::cert('mallory'), TestPki::key('mallory')));
        $this->assertTempEmpty();
    }

    public function testDecryptWithWrongKeyReturnsNull(): void
    {
        $cms = new CmsService($this->base);
        for ($i = 0; $i < 4; $i++) {
            $der = $cms->encrypt(self::BINARY_CONTENT, [TestPki::cert('alice')]);
            // right certificate (recipient matches), wrong private key
            $r = $this->decryptNeverPartial($cms, $der, TestPki::cert('alice'), TestPki::key('alice2'));
            self::assertNull($r);
            $this->assertTempEmpty();
        }
        // EC recipient with an RSA key
        $der = $cms->encrypt('x', [TestPki::cert('carol')]);
        self::assertNull($this->decryptNeverPartial($cms, $der, TestPki::cert('carol'), TestPki::key('bob')));
        $this->assertTempEmpty();
    }

    public function testCorruptedCiphertextNeverYieldsPartialPlaintext(): void
    {
        $cms = new CmsService($this->base);
        $content = str_repeat("secret line 0123456789abcdef\r\n", 20);
        $der = $cms->encrypt($content, [TestPki::cert('bob')]);
        $cert = TestPki::cert('bob');
        $key = TestPki::key('bob');

        // truncated at various points
        foreach ([1, 16, 17, 100, intdiv(strlen($der), 2)] as $cut) {
            self::assertNull($this->decryptNeverPartial($cms, substr($der, 0, strlen($der) - $cut), $cert, $key), 'cut ' . $cut);
            $this->assertTempEmpty();
        }

        // the encrypted content is the last element of the DER structure: flipping the top bit of the
        // last byte of the penultimate ciphertext block flips the top bit of the CBC padding byte,
        // which makes the padding invalid deterministically
        $flipped = $der;
        $flipped[strlen($der) - 17] = chr(ord($flipped[strlen($der) - 17]) ^ 0x80);
        self::assertNull($this->decryptNeverPartial($cms, $flipped, $cert, $key));
        $this->assertTempEmpty();

        // garbage
        self::assertNull($this->decryptNeverPartial($cms, random_bytes(64), $cert, $key));
        self::assertNull($this->decryptNeverPartial($cms, '', $cert, $key));
        $this->assertTempEmpty();
    }

    public function testEmptyRecipientListRejected(): void
    {
        try {
            (new CmsService($this->base))->encrypt('x', []);
            self::fail('empty recipient list must be rejected');
        } catch (CryptoException $e) {
            self::assertSame('encryptfailed', $e->getUserLabel());
        }
        $this->assertTempEmpty();
    }

    public function testGcmEncryptionDependsOnPhpVersion(): void
    {
        $cms = new CmsService($this->base);
        $content = self::BINARY_CONTENT;
        if (PHP_VERSION_ID >= 80500) {
            self::assertContains(CmsService::CIPHER_AES_256_GCM, CmsService::supportedCiphers());
            self::assertContains(CmsService::CIPHER_AES_128_GCM, CmsService::supportedCiphers());
            $der = $cms->encrypt($content, [TestPki::cert('alice'), TestPki::cert('carol')], CmsService::CIPHER_AES_256_GCM);
            $this->assertTempEmpty();
            self::assertSame(CmsInspector::OID_AUTH_ENVELOPED_DATA, CmsInspector::contentType($der));
            self::assertSame('aes-256-gcm', CmsInspector::envelopedData($der)['cipher']);
            self::assertSame($content, $cms->decrypt($der, TestPki::cert('alice'), TestPki::key('alice')));
            self::assertSame($content, $cms->decrypt($der, TestPki::cert('carol'), TestPki::key('carol')));
            $this->assertTempEmpty();

            $der128 = $cms->encrypt($content, [TestPki::cert('bob')], CmsService::CIPHER_AES_128_GCM);
            self::assertSame('aes-128-gcm', CmsInspector::envelopedData($der128)['cipher']);
            self::assertSame($content, $cms->decrypt($der128, TestPki::cert('bob'), TestPki::key('bob')));
            $this->assertTempEmpty();

            // CLI decrypts what PHP produced
            $in = $this->put('gcm-php.der', $der);
            [$rc, $out, $err] = self::openssl(['cms', '-decrypt', '-binary', '-inform', 'DER', '-in', $in,
                '-recip', TestPki::path('alice.crt'), '-inkey', TestPki::path('alice.key')]);
            self::assertSame(0, $rc, $err);
            self::assertSame($content, $out);

            // authenticated: any bit flip in the ciphertext is rejected
            $pos = strlen($der) - 40;
            $bad = $der;
            $bad[$pos] = chr(ord($bad[$pos]) ^ 0x01);
            self::assertNull($this->decryptNeverPartial($cms, $bad, TestPki::cert('alice'), TestPki::key('alice')));
            $this->assertTempEmpty();
        } else {
            self::assertNotContains(CmsService::CIPHER_AES_256_GCM, CmsService::supportedCiphers());
            self::assertNotContains(CmsService::CIPHER_AES_128_GCM, CmsService::supportedCiphers());
            foreach ([CmsService::CIPHER_AES_256_GCM, CmsService::CIPHER_AES_128_GCM] as $c) {
                try {
                    $cms->encrypt($content, [TestPki::cert('alice')], $c);
                    self::fail('GCM must be refused before PHP 8.5');
                } catch (CryptoException $e) {
                    self::assertSame('encryptfailed', $e->getUserLabel());
                }
            }
            $this->assertTempEmpty();
        }
        self::assertContains(CmsService::CIPHER_AES_256_CBC, CmsService::supportedCiphers());
        self::assertContains(CmsService::CIPHER_AES_128_CBC, CmsService::supportedCiphers());
    }

    public function testUnknownCipherRejected(): void
    {
        try {
            (new CmsService($this->base))->encrypt('x', [TestPki::cert('alice')], 'des-ede3-cbc');
            self::fail('3DES must not be used for new messages');
        } catch (CryptoException $e) {
            self::assertSame('encryptfailed', $e->getUserLabel());
        }
        $this->assertTempEmpty();
    }

    public function testDecryptGcmFromCli(): void
    {
        $content = self::BINARY_CONTENT;
        $cms = new CmsService($this->base);
        foreach (['-aes-256-gcm', '-aes-128-gcm'] as $cipher) {
            $der = $this->cliEncrypt($content, [$cipher], ['alice', 'carol']);
            self::assertSame(CmsInspector::OID_AUTH_ENVELOPED_DATA, CmsInspector::contentType($der));
            self::assertSame($content, $cms->decrypt($der, TestPki::cert('alice'), TestPki::key('alice')), $cipher);
            self::assertSame($content, $cms->decrypt($der, TestPki::cert('carol'), TestPki::key('carol')), $cipher);
            self::assertNull($cms->decrypt($der, TestPki::cert('bob'), TestPki::key('bob')));
            $this->assertTempEmpty();
        }
    }

    public function testDecryptRsaOaepFromCli(): void
    {
        $content = self::BINARY_CONTENT;
        $in = $this->put('oaep-in.bin', $content);
        $out = $this->work . '/oaep.der';
        [$rc, , $err] = self::openssl(['cms', '-encrypt', '-binary', '-aes-256-cbc', '-in', $in, '-outform', 'DER', '-out', $out,
            '-recip', TestPki::path('bob.crt'), '-keyopt', 'rsa_padding_mode:oaep']);
        self::assertSame(0, $rc, $err);
        $der = (string) file_get_contents($out);
        // keyEncryptionAlgorithm id-RSAES-OAEP
        self::assertSame('1.2.840.113549.1.1.7', CmsInspector::envelopedData($der)['recipients'][0]['alg']);

        $cms = new CmsService($this->base);
        self::assertSame($content, $cms->decrypt($der, TestPki::cert('bob'), TestPki::key('bob')));
        $this->assertTempEmpty();
    }

    public function testDecryptLegacy3DesFromCli(): void
    {
        $content = self::BINARY_CONTENT;
        $der = $this->cliEncrypt($content, ['-des3'], ['alice']);
        self::assertSame('des-ede3-cbc', CmsInspector::envelopedData($der)['cipher']);
        $cms = new CmsService($this->base);
        self::assertSame($content, $cms->decrypt($der, TestPki::cert('alice'), TestPki::key('alice')));
        $this->assertTempEmpty();
    }

    public function testDecryptRc2FailsAsUnsupportedAlgorithm(): void
    {
        $content = self::BINARY_CONTENT;
        $der = $this->cliEncrypt($content, ['-provider', 'legacy', '-provider', 'default', '-rc2-40'], ['alice']);
        self::assertSame('rc2-cbc', CmsInspector::envelopedData($der)['cipher']);

        $cms = new CmsService($this->base);
        if (self::phpHasLegacyProvider()) {
            // legacy provider active in this PHP: RC2 is readable
            self::assertSame($content, $cms->decrypt($der, TestPki::cert('alice'), TestPki::key('alice')));
        } else {
            try {
                $cms->decrypt($der, TestPki::cert('alice'), TestPki::key('alice'));
                self::fail('RC2 must fail with unsupportedalgorithm');
            } catch (CryptoException $e) {
                self::assertSame('unsupportedalgorithm', $e->getUserLabel());
            }
        }
        $this->assertTempEmpty();
    }

    // ------------------------------------------------------------------ helpers

    /**
     * decrypt() must return null (or throw) - and if it ever returns a string, it must not be a
     * fragment of the plaintext.
     */
    private function decryptNeverPartial(CmsService $cms, string $der, Certificate $cert, string $key): ?string
    {
        try {
            $r = $cms->decrypt($der, $cert, $key);
        } catch (CryptoException $e) {
            self::assertNotSame('', $e->getUserLabel());
            return null;
        }
        if ($r !== null) {
            self::fail('decrypt of corrupted/foreign ciphertext returned data (' . strlen($r) . ' bytes)');
        }
        return null;
    }

    private static function phpHasLegacyProvider(): bool
    {
        [$r] = OpenSsl::run(static fn () => openssl_encrypt('probe', 'rc2-40-cbc', 'key', 0, '12345678'));
        return is_string($r) && $r !== '';
    }

    private function assertTempEmpty(): void
    {
        $dir = $this->base . '/mimeshield';
        if (!file_exists($dir)) {
            // operation rejected before any temp file was needed
            self::assertFileDoesNotExist($dir);
            return;
        }
        self::assertDirectoryExists($dir);
        $left = array_values(array_diff((array) scandir($dir), ['.', '..']));
        self::assertSame([], $left, 'SecureTemp left files behind');
    }

    private function cmsPrint(string $der): string
    {
        $f = $this->put('print-' . bin2hex(random_bytes(4)) . '.der', $der);
        [$rc, $out, $err] = self::openssl(['cms', '-cmsout', '-print', '-inform', 'DER', '-in', $f]);
        self::assertSame(0, $rc, $err);
        return $out;
    }

    private function cliSignOpaque(string $content): string
    {
        $in = $this->put('opaque-in.bin', $content);
        $out = $this->work . '/opaque.der';
        [$rc, , $err] = self::openssl(['cms', '-sign', '-nodetach', '-binary', '-in', $in, '-signer', TestPki::path('alice.crt'),
            '-inkey', TestPki::path('alice.key'), '-outform', 'DER', '-out', $out]);
        self::assertSame(0, $rc, $err);
        return (string) file_get_contents($out);
    }

    /**
     * @param list<string> $opts
     * @param list<string> $recipients
     */
    private function cliEncrypt(string $content, array $opts, array $recipients): string
    {
        $in = $this->put('enc-in.bin', $content);
        $out = $this->work . '/enc-' . bin2hex(random_bytes(4)) . '.der';
        $args = array_merge(['cms', '-encrypt', '-binary'], $opts, ['-in', $in, '-outform', 'DER', '-out', $out]);
        foreach ($recipients as $r) {
            $args[] = TestPki::path($r . '.crt');
        }
        [$rc, , $err] = self::openssl($args);
        self::assertSame(0, $rc, $err);
        return (string) file_get_contents($out);
    }

    private function put(string $name, string $data): string
    {
        $p = $this->work . '/' . $name;
        file_put_contents($p, $data);
        return $p;
    }

    /**
     * @param list<string> $args
     *
     * @return array{0: int, 1: string, 2: string}
     */
    private static function openssl(array $args): array
    {
        $p = proc_open(array_merge([self::OPENSSL], $args), [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($p);
        fclose($pipes[0]);
        $out = (string) stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        return [proc_close($p), $out, $err];
    }

    private static function rmTree(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach ((array) scandir($dir) as $f) {
            if ($f === '.' || $f === '..') {
                continue;
            }
            $p = $dir . '/' . $f;
            is_dir($p) && !is_link($p) ? self::rmTree($p) : @unlink($p);
        }
        @rmdir($dir);
    }
}
