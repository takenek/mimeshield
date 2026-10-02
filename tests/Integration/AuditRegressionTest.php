<?php

declare(strict_types=1);

namespace MimeShield\Tests\Integration;

use MimeShield\Cert\Certificate;
use MimeShield\Cert\KdfInspector;
use MimeShield\Cert\KeyImporter;
use MimeShield\Config;
use MimeShield\Crypto\Asn1;
use MimeShield\Crypto\CmsInspector;
use MimeShield\Crypto\CmsService;
use MimeShield\Exception\CryptoException;
use MimeShield\Exception\ValidationException;
use MimeShield\Service\SignatureVerifier;
use MimeShield\Tests\TestPki;
use MimeShield\Trust\AddressMatcher;
use MimeShield\Trust\ChainValidator;
use MimeShield\Trust\RevocationChecker;
use MimeShield\Trust\TrustStore;
use MimeShield\Trust\VerificationResult;
use PHPUnit\Framework\TestCase;

/**
 * Regression tests for the findings of the 30-point security audit.
 */
final class AuditRegressionTest extends TestCase
{
    private string $tmp;

    protected function setUp(): void
    {
        if (!MIMESHIELD_RC_LOADED) {
            self::markTestSkipped('needs MIMESHIELD_RC');
        }
        $this->tmp = TestPki::tempDir();
    }

    protected function tearDown(): void
    {
        if (isset($this->tmp) && is_dir($this->tmp)) {
            exec('rm -rf ' . escapeshellarg($this->tmp));
        }
    }

    private function sh(string $cmd): void
    {
        exec($cmd . ' 2>&1', $out, $rc);
        self::assertSame(0, $rc, $cmd . "\n" . implode("\n", $out));
    }

    // #12: KDF cost parameters are checked before OpenSSL runs them

    public function testPkcs12WithHugeIterationCountIsRejectedQuickly(): void
    {
        $p = escapeshellarg(TestPki::path('alice.crt'));
        $k = escapeshellarg(TestPki::path('alice.key'));
        $f = $this->tmp . '/big.p12';
        $this->sh("openssl pkcs12 -export -in $p -inkey $k -passout pass:x -iter 2500000 -out " . escapeshellarg($f));
        $t = microtime(true);
        try {
            (new KeyImporter())->import((string) file_get_contents($f), 'wrong-password');
            self::fail('expected rejection');
        } catch (ValidationException $e) {
            self::assertSame('p12invalid', $e->getUserLabel());
            self::assertStringContainsString('KDF', $e->getMessage());
        }
        self::assertLessThan(1.0, microtime(true) - $t, 'must not run the KDF');
    }

    public function testPkcs8WithExpensiveScryptIsRejected(): void
    {
        $k = escapeshellarg(TestPki::path('alice.key'));
        $f = $this->tmp . '/scrypt.pem';
        $this->sh("openssl pkcs8 -topk8 -in $k -scrypt -scrypt_N 16384 -scrypt_r 8 -scrypt_p 16 -passout pass:x -out " . escapeshellarg($f));
        $bundle = TestPki::read('alice.crt') . file_get_contents($f);
        try {
            (new KeyImporter())->import($bundle, 'x');
            self::fail('expected rejection');
        } catch (ValidationException $e) {
            self::assertSame('keyinvalid', $e->getUserLabel());
        }
    }

    public function testNormalPkcs12FilesStillImport(): void
    {
        foreach (['alice.p12', 'alice-3des.p12', 'carol.p12'] as $f) {
            KdfInspector::check(TestPki::read($f), 'p12invalid');
            $r = (new KeyImporter())->import(TestPki::read($f), TestPki::PASSWORD);
            self::assertNotSame('', $r->certificate->fingerprint);
        }
    }

    // #24 / A: administrator locks cannot be overridden by user preferences

    public function testLockedOptionUsesAdministratorValueNotUserPreference(): void
    {
        $rc = new class () extends \rcube_config {
            /** @var array<string, mixed> */
            public array $values = [];

            public function __construct()
            {
            }

            public function get($name, $def = null)
            {
                return array_key_exists($name, $this->values) ? $this->values[$name] : $def;
            }
        };
        $rc->values = [
            'mimeshield_encrypt_default' => true,
            'mimeshield_options_lock' => ['encrypt'],
            'mimeshield_pref_encrypt' => false,     // user tried to switch it off
            'mimeshield_pref_sign' => true,
        ];
        $cfg = new Config($rc);
        self::assertTrue($cfg->isLocked('encrypt'));
        self::assertTrue($cfg->optionDefault('encrypt'));
        self::assertFalse($cfg->isLocked('sign'));
        self::assertTrue($cfg->optionDefault('sign'), 'unlocked options follow the user preference');
    }

    // #25: unparsable From entries never count as verified

    public function testUnparsableFromAddressMakesIdentityMismatch(): void
    {
        $r = AddressMatcher::parseListStrict('alice@example.test, "Chef" <jörg@bank.example>', false);
        self::assertSame(['alice@example.test'], $r['valid']);
        self::assertNotSame([], $r['invalid']);

        $cms = new CmsService($this->tmp);
        $content = "Content-Type: text/plain\r\n\r\nhello\r\n";
        $sig = $cms->signDetached($content, TestPki::cert('alice'), TestPki::key('alice'), [TestPki::read('int.crt')]);
        $ts = new TrustStore([TestPki::path('root.crt')], false);
        $v = new SignatureVerifier(new ChainValidator($ts, $this->tmp), $ts, new RevocationChecker('off', null, ''));
        $check = $cms->verifyDetached($content, $sig);

        self::assertSame(VerificationResult::IDENTITY_MATCH, $v->evaluate($check, $r['valid'], [])->identity);
        $res = $v->evaluate($check, $r['valid'], [], false, null, $r['invalid']);
        self::assertSame(VerificationResult::IDENTITY_MISMATCH, $res->identity);
        self::assertSame(VerificationResult::LEVEL_ERROR, $res->level());
    }

    // #23: AES-GCM authentication tags shorter than 12 bytes / inconsistent ICVlen are refused

    public function testTruncatedGcmTagIsRejected(): void
    {
        $in = $this->tmp . '/in.txt';
        file_put_contents($in, "Content-Type: text/plain\r\n\r\nsecret\r\n");
        $der = $this->tmp . '/gcm.der';
        $this->sh('openssl cms -encrypt -binary -aes-256-gcm -outform DER -in ' . escapeshellarg($in) . ' -out ' . escapeshellarg($der) . ' ' . escapeshellarg(TestPki::path('alice.crt')));
        $orig = (string) file_get_contents($der);

        $cms = new CmsService($this->tmp);
        self::assertSame((string) file_get_contents($in), $cms->decrypt($orig, TestPki::cert('alice'), TestPki::key('alice')));

        // shorten the mac OCTET STRING to 4 bytes (the last child of AuthEnvelopedData)
        $root = Asn1::parse($orig);
        $aed = $root->child(1)->child(0);
        $children = $aed->children();
        $macIdx = count($children) - 1;
        self::assertTrue($children[$macIdx]->isUniversal(Asn1::TAG_OCTET_STRING));
        $short = Asn1::encode("\x04", substr($children[$macIdx]->content(), 0, 4));
        $tampered = Asn1::replaceAt($root, [1, 0, $macIdx], $short);
        self::assertSame(4, CmsInspector::envelopedData($tampered)['macLength']);

        $this->expectException(CryptoException::class);
        $cms->decrypt($tampered, TestPki::cert('alice'), TestPki::key('alice'));
    }

    // re-audit #23: the tag check must not fail open when another field is unusual

    public function testGcmTagCheckFailsClosedWithDecoyRecipient(): void
    {
        $in = $this->tmp . '/in.txt';
        file_put_contents($in, "Content-Type: text/plain\r\n\r\nsecret\r\n");
        $der = $this->tmp . '/gcm.der';
        $this->sh('openssl cms -encrypt -binary -aes-256-gcm -outform DER -in ' . escapeshellarg($in) . ' -out ' . escapeshellarg($der) . ' ' . escapeshellarg(TestPki::path('alice.crt')));
        $root = Asn1::parse((string) file_get_contents($der));
        $aed = $root->child(1)->child(0);
        $f = $aed->children();
        $riIdx = 1;
        // decoy KeyTransRecipientInfo with an OID arc > 2^63 (OpenSSL skips it, our inspector cannot decode it)
        $issuer = TestPki::cert('alice')->issuerNameDer;
        $decoy = Asn1::encode("\x30", "\x02\x01\x00"
            . Asn1::encode("\x30", $issuer . "\x02\x03\x7F\x7E\x7D")
            . Asn1::encode("\x30", "\x06\x0C\x2A" . str_repeat("\xFF", 10) . "\x7F" . "\x05\x00")
            . Asn1::encode("\x04", str_repeat('A', 256)));
        $set = Asn1::encode("\x31", $f[$riIdx]->content() . $decoy);
        $withDecoy = Asn1::replaceAt($root, [1, 0, $riIdx], $set);
        $root2 = Asn1::parse($withDecoy);
        $f2 = $root2->child(1)->child(0)->children();
        $macIdx = count($f2) - 1;
        $tampered = Asn1::replaceAt($root2, [1, 0, $macIdx], Asn1::encode("\x04", substr($f2[$macIdx]->content(), 0, 4)));

        self::assertSame(4, CmsInspector::gcmTagInfo($tampered)['macLength']);
        $this->expectException(CryptoException::class);
        (new CmsService($this->tmp))->decrypt($tampered, TestPki::cert('alice'), TestPki::key('alice'));
    }

    // re-audit #25: address lists are read with the header charset Roundcube displays them with

    public function testFromIsParsedWithHeaderCharset(): void
    {
        $withCharset = AddressMatcher::parseListStrict('Alice <alice@example.test>, ceo+AEA-bank.example', true, 'UTF-7');
        $withoutCharset = AddressMatcher::parseListStrict('Alice <alice@example.test>, ceo+AEA-bank.example', true, null);
        self::assertNotSame($withCharset['valid'], $withoutCharset['valid'], 'the two readings differ - the processor treats the difference as unverifiable');
    }

    // re-audit #24: a stale user preference stored under an administrator key is ignored

    public function testStaleUserPreferenceUnderAdminKeyIsIgnored(): void
    {
        $rc = new class () extends \rcube_config {
            /** @var array<string, mixed> */
            public array $values = [];

            public function __construct()
            {
            }

            public function get($name, $def = null)
            {
                return array_key_exists($name, $this->values) ? $this->values[$name] : $def;
            }
        };
        // merged view as Roundcube builds it: the user preference overrides the admin value
        $rc->values = ['mimeshield_encrypt_default' => true, 'mimeshield_options_lock' => ['encrypt']];
        $cfg = new Config($rc, ['mimeshield_encrypt_default' => true, 'mimeshield_options_lock' => ['encrypt']]);
        // the real administrator configuration (no mimeshield options in the test installation) wins
        self::assertSame([], $cfg->optionsLock());
        self::assertFalse($cfg->optionDefault('encrypt'));
    }

    // #30: deeply nested BER constructed strings cannot exhaust recursion/memory

    public function testDeeplyNestedConstructedOctetStringIsRejected(): void
    {
        $leaf = "\x04\x01A";
        $s = $leaf;
        for ($i = 0; $i < 20; $i++) {
            $s = "\x24\x80" . $s . "\x00\x00";
        }
        $node = Asn1::parse($s, false, true);
        $t = microtime(true);
        try {
            $node->content();
            self::fail('expected rejection');
        } catch (ValidationException $e) {
            self::assertStringContainsString('nested too deeply', $e->getMessage());
        }
        self::assertLessThan(0.5, microtime(true) - $t);

        // one level (what real encoders produce) still works
        self::assertSame('AB', Asn1::parse("\x24\x80\x04\x01A\x04\x01B\x00\x00", false, true)->content());
    }

    // hardening: certificate names cannot spoof the display with control / bidi characters

    public function testDisplaySafeNeutralisesControlAndBidiCharacters(): void
    {
        $s = Certificate::displaySafe("Alice\nIssuer: Trusted\u{202E}gpj.exe\u{2066}\x1b[31m");
        self::assertStringNotContainsString("\n", $s);
        self::assertStringNotContainsString("\u{202E}", $s);
        self::assertStringNotContainsString("\u{2066}", $s);
        self::assertStringNotContainsString("\x1b", $s);
        self::assertStringContainsString('Alice', $s);
    }
}
