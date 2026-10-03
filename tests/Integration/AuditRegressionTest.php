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

    /**
     * Audit MS-05: a shrouded key bag with an excessive iteration count hidden INSIDE an encrypted
     * SafeContents layer (outer layer: 2048 iterations) is rejected before OpenSSL runs any KDF.
     */
    public function testExpensiveKeyBagHiddenInEncryptedLayerIsRejected(): void
    {
        $pfx = $this->pfxWithEncryptedKeyBag(2500000, 'outer-pass');

        KdfInspector::check($pfx, 'p12invalid');   // without the password the inner layer is opaque
        $t = microtime(true);
        try {
            KdfInspector::check($pfx, 'p12invalid', 'outer-pass');
            self::fail('expected rejection');
        } catch (ValidationException $e) {
            self::assertSame('p12invalid', $e->getUserLabel());
            self::assertStringContainsString('KDF', $e->getMessage());
        }
        try {
            (new KeyImporter())->import($pfx, 'outer-pass');
            self::fail('expected rejection');
        } catch (ValidationException $e) {
            self::assertSame('p12invalid', $e->getUserLabel());
            self::assertStringContainsString('KDF', $e->getMessage());
        }
        self::assertLessThan(2.0, microtime(true) - $t, 'the hidden KDF must never run');

        // a wrong password cannot open the layer: reported as such, cheaply
        try {
            KdfInspector::check($pfx, 'p12invalid', 'wrong');
            self::fail('expected rejection');
        } catch (ValidationException $e) {
            self::assertSame('badpassword', $e->getUserLabel());
        }
    }

    /**
     * Audit MS-05 (follow-up): the inspector runs the KDF of an encrypted layer itself, so an iteration
     * count that is not a positive INTEGER (never counted in the budget) must be rejected before the
     * derivation loop - neither an unbounded loop (PKCS#12 PBE) nor an uncaught error (PBES2).
     */
    public function testEncryptedLayerWithNonIntegerIterationCountIsRejected(): void
    {
        $seq = static fn (string ...$c): string => Asn1::encode("\x30", implode('', $c));
        $oid = static function (string $dotted): string {
            $parts = array_map('intval', explode('.', $dotted));
            $body = chr(40 * $parts[0] + $parts[1]);
            foreach (array_slice($parts, 2) as $n) {
                $enc = chr($n & 0x7F);
                for ($n >>= 7; $n > 0; $n >>= 7) {
                    $enc = chr(0x80 | ($n & 0x7F)) . $enc;
                }
                $body .= $enc;
            }
            return Asn1::encode("\x06", $body);
        };
        $octets = static fn (string $c): string => Asn1::encode("\x04", $c);
        $explicit0 = static fn (string $c): string => Asn1::encode("\xA0", $c);
        $badIterations = $octets("\x08\x00");   // OCTET STRING instead of INTEGER

        $algorithms = [
            'pkcs12-pbe' => $seq($oid('1.2.840.113549.1.12.1.3'), $seq($octets('saltsalt'), $badIterations)),
            'pbes2' => $seq($oid('1.2.840.113549.1.5.13'), $seq(
                $seq($oid('1.2.840.113549.1.5.12'), $seq($octets('saltsalt'), $badIterations)),
                $seq($oid('2.16.840.1.101.3.4.1.42'), $octets(str_repeat("\x00", 16))),
            )),
        ];
        foreach ($algorithms as $name => $alg) {
            $eci = $seq($oid('1.2.840.113549.1.7.1'), $alg, Asn1::encode("\x80", str_repeat("\x11", 32)));
            $contentInfo = $seq($oid('1.2.840.113549.1.7.6'), $explicit0($seq(Asn1::encode("\x02", "\x00"), $eci)));
            $pfx = $seq(Asn1::encode("\x02", "\x03"), $seq($oid('1.2.840.113549.1.7.1'), $explicit0($octets($seq($contentInfo)))));
            $t = microtime(true);
            try {
                KdfInspector::check($pfx, 'p12invalid', 'any-password');
                self::fail($name . ': expected rejection');
            } catch (ValidationException $e) {
                self::assertSame('p12invalid', $e->getUserLabel(), $name);
                self::assertStringContainsString('KDF', $e->getMessage(), $name);
            }
            self::assertLessThan(1.0, microtime(true) - $t, $name . ': no key derivation may run');
        }
    }

    /**
     * Audit F-03: an authSafe OCTET STRING encoded as BER segments (each segment alone is not DER) is
     * inspected on the joined content - the expensive key bag inside is found and rejected before
     * OpenSSL runs anything.
     */
    public function testSegmentedBerAuthSafeIsInspectedOnTheJoinedContent(): void
    {
        [$seq, $oid, $octets, $int, $explicit0] = self::builders();
        $epki = $seq(
            $seq($oid('1.2.840.113549.1.5.13'), $seq(
                $seq($oid('1.2.840.113549.1.5.12'), $seq($octets('saltsalt'), $int(2500000))),
                $seq($oid('2.16.840.1.101.3.4.1.42'), $octets(str_repeat("\x00", 16))),
            )),
            $octets(str_repeat("\x11", 64)),
        );
        $safeContents = $seq($seq($oid('1.2.840.113549.1.12.10.1.2'), $explicit0($epki)));
        $authSafe = $seq($seq($oid('1.2.840.113549.1.7.1'), $explicit0($octets($safeContents))));
        // constructed OCTET STRING (0x24): three segments split at points where no segment is DER
        $segments = '';
        foreach (str_split($authSafe, intdiv(strlen($authSafe), 3) + 1) as $chunk) {
            $segments .= Asn1::encode("\x04", $chunk);
        }
        $pfx = $seq($int(3), $seq($oid('1.2.840.113549.1.7.1'), $explicit0(Asn1::encode("\x24", $segments))));

        $t = microtime(true);
        foreach ([null, 'any-password'] as $password) {
            try {
                KdfInspector::check($pfx, 'p12invalid', $password);
                self::fail('expected rejection');
            } catch (ValidationException $e) {
                self::assertSame('p12invalid', $e->getUserLabel());
                self::assertStringContainsString('KDF', $e->getMessage());
            }
        }
        try {
            (new KeyImporter())->import($pfx, 'any-password');
            self::fail('expected rejection');
        } catch (ValidationException $e) {
            self::assertSame('p12invalid', $e->getUserLabel());
        }
        self::assertLessThan(1.0, microtime(true) - $t, 'no key derivation may run');
    }

    /** F-03: benign segmented BER stays compatible with the native parser at normal KDF cost. */
    public function testNormalSegmentedBerPkcs12ImportsTheSameCertificate(): void
    {
        $original = TestPki::read('alice.p12');
        $pfx = Asn1::parse($original, true, true)->children();
        $ci = $pfx[1]->children();
        $content = $ci[1]->child(0)->content();
        $segments = '';
        foreach (str_split($content, 37) as $chunk) {
            $segments .= Asn1::encode("\x04", $chunk);
        }
        $expected = (new KeyImporter())->import($original, TestPki::PASSWORD)->certificate->fingerprint;
        foreach ([Asn1::encode("\x24", $segments), "\x24\x80" . $segments . "\x00\x00"] as $octets) {
            $segmented = Asn1::encode("\x30", $pfx[0]->raw()
                . Asn1::encode("\x30", $ci[0]->raw() . Asn1::encode("\xA0", $octets))
                . $pfx[2]->raw());
            $imported = (new KeyImporter())->import($segmented, TestPki::PASSWORD);
            self::assertSame($expected, $imported->certificate->fingerprint);
        }
    }

    /**
     * Audit F-03: content the PFX schema requires to be DER but that does not parse is refused
     * (fail closed), never skipped as "opaque".
     */
    public function testUnparsableAuthSafeContentIsRefused(): void
    {
        [$seq, $oid, $octets, $int, $explicit0] = self::builders();
        foreach (["\x30\x84garbage", 'not DER at all', ''] as $content) {
            $pfx = $seq($int(3), $seq($oid('1.2.840.113549.1.7.1'), $explicit0($octets($content))));
            try {
                KdfInspector::check($pfx, 'p12invalid');
                self::fail('expected rejection');
            } catch (ValidationException $e) {
                self::assertSame('p12invalid', $e->getUserLabel());
                self::assertStringContainsString('not inspectable', $e->getMessage());
            }
        }
        // a content type the inspector cannot look into (e.g. envelopedData) is refused too
        $pfx = $seq($int(3), $seq($oid('1.2.840.113549.1.7.1'), $explicit0($octets($seq(
            $seq($oid('1.2.840.113549.1.7.3'), $explicit0($seq($int(0))))
        )))));
        $this->expectException(ValidationException::class);
        KdfInspector::check($pfx, 'p12invalid');
    }

    /**
     * Audit F-08: the PKCS#12 PBE derivation the inspector runs in PHP is bounded by its real work
     * (iterations x output blocks x password encodings), not only by the declared iterations.
     */
    public function testPhpKeyDerivationWorkIsBounded(): void
    {
        [$seq, $oid, $octets, $int, $explicit0] = self::builders();
        $password = 'zażółć';   // non-ASCII: two password encodings are tried
        $iter = 1500000;        // declared total 3 000 000 (< MAX_TOTAL_ITERATIONS)
        $kdf = new \ReflectionMethod(KdfInspector::class, 'pkcs12Kdf');
        $bmp = mb_convert_encoding($password, 'UTF-16BE', 'UTF-8') . "\x00\x00";
        $salt = random_bytes(8);
        $inner = $seq($seq($oid('1.2.840.113549.1.12.10.1.3'), $explicit0($seq($oid('1.2.840.113549.1.9.22.1'), $explicit0($octets('x'))))));
        $ct = (string) openssl_encrypt($inner, 'des-ede3-cbc', (string) $kdf->invoke(null, $bmp, $salt, 1, $iter, 24),
            OPENSSL_RAW_DATA, (string) $kdf->invoke(null, $bmp, $salt, 2, $iter, 8));
        $layer = $seq($oid('1.2.840.113549.1.7.6'), $explicit0($seq($int(0), $seq(
            $oid('1.2.840.113549.1.7.1'),
            $seq($oid('1.2.840.113549.1.12.1.3'), $seq($octets($salt), $int($iter))),
            Asn1::encode("\x80", $ct),
        ))));
        $pfx = $seq($int(3), $seq($oid('1.2.840.113549.1.7.1'), $explicit0($octets($seq($layer, $layer)))));

        // one layer: 1.5M x 3 blocks x 2 encodings = 9M <= budget; the second one exceeds it
        self::assertLessThanOrEqual(KdfInspector::MAX_PHP_KDF_WORK, $iter * 3 * 2);
        self::assertGreaterThan(KdfInspector::MAX_PHP_KDF_WORK, 2 * $iter * 3 * 2);
        try {
            KdfInspector::check($pfx, 'p12invalid', $password);
            self::fail('expected rejection');
        } catch (ValidationException $e) {
            self::assertSame('p12invalid', $e->getUserLabel());
            self::assertStringContainsString('work budget', $e->getMessage());
        }
    }

    /**
     * @return array{0: \Closure, 1: \Closure, 2: \Closure, 3: \Closure, 4: \Closure}
     */
    private static function builders(): array
    {
        $seq = static fn (string ...$c): string => Asn1::encode("\x30", implode('', $c));
        $oid = static function (string $dotted): string {
            $parts = array_map('intval', explode('.', $dotted));
            $body = chr(40 * $parts[0] + $parts[1]);
            foreach (array_slice($parts, 2) as $n) {
                $enc = chr($n & 0x7F);
                for ($n >>= 7; $n > 0; $n >>= 7) {
                    $enc = chr(0x80 | ($n & 0x7F)) . $enc;
                }
                $body .= $enc;
            }
            return Asn1::encode("\x06", $body);
        };
        $octets = static fn (string $c): string => Asn1::encode("\x04", $c);
        $int = static function (int $n): string {
            $b = ltrim(pack('J', $n), "\x00");
            $b = $b === '' ? "\x00" : ((ord($b[0]) & 0x80) ? "\x00" . $b : $b);
            return Asn1::encode("\x02", $b);
        };
        $explicit0 = static fn (string $c): string => Asn1::encode("\xA0", $c);
        return [$seq, $oid, $octets, $int, $explicit0];
    }

    public function testNormalKeyBagInEncryptedLayerPassesTheInspection(): void
    {
        $pfx = $this->pfxWithEncryptedKeyBag(2048, 'outer-pass');
        KdfInspector::check($pfx, 'p12invalid', 'outer-pass');
        $this->addToAssertionCount(1);
    }

    /**
     * PFX whose only content is an EncryptedData (PBES2: PBKDF2-SHA256 2048 + AES-256-CBC) holding a
     * SafeContents with one pkcs8ShroudedKeyBag encrypted with $innerIterations (MAC not valid: the
     * inspection runs before OpenSSL).
     */
    private function pfxWithEncryptedKeyBag(int $innerIterations, string $password): string
    {
        $k = escapeshellarg(TestPki::path('alice.key'));
        $f = $this->tmp . '/inner-' . $innerIterations . '.der';
        $this->sh("openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -iter $innerIterations -in $k -passout pass:inner -outform DER -out " . escapeshellarg($f));
        $epki = (string) file_get_contents($f);

        $seq = static fn (string ...$c): string => Asn1::encode("\x30", implode('', $c));
        $oid = static function (string $dotted): string {
            $parts = array_map('intval', explode('.', $dotted));
            $body = chr(40 * $parts[0] + $parts[1]);
            foreach (array_slice($parts, 2) as $n) {
                $enc = chr($n & 0x7F);
                for ($n >>= 7; $n > 0; $n >>= 7) {
                    $enc = chr(0x80 | ($n & 0x7F)) . $enc;
                }
                $body .= $enc;
            }
            return Asn1::encode("\x06", $body);
        };
        $octets = static fn (string $c): string => Asn1::encode("\x04", $c);
        $int = static fn (int $n): string => Asn1::encode("\x02", ltrim(pack('N', $n), "\x00") === '' ? "\x00" : (ord(ltrim(pack('N', $n), "\x00")[0]) & 0x80 ? "\x00" : '') . ltrim(pack('N', $n), "\x00"));
        $explicit0 = static fn (string $c): string => Asn1::encode("\xA0", $c);

        $bag = $seq($oid('1.2.840.113549.1.12.10.1.2'), $explicit0($epki));
        $safeContents = $seq($bag);

        $salt = random_bytes(8);
        $iv = random_bytes(16);
        $key = openssl_pbkdf2($password, $salt, 32, 2048, 'sha256');
        $ct = (string) openssl_encrypt($safeContents, 'aes-256-cbc', (string) $key, OPENSSL_RAW_DATA, $iv);
        $alg = $seq($oid('1.2.840.113549.1.5.13'), $seq(
            $seq($oid('1.2.840.113549.1.5.12'), $seq($octets($salt), $int(2048), $seq($oid('1.2.840.113549.2.9'), "\x05\x00"))),
            $seq($oid('2.16.840.1.101.3.4.1.42'), $octets($iv)),
        ));
        $encryptedContentInfo = $seq($oid('1.2.840.113549.1.7.1'), $alg, Asn1::encode("\x80", $ct));
        $contentInfo = $seq($oid('1.2.840.113549.1.7.6'), $explicit0($seq($int(0), $encryptedContentInfo)));
        $authSafe = $seq($oid('1.2.840.113549.1.7.1'), $explicit0($octets($seq($contentInfo))));
        $macData = $seq($seq($seq($oid('2.16.840.1.101.3.4.2.1'), "\x05\x00"), $octets(str_repeat("\x00", 32))), $octets(random_bytes(8)), $int(2048));
        return $seq($int(3), $authSafe, $macData);
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

    /**
     * F-03 (Stage 6 pass 05): a key encryption scheme whose cost parameters are not understood is
     * refused instead of being passed to OpenSSL uninspected; every PKCS#5 PBES1 variant is counted,
     * and a PBKDF2 keyLength beyond any supported key or MAC size is refused.
     */
    public function testUninspectableKeyEncryptionSchemesAreRefused(): void
    {
        [$seq, $oid, $octets, $int] = self::builders();
        $pkcs8 = static fn (string $alg): string => $seq($alg, $octets(str_repeat("\x00", 32)));
        $pbkdf2 = static fn (int $iter, ?int $keyLength = null): string => $seq($oid('1.2.840.113549.1.5.12'), $seq(
            $octets(str_repeat("\x01", 8)),
            $int($iter),
            ...($keyLength !== null ? [$int($keyLength)] : []),
        ));
        $pbes2 = static fn (string $kdf): string => $seq($oid('1.2.840.113549.1.5.13'), $seq(
            $kdf,
            $seq($oid('2.16.840.1.101.3.4.1.42'), $octets(str_repeat("\x02", 16))),
        ));
        $refused = static function (string $der, string $label, string $message): void {
            try {
                KdfInspector::check($der, 'keyinvalid');
                self::fail('expected rejection: ' . $message);
            } catch (ValidationException $e) {
                self::assertSame($label, $e->getUserLabel(), $message);
                self::assertStringContainsString($message, $e->getMessage());
            }
        };

        // PBES1 with MD2 (pbeWithMD2AndDES-CBC / -RC2-CBC): the iteration count is inspected
        foreach (['1.2.840.113549.1.5.1', '1.2.840.113549.1.5.4'] as $pbes1) {
            $refused($pkcs8($seq($oid($pbes1), $seq($octets(str_repeat("\x01", 8)), $int(1 << 30)))), 'keyinvalid', 'KDF');
        }
        // unknown scheme, or PBES2 with an unknown key derivation function
        $refused($pkcs8($seq($oid('1.2.3.4.5'), $seq($octets(str_repeat("\x01", 8)), $int(1 << 30)))), 'keyinvalid', 'unsupported key encryption algorithm');
        $refused($pkcs8($pbes2($seq($oid('1.2.3.4.6'), $seq($octets(str_repeat("\x01", 8)), $int(1 << 30))))), 'keyinvalid', 'unsupported key encryption algorithm');
        // PBKDF2 keyLength far beyond any cipher key / HMAC output
        $refused($pkcs8($pbes2($pbkdf2(2048, 1 << 20))), 'keyinvalid', 'KDF');

        // ordinary PBES2/PBKDF2 (with and without an explicit AES-256 keyLength) still passes
        KdfInspector::check($pkcs8($pbes2($pbkdf2(2048))), 'keyinvalid');
        KdfInspector::check($pkcs8($pbes2($pbkdf2(2048, 32))), 'keyinvalid');
        $this->addToAssertionCount(2);
    }

    /**
     * F-03 (Stage 6 pass 05): inside a PKCS#12, a shrouded key bag with an unknown scheme is not
     * handed to the in-process OpenSSL parser ('p12legacy': only the optional, time-limited converter
     * process may try it).
     */
    public function testUnknownSchemeInPkcs12KeyBagIsNotPassedToOpenSsl(): void
    {
        [$seq, $oid, $octets, $int, $explicit0] = self::builders();
        $epki = $seq($seq($oid('1.2.3.4.5'), $seq($octets(str_repeat("\x01", 8)), $int(1 << 30))), $octets(str_repeat("\x00", 32)));
        $safeContents = $seq($seq($oid('1.2.840.113549.1.12.10.1.2'), $explicit0($epki)));
        $authSafe = $seq($oid('1.2.840.113549.1.7.1'), $explicit0($octets($seq(
            $seq($oid('1.2.840.113549.1.7.1'), $explicit0($octets($safeContents))),
        ))));
        try {
            KdfInspector::check($seq($int(3), $authSafe), 'p12invalid', 'any');
            self::fail('expected rejection');
        } catch (ValidationException $e) {
            self::assertSame('p12legacy', $e->getUserLabel());
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

    /**
     * Audit MS-13: trust store and master key source are built from the protected configuration -
     * a user preference named like the administrator option never changes them.
     */
    public function testUserPreferenceCannotChangeTrustAnchorsOrMasterKeySource(): void
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
        $injected = [
            'mimeshield_ca_bundle' => [TestPki::path('rogue.crt')],
            'mimeshield_use_system_ca' => true,
            'mimeshield_master_key_file' => $this->tmp . '/attacker.key',
        ];
        $rc->values = $injected;   // Roundcube merges user preferences over the configuration

        $protected = new Config($rc, $injected);
        $store = TrustStore::fromConfig($protected);
        self::assertNotContains(TestPki::path('rogue.crt'), $store->caInfo());
        self::assertFalse($store->isAnchor(TestPki::cert('rogue')));
        $mk = \MimeShield\KeyStore\MasterKeyProvider::fromConfig($protected);
        self::assertStringNotContainsString('attacker.key', (new \ReflectionProperty($mk, 'file'))->getValue($mk));

        // the same values set by the administrator (not a user preference) are used
        $admin = new Config($rc, []);
        self::assertContains(TestPki::path('rogue.crt'), TrustStore::fromConfig($admin)->caInfo());
    }

    /**
     * Audit MS-07: the system (TLS) CA bundle is not trusted for S/MIME unless configured.
     */
    public function testSystemCaStoreIsNotTrustedByDefault(): void
    {
        self::assertFalse(Config::DEFAULTS['mimeshield_use_system_ca']);
        $rc = new class () extends \rcube_config {
            public function __construct()
            {
            }

            public function get($name, $def = null)
            {
                return $def;
            }
        };
        self::assertSame([], TrustStore::fromConfig(new Config($rc))->caInfo());
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
