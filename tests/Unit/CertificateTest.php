<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Cert\Certificate;
use MimeShield\Crypto\Asn1;
use MimeShield\Exception\ValidationException;
use MimeShield\Tests\TestPki;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CertificateTest extends TestCase
{
    private const OPENSSL = '/usr/bin/openssl';

    /** @var list<string> */
    private array $tempDirs = [];

    protected function tearDown(): void
    {
        foreach ($this->tempDirs as $d) {
            self::rmTree($d);
        }
        $this->tempDirs = [];
    }

    // ------------------------------------------------------------------ helpers

    /**
     * Run the openssl CLI (argument array, no shell). Returns [exit code, stdout, stderr].
     *
     * @param list<string> $args
     *
     * @return array{0: int, 1: string, 2: string}
     */
    private static function openssl(array $args, string $stdin = ''): array
    {
        $proc = proc_open(
            array_merge([self::OPENSSL], $args),
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            null,
            ['PATH' => '/usr/bin:/bin', 'LANG' => 'C']
        );
        self::assertIsResource($proc, 'cannot start openssl');
        fwrite($pipes[0], $stdin);
        fclose($pipes[0]);
        $out = (string) stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($proc);
        return [$code, $out, $err];
    }

    private static function opensslOk(array $args, string $stdin = ''): string
    {
        [$code, $out, $err] = self::openssl($args, $stdin);
        self::assertSame(0, $code, 'openssl ' . implode(' ', $args) . ' failed: ' . $err);
        return $out;
    }

    private function tempDir(): string
    {
        $d = TestPki::tempDir();
        $this->tempDirs[] = $d;
        return $d;
    }

    private static function rmTree(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (scandir($dir) ?: [] as $e) {
            if ($e === '.' || $e === '..') {
                continue;
            }
            $p = $dir . '/' . $e;
            is_dir($p) && !is_link($p) ? self::rmTree($p) : unlink($p);
        }
        rmdir($dir);
    }

    private static function expectLabel(string $label, callable $fn): ValidationException
    {
        try {
            $fn();
        } catch (ValidationException $e) {
            self::assertSame($label, $e->getUserLabel(), 'unexpected label; internal: ' . $e->getMessage());
            return $e;
        }
        self::fail('ValidationException(' . $label . ') expected');
    }

    private static function expectValidation(callable $fn): ValidationException
    {
        try {
            $fn();
        } catch (ValidationException $e) {
            // structural ASN.1 errors are reported as 'malformed', everything else as 'certinvalid'
            self::assertContains($e->getUserLabel(), ['certinvalid', 'malformed'], $e->getMessage());
            return $e;
        }
        self::fail('ValidationException expected');
    }

    // ------------------------------------------------------------------ alice: all fields

    public function testAliceSubjectAndIssuer(): void
    {
        $c = TestPki::cert('alice');
        self::assertSame('C=PL, O=MIME Shield TEST ONLY, CN=alice (TEST ONLY)', $c->subject);
        self::assertSame('C=PL, O=MIME Shield TEST ONLY, CN=MIME Shield Test Intermediate CA', $c->issuer);
        self::assertSame('alice (TEST ONLY)', $c->subjectParts['CN']);
        self::assertSame('PL', $c->subjectParts['C']);
        self::assertSame('MIME Shield Test Intermediate CA', $c->issuerParts['CN']);
        self::assertSame('alice (TEST ONLY)', $c->displayName());
        self::assertSame('MIME Shield Test Intermediate CA', $c->issuerDisplayName());
        self::assertFalse($c->isSelfIssued());
        self::assertFalse($c->isCa);
        self::assertSame('sha256WithRSAEncryption', $c->signatureAlgorithm);
    }

    public function testAliceSerialMatchesOpensslCli(): void
    {
        $out = self::opensslOk(['x509', '-in', TestPki::path('alice.crt'), '-noout', '-serial']);
        self::assertSame(1, preg_match('/^serial=([0-9A-F]+)\s*$/', $out, $m), $out);
        $c = TestPki::cert('alice');
        self::assertSame(strtoupper($m[1]), strtoupper($c->serialHex));
        self::assertMatchesRegularExpression('/^[0-9A-Fa-f]+$/', $c->serialHex);
    }

    public function testAliceFingerprintMatchesOpensslCli(): void
    {
        $out = self::opensslOk(['x509', '-in', TestPki::path('alice.crt'), '-noout', '-fingerprint', '-sha256']);
        self::assertSame(1, preg_match('/Fingerprint=([0-9A-F:]+)/i', $out, $m), $out);
        $expected = strtolower(str_replace(':', '', $m[1]));
        $c = TestPki::cert('alice');
        self::assertSame($expected, $c->fingerprint);
        self::assertSame(64, strlen($c->fingerprint));
        // fingerprint is over the DER encoding
        self::assertSame(hash('sha256', $c->der), $c->fingerprint);
    }

    public function testAliceValidityMatchesOpensslCli(): void
    {
        $out = self::opensslOk(['x509', '-in', TestPki::path('alice.crt'), '-noout', '-startdate', '-enddate']);
        self::assertSame(1, preg_match('/notBefore=(.+)/', $out, $nb));
        self::assertSame(1, preg_match('/notAfter=(.+)/', $out, $na));
        $c = TestPki::cert('alice');
        self::assertSame(strtotime(trim($nb[1])), $c->notBefore);
        self::assertSame(strtotime(trim($na[1])), $c->notAfter);
        self::assertTrue($c->isTimeValid($c->notBefore));
        self::assertTrue($c->isTimeValid($c->notAfter));
        self::assertFalse($c->isTimeValid($c->notAfter + 1));
        self::assertTrue($c->isExpired($c->notAfter + 1));
        self::assertTrue($c->isNotYetValid($c->notBefore - 1));
        self::assertFalse($c->isNotYetValid($c->notBefore));
    }

    public function testAliceEmailsKeyUsageAndEku(): void
    {
        $c = TestPki::cert('alice');
        self::assertSame(['alice@example.test'], $c->emails());
        self::assertSame(['alice@example.test'], $c->emails(false));
        self::assertSame(['alice@example.test'], $c->sanEmails);
        self::assertSame([], $c->rejectedEmails);
        self::assertFalse($c->usesLegacySubjectEmail());
        self::assertSame(['Digital Signature', 'Key Encipherment'], $c->keyUsageNames());
        self::assertSame(Certificate::KU_DIGITAL_SIGNATURE | Certificate::KU_KEY_ENCIPHERMENT, $c->keyUsage);
        self::assertSame(['E-mail Protection', 'TLS Web Client Authentication'], $c->extendedKeyUsageNames());
        self::assertSame([Certificate::EKU_EMAIL_PROTECTION, '1.3.6.1.5.5.7.3.2'], $c->extendedKeyUsage);
        self::assertTrue($c->allowsEmailProtection());
    }

    public function testAliceKeyIdentifiersMatchOpensslCli(): void
    {
        $text = self::opensslOk(['x509', '-in', TestPki::path('alice.crt'), '-noout', '-text']);
        self::assertSame(1, preg_match('/Subject Key Identifier:\s*\n\s*([0-9A-F:]+)/', $text, $ski));
        self::assertSame(1, preg_match('/Authority Key Identifier:\s*\n\s*(?:keyid:)?([0-9A-F:]+)/', $text, $aki));
        $c = TestPki::cert('alice');
        self::assertSame(str_replace(':', '', $ski[1]), $c->subjectKeyId);
        self::assertSame(str_replace(':', '', $aki[1]), $c->authorityKeyId);
        self::assertSame(TestPki::cert('int')->subjectKeyId, $c->authorityKeyId);
    }

    public function testKeyDescription(): void
    {
        self::assertSame('RSA 2048 bit', TestPki::cert('alice')->keyDescription());
        self::assertSame('RSA 3072 bit', TestPki::cert('bob')->keyDescription());
        $carol = TestPki::cert('carol');
        self::assertSame('EC prime256v1 (256 bit)', $carol->keyDescription());
        self::assertSame('EC', $carol->keyType);
        self::assertSame('prime256v1', $carol->curve);
        self::assertSame(256, $carol->keyBits);
        // carol is EC but signed by the RSA intermediate
        self::assertSame('sha256WithRSAEncryption', $carol->signatureAlgorithm);
    }

    public function testCarolKeyUsageAndEku(): void
    {
        $c = TestPki::cert('carol');
        self::assertSame(['Digital Signature', 'Key Agreement'], $c->keyUsageNames());
        self::assertSame(['E-mail Protection'], $c->extendedKeyUsageNames());
        self::assertSame(['carol@example.test'], $c->emails());
    }

    // ------------------------------------------------------------------ sign / encrypt matrix

    /**
     * @return iterable<string, array{0: string, 1: bool, 2: bool}>
     */
    public static function capabilityMatrix(): iterable
    {
        yield 'alice RSA sign+encrypt' => ['alice', true, true];
        yield 'bob RSA3072 sign+encrypt' => ['bob', true, true];
        yield 'carol EC: encrypt via keyAgreement' => ['carol', true, true];
        yield 'server: EKU serverAuth only' => ['server', false, false];
        yield 'signonly: KU digitalSignature only' => ['signonly', true, false];
        yield 'root CA' => ['root', false, false];
        yield 'intermediate CA' => ['int', false, false];
        yield 'rogue CA' => ['rogue', false, false];
    }

    #[DataProvider('capabilityMatrix')]
    public function testCanSignCanEncrypt(string $name, bool $sign, bool $encrypt): void
    {
        $c = TestPki::cert($name);
        self::assertSame($sign, $c->canSign(), $name . ' canSign');
        self::assertSame($encrypt, $c->canEncrypt(), $name . ' canEncrypt');
    }

    public function testCaFlags(): void
    {
        $root = TestPki::cert('root');
        self::assertTrue($root->isCa);
        self::assertTrue($root->isSelfIssued());
        self::assertSame(['Certificate Sign', 'CRL Sign'], $root->keyUsageNames());
        self::assertNull($root->extendedKeyUsage);
        self::assertSame([], $root->extendedKeyUsageNames());
        self::assertTrue(TestPki::cert('int')->isCa);
        self::assertFalse(TestPki::cert('int')->isSelfIssued());
    }

    public function testServerEkuNames(): void
    {
        $c = TestPki::cert('server');
        self::assertSame(['TLS Web Server Authentication'], $c->extendedKeyUsageNames());
        self::assertFalse($c->allowsEmailProtection());
    }

    // ------------------------------------------------------------------ SAN security properties

    public function testEvilSanValueIsRejectedNotSplit(): void
    {
        $c = TestPki::cert('evil');
        // A single rfc822Name "victim@example.test, email:attacker@evil.test" must NOT yield any address.
        self::assertSame([], $c->emails());
        self::assertSame([], $c->emails(false));
        self::assertSame([], $c->sanEmails);
        self::assertSame(['victim@example.test, email:attacker@evil.test'], $c->rejectedEmails);
        self::assertNotContains('victim@example.test', $c->emails());
        self::assertNotContains('attacker@evil.test', $c->emails());
        self::assertFalse($c->usesLegacySubjectEmail());
        // display name falls back to CN, never to the injected address
        self::assertSame('evil (TEST ONLY)', $c->displayName());
    }

    public function testEvilSanIsAmbiguousInOpensslParseButNotHere(): void
    {
        // documents WHY the DER parser is used: openssl_x509_parse renders the single value like two entries
        $info = openssl_x509_parse(TestPki::read('evil.crt'));
        self::assertIsArray($info);
        self::assertStringContainsString('email:attacker@evil.test', (string) $info['extensions']['subjectAltName']);
        self::assertSame([], TestPki::cert('evil')->emails());
    }

    public function testLegacySubjectEmailFallback(): void
    {
        $c = TestPki::cert('legacyemail');
        self::assertSame([], $c->sanEmails);
        self::assertSame(['legacy@example.test'], $c->subjectEmails);
        self::assertSame(['legacy@example.test'], $c->emails(true));
        self::assertSame(['legacy@example.test'], $c->emails());
        self::assertSame([], $c->emails(false));
        self::assertTrue($c->usesLegacySubjectEmail());
        self::assertSame('legacy@example.test', $c->subjectParts['emailAddress']);
    }

    public function testCasHaveNoEmails(): void
    {
        self::assertSame([], TestPki::cert('root')->emails());
        self::assertFalse(TestPki::cert('root')->usesLegacySubjectEmail());
    }

    // ------------------------------------------------------------------ URLs

    public function testAliceDistributionUrls(): void
    {
        $c = TestPki::cert('alice');
        self::assertSame(['http://crl.example.test/int.crl', 'ldap://ldap.example.test/int'], $c->crlUrls);
        self::assertSame(['http://ocsp.example.test/'], $c->ocspUrls);
        self::assertSame(['http://ca.example.test/int.crt'], $c->caIssuerUrls);

        $carol = TestPki::cert('carol');
        self::assertSame([], $carol->crlUrls);
        self::assertSame([], $carol->ocspUrls);
        self::assertSame([], $carol->caIssuerUrls);
    }

    // ------------------------------------------------------------------ issuer check

    public function testIsIssuedBy(): void
    {
        $alice = TestPki::cert('alice');
        $int = TestPki::cert('int');
        $root = TestPki::cert('root');
        $rogue = TestPki::cert('rogue');
        self::assertTrue($alice->isIssuedBy($int));
        self::assertFalse($alice->isIssuedBy($root));
        self::assertFalse($alice->isIssuedBy($rogue));
        self::assertFalse($alice->isIssuedBy($alice));
        self::assertTrue($int->isIssuedBy($root));
        self::assertTrue($root->isIssuedBy($root));
        self::assertTrue(TestPki::cert('untrusted')->isIssuedBy($rogue));
        self::assertFalse(TestPki::cert('untrusted')->isIssuedBy($int));
    }

    public function testIsIssuedByRejectsForgedIssuerWithSameNameButOtherKey(): void
    {
        // a CA with exactly the intermediate's DN but a different key and NO SKI: the name and
        // AKI/SKI pre-checks pass, so the decision must come from the signature verification
        $d = $this->tempDir();
        self::opensslOk([
            'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', $d . '/fake.key', '-out', $d . '/fake.crt',
            '-days', '30', '-sha256', '-subj', '/C=PL/O=MIME Shield TEST ONLY/CN=MIME Shield Test Intermediate CA',
            '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
            '-addext', 'subjectKeyIdentifier=none', '-addext', 'authorityKeyIdentifier=none',
        ]);
        $fake = Certificate::fromString((string) file_get_contents($d . '/fake.crt'));
        $alice = TestPki::cert('alice');
        self::assertSame($alice->issuerNameDer, $fake->subjectNameDer, 'precondition: identical DN encoding');
        self::assertSame('', $fake->subjectKeyId, 'precondition: no SKI');
        self::assertFalse($alice->isIssuedBy($fake));
    }

    // ------------------------------------------------------------------ parsing input formats

    public function testFromStringPemAndDerGiveSameCertificate(): void
    {
        $pem = Certificate::fromString(TestPki::read('bob.crt'));
        $der = Certificate::fromString(TestPki::read('bob.der'));
        $der2 = Certificate::fromDer(TestPki::read('bob.der'));
        self::assertSame($pem->fingerprint, $der->fingerprint);
        self::assertSame($pem->der, $der->der);
        self::assertSame($pem->fingerprint, $der2->fingerprint);
        self::assertSame(TestPki::read('bob.der'), $pem->der);
        self::assertStringStartsWith("-----BEGIN CERTIFICATE-----\n", $der->pem);
        self::assertSame(['bob@example.test'], $der->emails());
    }

    public function testFromStringPemWithSurroundingText(): void
    {
        $data = "Bag Attributes\n    friendlyName: x\nsubject=whatever\n" . TestPki::read('alice.crt') . "\ntrailing junk\n";
        $c = Certificate::fromString($data);
        self::assertSame(TestPki::cert('alice')->fingerprint, $c->fingerprint);
    }

    public function testFromStringBundleTakesFirstCertificate(): void
    {
        $c = Certificate::fromString(TestPki::read('chain.pem'));
        self::assertSame(TestPki::cert('int')->fingerprint, $c->fingerprint);
    }

    public function testDerToPemRoundTrip(): void
    {
        $der = TestPki::read('bob.der');
        $pem = Certificate::derToPem($der);
        self::assertSame(1, preg_match('/^-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+\/=\n]+)-----END CERTIFICATE-----\n$/', $pem, $m));
        foreach (explode("\n", trim($m[1])) as $line) {
            self::assertLessThanOrEqual(64, strlen($line));
        }
        self::assertSame($der, base64_decode(str_replace("\n", '', $m[1]), true));
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function garbageInputs(): iterable
    {
        yield 'empty' => [''];
        yield 'whitespace only' => ["  \n\t "];
        yield 'text' => ['this is not a certificate'];
        yield 'pem with invalid base64' => ["-----BEGIN CERTIFICATE-----\n!!!!****\n-----END CERTIFICATE-----\n"];
        yield 'pem with base64 of garbage' => ["-----BEGIN CERTIFICATE-----\n" . base64_encode('hello world, not DER') . "\n-----END CERTIFICATE-----\n"];
        yield 'pem with empty body' => ["-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n"];
        yield 'der sequence of nulls' => ["\x30\x04\x05\x00\x05\x00"];
        yield 'truncated der' => [substr((string) file_get_contents(TestPki::dir() . '/bob.der'), 0, 200)];
        yield 'der with trailing data' => [(string) file_get_contents(TestPki::dir() . '/bob.der') . "\x01\x02"];
        yield 'der private key' => [base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', (string) file_get_contents(TestPki::dir() . '/carol.key')) ?? '', true) ?: 'x'];
        yield 'indefinite length' => ["\x30\x80\x05\x00\x00\x00"];
    }

    #[DataProvider('garbageInputs')]
    public function testFromStringRejectsGarbage(string $data): void
    {
        self::expectValidation(static fn () => Certificate::fromString($data));
    }

    /**
     * Re-sign alice's TBS (with a varying serial) with the intermediate key until the DER encoding ends
     * with a byte that PHP's trim() strips. RSA PKCS#1 v1.5 is deterministic, so this is reproducible.
     */
    private static function validDerEndingWithTrimmableByte(): string
    {
        $root = Asn1::parse(TestPki::cert('alice')->der);
        $tbs = $root->child(0);
        $serialIdx = $tbs->children()[0]->isContext(0) ? 1 : 0;
        $intKey = openssl_pkey_get_private(TestPki::key('int'));
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $intKey);
        $algo = $root->child(1)->raw();
        for ($i = 1; $i < 5000; $i++) {
            $serial = Asn1::encode("\x02", "\x7A" . pack('N', $i));
            $newTbs = Asn1::replaceAt($tbs, [$serialIdx], $serial);
            $sig = '';
            self::assertTrue(openssl_sign($newTbs, $sig, $intKey, OPENSSL_ALGO_SHA256));
            if (in_array(substr($sig, -1), [" ", "\t", "\n", "\r", "\0", "\x0B"], true)) {
                return Asn1::encode("\x30", $newTbs . $algo . Asn1::encode("\x03", "\x00" . $sig));
            }
        }
        self::fail('could not build test certificate');
    }

    public function testFromStringAcceptsValidDerEndingWithWhitespaceByte(): void
    {
        $der = self::validDerEndingWithTrimmableByte();
        // the certificate is perfectly valid: fromDer() accepts it and the signature verifies
        $viaDer = Certificate::fromDer($der);
        self::assertTrue($viaDer->isIssuedBy(TestPki::cert('int')));
        // fromString() is documented to accept DER too, but trim() eats the last signature byte
        $viaString = Certificate::fromString($der);
        self::assertSame($viaDer->fingerprint, $viaString->fingerprint);
    }

    public function testFromStringRejectsOversizedDer(): void
    {
        // a syntactically valid DER SEQUENCE > 64 KiB
        $content = str_repeat("\x05\x00", 33000);
        $der = Asn1::encode("\x30", $content);
        self::assertGreaterThan(65536, strlen($der));
        self::expectLabel('certinvalid', static fn () => Certificate::fromString($der));
        self::expectLabel('certinvalid', static fn () => Certificate::fromDer($der));
        self::expectLabel('certinvalid', static fn () => Certificate::fromString(str_repeat('A', 70000)));
        self::expectLabel('certinvalid', static fn () => Certificate::fromDer(''));
    }

    public function testFromStringRejectsOversizedPem(): void
    {
        $der = Asn1::encode("\x30", str_repeat("\x05\x00", 33000));
        $pem = Certificate::derToPem($der);
        self::expectLabel('certinvalid', static fn () => Certificate::fromString($pem));
    }

    /**
     * Rebuild alice's DER with one extension duplicated (signature left untouched).
     */
    private static function aliceWithDuplicatedExtension(bool $duplicate): string
    {
        $der = TestPki::cert('alice')->der;
        $root = Asn1::parse($der);
        $tbs = $root->child(0);
        $extIdx = null;
        foreach ($tbs->children() as $i => $n) {
            if ($n->isContext(3)) {
                $extIdx = $i;
            }
        }
        self::assertNotNull($extIdx, 'alice has extensions');
        $extSeq = Asn1::parseContent($tbs->children()[$extIdx]);
        $exts = $extSeq->children();
        $content = '';
        foreach ($exts as $e) {
            $content .= $e->raw();
        }
        if ($duplicate) {
            // duplicate the SubjectAltName extension (append a second instance)
            foreach ($exts as $e) {
                if (Asn1::oid($e->child(0)) === '2.5.29.17') {
                    $content .= $e->raw();
                }
            }
        }
        $newExplicit = Asn1::encode("\xA3", Asn1::encode("\x30", $content));
        return Asn1::replaceAt($root, [0, $extIdx], $newExplicit);
    }

    public function testDuplicateExtensionIsRejected(): void
    {
        // control: re-encoding without duplication yields the original certificate
        $same = self::aliceWithDuplicatedExtension(false);
        self::assertSame(TestPki::cert('alice')->der, $same);

        $dup = self::aliceWithDuplicatedExtension(true);
        self::assertNotSame($same, $dup);
        self::expectLabel('certinvalid', static fn () => Certificate::fromDer($dup));
        self::expectLabel('certinvalid', static fn () => Certificate::fromString(Certificate::derToPem($dup)));
    }

    public function testDuplicateExtensionGeneratedByOpensslIsRejected(): void
    {
        // a properly signed certificate with two SAN extensions, made by re-signing the crafted TBS
        $dup = self::aliceWithDuplicatedExtension(true);
        // re-sign the manipulated TBS with the intermediate key so the signature is valid
        $root = Asn1::parse($dup);
        $tbsDer = $root->child(0)->raw();
        $intKey = openssl_pkey_get_private(TestPki::key('int'));
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $intKey);
        $sig = '';
        self::assertTrue(openssl_sign($tbsDer, $sig, $intKey, OPENSSL_ALGO_SHA256));
        $algo = $root->child(1)->raw();
        $signed = Asn1::encode("\x30", $tbsDer . $algo . Asn1::encode("\x03", "\x00" . $sig));
        // OpenSSL itself parses the structure and the signature is valid ...
        $parsed = openssl_x509_read(Certificate::derToPem($signed));
        self::assertInstanceOf(\OpenSSLCertificate::class, $parsed, 'precondition: OpenSSL parses the structure');
        $intPub = openssl_pkey_get_public(TestPki::read('int.crt'));
        self::assertSame(1, openssl_x509_verify($parsed, $intPub), 'precondition: valid signature by int');
        // ... but the plugin must reject it (RFC 5280 4.2)
        self::expectLabel('certinvalid', static fn () => Certificate::fromDer($signed));
    }

    // ------------------------------------------------------------------ splitPemBundle

    public function testSplitPemBundle(): void
    {
        $parts = Certificate::splitPemBundle(TestPki::read('chain.pem'));
        self::assertCount(2, $parts);
        self::assertSame(TestPki::cert('int')->fingerprint, Certificate::fromString($parts[0])->fingerprint);
        self::assertSame(TestPki::cert('root')->fingerprint, Certificate::fromString($parts[1])->fingerprint);
        foreach ($parts as $p) {
            self::assertStringStartsWith('-----BEGIN CERTIFICATE-----', $p);
            self::assertStringEndsWith("-----END CERTIFICATE-----\n", $p);
        }
    }

    public function testSplitPemBundleIgnoresOtherBlocks(): void
    {
        $parts = Certificate::splitPemBundle(TestPki::read('alice-bundle.pem'));
        self::assertCount(2, $parts);
        foreach ($parts as $p) {
            self::assertStringNotContainsString('PRIVATE KEY', $p);
        }
        self::assertSame([], Certificate::splitPemBundle(TestPki::key('alice')));
        self::assertSame([], Certificate::splitPemBundle(''));
        self::assertSame([], Certificate::splitPemBundle("-----BEGIN CERTIFICATE-----\nno end marker"));
    }

    public function testSplitPemBundleRespectsMax(): void
    {
        $one = TestPki::read('alice.crt');
        $bundle = str_repeat($one, 600);
        self::assertCount(500, Certificate::splitPemBundle($bundle));
        self::assertCount(3, Certificate::splitPemBundle($bundle, 3));
        self::assertCount(1, Certificate::splitPemBundle($bundle, 1));
        self::assertCount(2, Certificate::splitPemBundle(TestPki::read('chain.pem'), 10));
    }
}
