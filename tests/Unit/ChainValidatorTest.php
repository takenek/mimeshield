<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Cert\Certificate;
use MimeShield\Tests\TestPki;
use MimeShield\Trust\ChainResult;
use MimeShield\Trust\ChainValidator;
use MimeShield\Trust\TrustStore;
use PHPUnit\Framework\TestCase;

final class ChainValidatorTest extends TestCase
{
    private const ROOT_SUBJECT = 'C=PL, O=MIME Shield TEST ONLY, CN=MIME Shield Test Root CA';
    private const INT_SUBJECT = 'C=PL, O=MIME Shield TEST ONLY, CN=MIME Shield Test Intermediate CA';
    private const ROGUE_SUBJECT = 'C=PL, O=Rogue TEST ONLY, CN=Rogue Test CA';

    private string $tmp;

    protected function setUp(): void
    {
        $this->tmp = TestPki::tempDir();
        $GLOBALS['mimeshield_test_log'] = [];
    }

    protected function tearDown(): void
    {
        self::rmTree($this->tmp);
    }

    /**
     * @param list<string> $intermediates fixture names
     */
    private function validator(array $intermediates = [], ?array $bundles = null): ChainValidator
    {
        $store = new TrustStore(
            $bundles ?? [TestPki::path('root.crt')],
            false,
            array_map(static fn (string $n) => TestPki::path($n), $intermediates),
        );
        return new ChainValidator($store, $this->tmp);
    }

    /**
     * @param list<string> $names fixture file names
     *
     * @return list<string>
     */
    private static function pems(array $names): array
    {
        return array_map(static fn (string $n) => TestPki::read($n), $names);
    }

    public function testLeafWithEmbeddedIntermediateIsTrustedForBothPurposes(): void
    {
        $v = $this->validator();
        $alice = TestPki::cert('alice');
        foreach ([ChainValidator::PURPOSE_SIGN, ChainValidator::PURPOSE_ENCRYPT] as $purpose) {
            $r = $v->validate($alice, self::pems(['int.crt']), $purpose);
            self::assertSame(ChainResult::TRUSTED, $r->status, $purpose);
            self::assertTrue($r->isTrusted());
            self::assertFalse($r->leafExpired);
            self::assertSame([$alice->subject, self::INT_SUBJECT, self::ROOT_SUBJECT], $r->path);
        }
    }

    public function testMissingIntermediateIsIncomplete(): void
    {
        $alice = TestPki::cert('alice');
        $r = $this->validator()->validate($alice, [], ChainValidator::PURPOSE_SIGN);
        self::assertSame(ChainResult::INCOMPLETE, $r->status);
        self::assertFalse($r->isTrusted());
        self::assertFalse($r->leafExpired);
        self::assertSame([$alice->subject], $r->path);
    }

    public function testConfiguredIntermediateCompletesTheChain(): void
    {
        $alice = TestPki::cert('alice');
        $r = $this->validator(['int.crt'])->validate($alice, [], ChainValidator::PURPOSE_SIGN);
        self::assertSame(ChainResult::TRUSTED, $r->status);
        self::assertSame([$alice->subject, self::INT_SUBJECT, self::ROOT_SUBJECT], $r->path);
    }

    public function testRogueCaEmbeddedIsUntrustedRoot(): void
    {
        $leaf = TestPki::cert('untrusted');
        $r = $this->validator()->validate($leaf, self::pems(['rogue.crt']), ChainValidator::PURPOSE_SIGN);
        self::assertSame(ChainResult::UNTRUSTED_ROOT, $r->status);
        self::assertSame([$leaf->subject, self::ROGUE_SUBJECT], $r->path);
    }

    public function testRogueCaNotEmbeddedIsIncomplete(): void
    {
        $leaf = TestPki::cert('untrusted');
        $r = $this->validator()->validate($leaf, [], ChainValidator::PURPOSE_SIGN);
        self::assertSame(ChainResult::INCOMPLETE, $r->status);
        self::assertSame([$leaf->subject], $r->path);
    }

    public function testConfiguredIntermediatesAreNeverAnchors(): void
    {
        // a self-signed CA in the intermediates file must not become a trust anchor
        $leaf = TestPki::cert('untrusted');
        $r = $this->validator(['rogue.crt'])->validate($leaf, [], ChainValidator::PURPOSE_SIGN);
        self::assertSame(ChainResult::UNTRUSTED_ROOT, $r->status);
        self::assertSame([$leaf->subject, self::ROGUE_SUBJECT], $r->path);
    }

    public function testEmbeddingTheRealRootDoesNotHelpAForeignLeaf(): void
    {
        $leaf = TestPki::cert('untrusted');
        $r = $this->validator()->validate($leaf, self::pems(['root.crt', 'int.crt']), ChainValidator::PURPOSE_SIGN);
        self::assertFalse($r->isTrusted());
        self::assertSame(ChainResult::INCOMPLETE, $r->status);
    }

    public function testSelfSignedLeafIsUntrustedRoot(): void
    {
        $leaf = TestPki::cert('selfsigned');
        foreach ([[], self::pems(['selfsigned.crt'])] as $embedded) {
            $r = $this->validator()->validate($leaf, $embedded, ChainValidator::PURPOSE_SIGN);
            self::assertSame(ChainResult::UNTRUSTED_ROOT, $r->status);
            self::assertSame([$leaf->subject], $r->path);
        }
    }

    public function testExpiredLeafInAnchoredPath(): void
    {
        $leaf = TestPki::cert('expired');
        foreach ([ChainValidator::PURPOSE_SIGN, ChainValidator::PURPOSE_ENCRYPT] as $purpose) {
            $r = $this->validator()->validate($leaf, self::pems(['int.crt']), $purpose);
            self::assertSame(ChainResult::EXPIRED, $r->status, $purpose);
            self::assertSame([$leaf->subject, self::INT_SUBJECT, self::ROOT_SUBJECT], $r->path);
        }
    }

    public function testExpiredLeafWithoutPathIsIncompleteWithLeafExpiredFlag(): void
    {
        $leaf = TestPki::cert('expired');
        $r = $this->validator()->validate($leaf, [], ChainValidator::PURPOSE_SIGN);
        self::assertSame(ChainResult::INCOMPLETE, $r->status);
        self::assertTrue($r->leafExpired);
        self::assertFalse($r->isTrusted());
    }

    public function testNotYetValidLeaf(): void
    {
        $leaf = TestPki::cert('notyet');
        $r = $this->validator()->validate($leaf, self::pems(['int.crt']), ChainValidator::PURPOSE_SIGN);
        self::assertSame(ChainResult::NOT_YET_VALID, $r->status);
        self::assertFalse($r->leafExpired);
        self::assertSame([$leaf->subject, self::INT_SUBJECT, self::ROOT_SUBJECT], $r->path);
    }

    public function testServerAuthCertificateHasBadPurpose(): void
    {
        $leaf = TestPki::cert('server');
        foreach ([ChainValidator::PURPOSE_SIGN, ChainValidator::PURPOSE_ENCRYPT] as $purpose) {
            $r = $this->validator()->validate($leaf, self::pems(['int.crt']), $purpose);
            self::assertSame(ChainResult::BAD_PURPOSE, $r->status, $purpose);
            self::assertSame([$leaf->subject, self::INT_SUBJECT, self::ROOT_SUBJECT], $r->path);
        }
    }

    public function testEcKeyAgreementRecipientIsTrustedForEncryption(): void
    {
        // OpenSSL's SMIME_ENCRYPT purpose rejects keyAgreement certificates; the validator must cope
        $carol = TestPki::cert('carol');
        self::assertSame('EC', $carol->keyType);
        foreach ([ChainValidator::PURPOSE_ENCRYPT, ChainValidator::PURPOSE_SIGN] as $purpose) {
            $r = $this->validator()->validate($carol, self::pems(['int.crt']), $purpose);
            self::assertSame(ChainResult::TRUSTED, $r->status, $purpose);
            self::assertSame([$carol->subject, self::INT_SUBJECT, self::ROOT_SUBJECT], $r->path);
        }
    }

    public function testEcEncryptionPathStillEnforcesAnchorsAndTime(): void
    {
        // the relaxed OpenSSL purpose for EC recipients must not relax trust or validity
        $rogueEc = $this->makeEcCert('rogue', null, null);
        $r = $this->validator()->validate($rogueEc, self::pems(['rogue.crt']), ChainValidator::PURPOSE_ENCRYPT);
        self::assertSame(ChainResult::UNTRUSTED_ROOT, $r->status);

        $expiredEc = $this->makeEcCert('int', '20200101000000Z', '20210101000000Z');
        $r = $this->validator()->validate($expiredEc, self::pems(['int.crt']), ChainValidator::PURPOSE_ENCRYPT);
        self::assertSame(ChainResult::EXPIRED, $r->status);

        $notYetEc = $this->makeEcCert('int', '20350101000000Z', '20360101000000Z');
        $r = $this->validator()->validate($notYetEc, self::pems(['int.crt']), ChainValidator::PURPOSE_ENCRYPT);
        self::assertSame(ChainResult::NOT_YET_VALID, $r->status);

        $goodEc = $this->makeEcCert('int', null, null);
        $r = $this->validator()->validate($goodEc, self::pems(['int.crt']), ChainValidator::PURPOSE_ENCRYPT);
        self::assertSame(ChainResult::TRUSTED, $r->status);
    }

    /**
     * Audit MS-03: the "any" purpose used for EC recipients must not drop the EKU restrictions of the
     * CA certificates on the path (OpenSSL enforces them for RSA recipients with SMIME_ENCRYPT).
     */
    public function testEcRecipientUnderTlsOnlyIntermediateHasBadPurpose(): void
    {
        $tlsCa = $this->makeCa('tls-only', 'serverAuth, clientAuth');
        $ec = $this->makeEcCert($tlsCa, null, null);
        $r = $this->validator()->validate($ec, [(string) file_get_contents($tlsCa . '.crt')], ChainValidator::PURPOSE_ENCRYPT);
        self::assertSame(ChainResult::BAD_PURPOSE, $r->status);
        self::assertFalse($r->isTrusted());
        self::assertSame(['ec runtime (TEST ONLY)', 'tls-only (TEST ONLY)', self::ROOT_SUBJECT], array_map(
            static fn (string $s) => str_starts_with($s, 'CN=') ? substr($s, 3) : $s,
            $r->path
        ));

        // same CA restricted to e-mail protection: accepted
        $mailCa = $this->makeCa('mail-only', 'emailProtection');
        $ec = $this->makeEcCert($mailCa, null, null);
        $r = $this->validator()->validate($ec, [(string) file_get_contents($mailCa . '.crt')], ChainValidator::PURPOSE_ENCRYPT);
        self::assertSame(ChainResult::TRUSTED, $r->status);
    }

    public function testRsaRecipientUnderTlsOnlyIntermediateIsStillRejectedByOpenssl(): void
    {
        // reference behaviour the EC path is aligned with
        $tlsCa = $this->makeCa('tls-only', 'serverAuth');
        $rsa = $this->makeLeaf($tlsCa, 'rsa');
        $r = $this->validator()->validate($rsa, [(string) file_get_contents($tlsCa . '.crt')], ChainValidator::PURPOSE_ENCRYPT);
        self::assertFalse($r->isTrusted());
    }

    public function testNoTrustStore(): void
    {
        $alice = TestPki::cert('alice');
        $cases = [
            'empty config' => [],
            'missing file' => [$this->tmp . '/does-not-exist.pem'],
            'end entity only' => [TestPki::path('alice.crt')],
        ];
        foreach ($cases as $label => $bundles) {
            $r = $this->validator([], $bundles)->validate($alice, self::pems(['int.crt']), ChainValidator::PURPOSE_SIGN);
            self::assertSame(ChainResult::NO_TRUST_STORE, $r->status, $label);
            self::assertSame([], $r->path, $label);
            self::assertFalse($r->isTrusted(), $label);
        }
    }

    public function testGarbageAndEndEntityCertificatesInMessageAreIgnored(): void
    {
        $alice = TestPki::cert('alice');
        $embedded = ['not a certificate', "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", TestPki::read('mallory.crt'), TestPki::read('alice.crt'), TestPki::read('int.crt')];
        $r = $this->validator()->validate($alice, $embedded, ChainValidator::PURPOSE_SIGN);
        self::assertSame(ChainResult::TRUSTED, $r->status);
        self::assertSame([$alice->subject, self::INT_SUBJECT, self::ROOT_SUBJECT], $r->path);

        // an end-entity certificate cannot act as an intermediate even if it were the issuer by name
        $r = $this->validator()->validate($alice, [TestPki::read('mallory.crt')], ChainValidator::PURPOSE_SIGN);
        self::assertSame(ChainResult::INCOMPLETE, $r->status);
    }

    public function testValidatingTheIntermediateItselfIsAnchoredButNotTrustedForSmime(): void
    {
        $int = TestPki::cert('int');
        $r = $this->validator()->validate($int, [], ChainValidator::PURPOSE_SIGN);
        self::assertFalse($r->isTrusted());
        self::assertSame([self::INT_SUBJECT, self::ROOT_SUBJECT], $r->path);
    }

    public function testIntermediateConfiguredAsAnchorIsNotMisdiagnosedAsBadPurpose(): void
    {
        // OpenSSL (no PARTIAL_CHAIN) refuses a path that ends at a non-self-signed anchor. The diagnostic
        // path builder treats the path as anchored and, finding no time problem, reports BAD_PURPOSE
        // ("not valid for e-mail protection") although alice's KU/EKU are fine.
        $alice = TestPki::cert('alice');
        $r = $this->validator([], [TestPki::path('int.crt')])->validate($alice, [], ChainValidator::PURPOSE_SIGN);
        self::assertFalse($r->isTrusted());
        self::assertNotSame(ChainResult::BAD_PURPOSE, $r->status, 'misleading diagnosis: alice is valid for e-mail protection');
    }

    // --- helpers -------------------------------------------------------------------------------

    /**
     * Runtime intermediate CA (signed by the test root) with the given extendedKeyUsage.
     *
     * @return string path prefix of "<prefix>.crt" / "<prefix>.key"
     */
    private function makeCa(string $name, string $eku): string
    {
        $d = $this->tmp . '/ca-' . bin2hex(random_bytes(4));
        mkdir($d, 0700);
        file_put_contents($d . '/ext.cnf', "[e]\nbasicConstraints = critical, CA:TRUE, pathlen:0\nkeyUsage = critical, keyCertSign, cRLSign\n"
            . 'extendedKeyUsage = ' . $eku . "\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid:always\n");
        self::sh(['/usr/bin/openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', $d . '/ca.key']);
        self::sh(['/usr/bin/openssl', 'req', '-new', '-key', $d . '/ca.key', '-subj', '/CN=' . $name . ' (TEST ONLY)', '-out', $d . '/r.csr']);
        self::sh(['/usr/bin/openssl', 'x509', '-req', '-in', $d . '/r.csr', '-CA', TestPki::path('root.crt'), '-CAkey', TestPki::path('root.key'),
            '-set_serial', '0x' . bin2hex(random_bytes(8)), '-extfile', $d . '/ext.cnf', '-extensions', 'e', '-days', '30', '-out', $d . '/ca.crt']);
        return $d . '/ca';
    }

    private function makeLeaf(string $caPrefix, string $type): Certificate
    {
        $d = $this->tmp . '/leaf-' . bin2hex(random_bytes(4));
        mkdir($d, 0700);
        $ku = $type === 'rsa' ? 'digitalSignature, keyEncipherment' : 'digitalSignature, keyAgreement';
        file_put_contents($d . '/ext.cnf', "[e]\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, " . $ku . "\n"
            . "extendedKeyUsage = emailProtection\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid:always\nsubjectAltName = email:leaf@example.test\n");
        $gen = $type === 'rsa' ? ['-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'] : ['-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256'];
        self::sh(array_merge(['/usr/bin/openssl', 'genpkey'], $gen, ['-out', $d . '/k.pem']));
        self::sh(['/usr/bin/openssl', 'req', '-new', '-key', $d . '/k.pem', '-subj', '/CN=leaf runtime (TEST ONLY)', '-out', $d . '/r.csr']);
        self::sh(['/usr/bin/openssl', 'x509', '-req', '-in', $d . '/r.csr', '-CA', $caPrefix . '.crt', '-CAkey', $caPrefix . '.key',
            '-set_serial', '0x' . bin2hex(random_bytes(8)), '-extfile', $d . '/ext.cnf', '-extensions', 'e', '-days', '30', '-out', $d . '/c.pem']);
        return Certificate::fromString((string) file_get_contents($d . '/c.pem'));
    }

    /**
     * @param string $ca fixture name ("int") or a runtime CA path prefix from makeCa()
     */
    private function makeEcCert(string $ca, ?string $notBefore, ?string $notAfter): Certificate
    {
        $caCrt = str_starts_with($ca, '/') ? $ca . '.crt' : TestPki::path($ca . '.crt');
        $caKey = str_starts_with($ca, '/') ? $ca . '.key' : TestPki::path($ca . '.key');
        $d = $this->tmp . '/ec-' . bin2hex(random_bytes(4));
        mkdir($d, 0700);
        file_put_contents($d . '/ext.cnf', "[e]\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature, keyAgreement\n"
            . "extendedKeyUsage = emailProtection\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid:always\nsubjectAltName = email:ec@example.test\n");
        self::sh(['/usr/bin/openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', $d . '/k.pem']);
        self::sh(['/usr/bin/openssl', 'req', '-new', '-key', $d . '/k.pem', '-subj', '/CN=ec runtime (TEST ONLY)', '-out', $d . '/r.csr']);
        $cmd = ['/usr/bin/openssl', 'x509', '-req', '-in', $d . '/r.csr', '-CA', $caCrt, '-CAkey', $caKey,
            '-set_serial', '0x' . bin2hex(random_bytes(8)), '-extfile', $d . '/ext.cnf', '-extensions', 'e', '-out', $d . '/c.pem'];
        if ($notBefore !== null && $notAfter !== null) {
            array_push($cmd, '-not_before', $notBefore, '-not_after', $notAfter);
        } else {
            array_push($cmd, '-days', '30');
        }
        self::sh($cmd);
        return Certificate::fromString((string) file_get_contents($d . '/c.pem'));
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
