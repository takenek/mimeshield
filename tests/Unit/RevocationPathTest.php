<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Cert\Certificate;
use MimeShield\Crypto\CmsService;
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

/**
 * Trust decisions bound to ONE accepted path (audit F-02, F-04, F-05), on a throw-away PKI generated
 * with the openssl CLI where every certificate below the root has an http CRL distribution point:
 *
 *   root ── int ── leaf            (int: CRL DP root.crl, leaf: CRL DP int.crl)
 *            └── revoked           (listed on the CRL of int)
 *   intcopy: same subject and key as int, self-issued, WITHOUT cRLSign (shipped by an attacker)
 *   rogue ── rogueleaf / rogueec   (a CA only in the "OpenSSL default directory", SSL_CERT_DIR)
 *
 * CRLs are pre-seeded in the plugin CRL cache; the HTTP client refuses any network access.
 */
final class RevocationPathTest extends TestCase
{
    private const ROOT_CRL_URL = 'http://crl.example.test/path-root.crl';
    private const INT_CRL_URL = 'http://crl.example.test/path-int.crl';

    private static string $pki = '';

    /** @var array<string, string> */
    private static array $serials = [];

    private string $tmp = '';

    /** @var list<string> */
    private array $resolved = [];

    public static function setUpBeforeClass(): void
    {
        self::$pki = TestPki::tempDir();
        $d = self::$pki;
        file_put_contents($d . '/ext.cnf', implode("\n", [
            '[req]', 'distinguished_name = dn', '[dn]',
            '[root]', 'basicConstraints = critical, CA:TRUE', 'keyUsage = critical, keyCertSign, cRLSign', 'subjectKeyIdentifier = hash',
            '[int]', 'basicConstraints = critical, CA:TRUE, pathlen:0', 'keyUsage = critical, keyCertSign, cRLSign',
            'subjectKeyIdentifier = hash', 'authorityKeyIdentifier = keyid:always', 'crlDistributionPoints = URI:' . self::ROOT_CRL_URL,
            '[intcopy]', 'basicConstraints = critical, CA:TRUE', 'keyUsage = critical, keyCertSign', 'subjectKeyIdentifier = hash',
            '[leaf]', 'basicConstraints = critical, CA:FALSE', 'keyUsage = critical, digitalSignature, keyEncipherment',
            'extendedKeyUsage = emailProtection', 'subjectKeyIdentifier = hash', 'authorityKeyIdentifier = keyid:always',
            'subjectAltName = email:${ENV::SAN}', 'crlDistributionPoints = URI:' . self::INT_CRL_URL,
            '[leafec]', 'basicConstraints = critical, CA:FALSE', 'keyUsage = critical, digitalSignature, keyAgreement',
            'extendedKeyUsage = emailProtection', 'subjectAltName = email:${ENV::SAN}',
            '',
        ]));
        self::key('root');
        self::openssl(['req', '-x509', '-new', '-key', "$d/root.key", '-subj', '/O=TEST ONLY/CN=Path Test Root', '-days', '3650',
            '-sha256', '-config', "$d/ext.cnf", '-extensions', 'root', '-out', "$d/root.crt"]);
        self::issue('int', 'root', '/O=TEST ONLY/CN=Path Test Intermediate', 'int', 0x2001);
        self::issue('leaf', 'int', '/O=TEST ONLY/CN=Path Leaf', 'leaf', 0x3001, 'leaf@example.test');
        self::issue('revoked', 'int', '/O=TEST ONLY/CN=Path Revoked', 'leaf', 0x3002, 'revoked@example.test');
        // attacker copy of the intermediate: same subject, same key, no cRLSign
        self::openssl(['req', '-x509', '-new', '-key', "$d/int.key", '-subj', '/O=TEST ONLY/CN=Path Test Intermediate', '-days', '3650',
            '-sha256', '-config', "$d/ext.cnf", '-extensions', 'intcopy', '-set_serial', '0x2002', '-out', "$d/intcopy.crt"]);
        // a CA that only the OpenSSL default directory knows
        self::key('rogue');
        self::openssl(['req', '-x509', '-new', '-key', "$d/rogue.key", '-subj', '/O=TEST ONLY/CN=Default Store CA', '-days', '3650',
            '-sha256', '-config', "$d/ext.cnf", '-extensions', 'root', '-out', "$d/rogue.crt"]);
        self::issue('rogueleaf', 'rogue', '/O=TEST ONLY/CN=Default Store Leaf', 'leaf', 0x4001, 'leaf@example.test', false);
        self::issue('rogueec', 'rogue', '/O=TEST ONLY/CN=Default Store EC Leaf', 'leafec', 0x4002, 'leaf@example.test', true);
        mkdir("$d/default-ca", 0700);
        $rogue = (string) file_get_contents("$d/rogue.crt");
        $hash = (string) (openssl_x509_parse($rogue)['hash'] ?? '');
        file_put_contents("$d/default-ca/$hash.0", $rogue);
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$pki !== '') {
            self::rmTree(self::$pki);
        }
    }

    protected function setUp(): void
    {
        $this->tmp = TestPki::tempDir();
        $this->resolved = [];
        $GLOBALS['mimeshield_test_log'] = [];
    }

    protected function tearDown(): void
    {
        putenv('SSL_CERT_DIR');
        self::rmTree($this->tmp);
    }

    // ================================================================== F-04: every certificate on the path

    public function testWholePathGoodIsGood(): void
    {
        $rev = $this->checker([self::ROOT_CRL_URL => self::crl('root', []), self::INT_CRL_URL => self::crl('int', [])]);
        $chain = $this->validator()->validate(self::cert('leaf'), [self::pem('int')], ChainValidator::PURPOSE_SIGN);
        self::assertSame(ChainResult::TRUSTED, $chain->status);
        self::assertSame(['leaf', 'int', 'root'], $this->names($chain->certs));

        $r = $rev->checkPath($chain->certs, $this->store());
        self::assertSame(RevocationResult::GOOD, $r->status);
        self::assertSame([], $this->resolved);

        // the full verification is OK only now (signature, trusted chain, every level GOOD)
        $v = new SignatureVerifier($this->validator(), $this->store(), $rev);
        $res = $v->evaluate($this->sign('leaf'), ['leaf@example.test'], []);
        self::assertSame(RevocationResult::GOOD, $res->revocation->status);
        self::assertSame(VerificationResult::LEVEL_OK, $res->level());
    }

    public function testRevokedIntermediateRevokesTheLeaf(): void
    {
        $rev = $this->checker([self::ROOT_CRL_URL => self::crl('root', ['int']), self::INT_CRL_URL => self::crl('int', [])]);
        $v = new SignatureVerifier($this->validator(), $this->store(), $rev);

        $res = $v->evaluate($this->sign('leaf'), ['leaf@example.test'], []);

        self::assertSame(RevocationResult::REVOKED, $res->revocation->status);
        self::assertSame(VerificationResult::LEVEL_ERROR, $res->level());
        self::assertSame('status_sig_revoked', $res->headline());
    }

    public function testIntermediateWithoutUsableCrlIsUnknownNotGood(): void
    {
        $rev = $this->checker([self::INT_CRL_URL => self::crl('int', [])]);   // root CRL unavailable
        $chain = $this->validator()->validate(self::cert('leaf'), [self::pem('int')], ChainValidator::PURPOSE_SIGN);
        $r = $rev->checkPath($chain->certs, $this->store());
        self::assertSame(RevocationResult::UNKNOWN, $r->status);
    }

    public function testCaOnlyCrlCoversCasButNotEndEntities(): void
    {
        $caOnly = ['issuingDistributionPoint = critical, @idp', '[idp]', 'onlyCA = TRUE'];
        $rev = $this->checker([
            self::ROOT_CRL_URL => self::crl('root', ['int'], $caOnly, 'rootca'),
            self::INT_CRL_URL => self::crl('int', [], $caOnly, 'intca'),
        ]);
        // root's CA-only CRL is accepted for the intermediate (and finds it revoked)
        self::assertSame(RevocationResult::REVOKED, $rev->check(self::cert('int'), self::cert('root'))->status);
        // an end entity is never "good" on a CA-only CRL
        self::assertSame(RevocationResult::UNKNOWN, $rev->check(self::cert('leaf'), self::cert('int'))->status);
    }

    public function testEndEntityOnlyCrlNeverCoversACa(): void
    {
        $userOnly = ['issuingDistributionPoint = critical, @idp', '[idp]', 'onlyuser = TRUE'];
        $rev = $this->checker([self::ROOT_CRL_URL => self::crl('root', [], $userOnly, 'rootuser')]);
        $r = $rev->check(self::cert('int'), self::cert('root'));
        self::assertSame(RevocationResult::UNKNOWN, $r->status);
    }

    // ================================================================== F-05: issuer from the accepted path

    public function testShippedIssuerCopyWithoutCrlSignNeverHidesTheRevocation(): void
    {
        $rev = $this->checker([self::ROOT_CRL_URL => self::crl('root', []), self::INT_CRL_URL => self::crl('int', ['revoked'])]);
        $v = new SignatureVerifier($this->validator(), $this->store(), $rev);

        // the copy comes first in the message: the shortest anchored path uses the real intermediate
        $check = $this->sign('revoked', ['intcopy', 'int']);
        $res = $v->evaluate($check, ['revoked@example.test'], []);

        self::assertSame(['revoked', 'int', 'root'], $this->names($res->chain?->certs ?? []));
        self::assertSame(self::cert('int')->fingerprint, $res->chain?->issuerOf(self::cert('revoked'))?->fingerprint);
        self::assertSame(RevocationResult::REVOKED, $res->revocation->status);
        self::assertSame(VerificationResult::LEVEL_ERROR, $res->level());
    }

    public function testIssuerWithoutCrlSignIsReplacedOnlyByAnAdministratorCertificate(): void
    {
        $crls = [self::ROOT_CRL_URL => self::crl('root', []), self::INT_CRL_URL => self::crl('int', ['revoked'])];
        $path = [self::cert('revoked'), self::cert('intcopy'), self::cert('root')];

        // without an administrator copy of the issuer: undetermined (never GOOD)
        $r = $this->checker($crls)->checkPath($path, $this->store());
        self::assertSame(RevocationResult::UNKNOWN, $r->status);

        // the configured intermediate (same CA, may sign CRLs) is used instead
        $store = new TrustStore([self::$pki . '/root.crt'], false, [self::$pki . '/int.crt']);
        $r = $this->checker($crls)->checkPath($path, $store);
        self::assertSame(RevocationResult::REVOKED, $r->status);
    }

    public function testFindIssuerPrefersAdministratorCertificatesThatMaySignCrls(): void
    {
        $store = new TrustStore([self::$pki . '/root.crt'], false, []);
        $found = $store->findIssuer(self::cert('leaf'), [self::pem('intcopy'), self::pem('int')]);
        self::assertSame(self::cert('int')->fingerprint, $found?->fingerprint);
    }

    // ================================================================== F-02: isolation from the default CA directory

    public function testCaInTheOpenSslDefaultDirectoryIsNeverTrusted(): void
    {
        putenv('SSL_CERT_DIR=' . self::$pki . '/default-ca');
        $store = $this->store();

        // precondition: PHP really consults the default directory when ca_info names no directory,
        // otherwise this test would prove nothing
        $files = $store->caInfo();
        $pem = self::pem('rogueleaf');
        $raw = openssl_x509_checkpurpose($pem, X509_PURPOSE_SMIME_SIGN, $files);
        if ($raw !== true) {
            self::markTestSkipped('this PHP/OpenSSL build does not consult SSL_CERT_DIR - isolation cannot be demonstrated');
        }

        $v = new ChainValidator($store, $this->tmp);
        $locations = $store->verifyLocations($this->tmp);
        self::assertNotNull($locations);
        foreach ([
            ['rogueleaf', ChainValidator::PURPOSE_SIGN, X509_PURPOSE_SMIME_SIGN],
            ['rogueleaf', ChainValidator::PURPOSE_ENCRYPT, X509_PURPOSE_SMIME_ENCRYPT],
            ['rogueec', ChainValidator::PURPOSE_ENCRYPT, X509_PURPOSE_ANY],
        ] as [$name, $purpose, $opensslPurpose]) {
            // Each certificate is otherwise usable for its actual purpose. Exercise the isolated
            // OpenSSL store directly too: validate() can refuse a foreign CA before OpenSSL runs.
            self::assertTrue(openssl_x509_checkpurpose(self::pem($name), $opensslPurpose, $files), $name . '/' . $purpose . ' precondition');
            self::assertFalse(openssl_x509_checkpurpose(self::pem($name), $opensslPurpose, $locations), $name . '/' . $purpose . ' isolated OpenSSL store');
            $r = $v->validate(self::cert($name), [], $purpose);
            self::assertFalse($r->isTrusted(), $name . '/' . $purpose . ' must not be trusted through the default CA directory');
            self::assertSame([], $r->certs);
        }

        // the isolation directory exists, is private and empty
        $iso = TrustStore::isolationDir($this->tmp);
        self::assertNotNull($iso);
        self::assertSame(0700, fileperms($iso) & 0777);
        self::assertSame(['.', '..'], scandir($iso));

        // the configured anchors still work with the same environment
        self::assertTrue($v->validate(self::cert('leaf'), [self::pem('int')], ChainValidator::PURPOSE_SIGN)->isTrusted());
    }

    public function testNonEmptyIsolationDirectoryFailsClosed(): void
    {
        $iso = TrustStore::isolationDir($this->tmp);
        self::assertNotNull($iso);
        file_put_contents($iso . '/planted.0', self::pem('rogue'));
        self::assertNull(TrustStore::isolationDir($this->tmp));
        $r = $this->validator()->validate(self::cert('leaf'), [self::pem('int')], ChainValidator::PURPOSE_SIGN);
        self::assertFalse($r->isTrusted());
    }

    // ================================================================== helpers

    private function store(): TrustStore
    {
        return new TrustStore([self::$pki . '/root.crt'], false, []);
    }

    private function validator(): ChainValidator
    {
        return new ChainValidator($this->store(), $this->tmp);
    }

    /**
     * @param array<string, string> $crls url => DER, seeded into the CRL cache
     */
    private function checker(array $crls): RevocationChecker
    {
        $cache = $this->tmp . '/cache-' . bin2hex(random_bytes(4));
        mkdir($cache . '/crl', 0700, true);
        foreach ($crls as $url => $der) {
            file_put_contents($cache . '/crl/' . hash('sha256', $url) . '.crl', $der);
        }
        $http = new SafeHttpClient(1, 1, [80, 443], [], [], '', function (string $host): array {
            $this->resolved[] = $host;
            return ['127.0.0.1'];
        });
        return new RevocationChecker(RevocationChecker::MODE_CRL, $http, $cache);
    }

    /**
     * @param list<string> $embedded
     */
    private function sign(string $name, array $embedded = ['int']): \MimeShield\Crypto\SignatureCheck
    {
        $cms = new CmsService($this->tmp);
        $content = "Content-Type: text/plain\r\n\r\npath test\r\n";
        $der = $cms->signDetached($content, self::cert($name), (string) file_get_contents(self::$pki . "/$name.key"), array_map(self::pem(...), $embedded));
        return $cms->verifyDetached($content, $der);
    }

    /**
     * @param list<Certificate> $certs
     *
     * @return list<string>
     */
    private function names(array $certs): array
    {
        $out = [];
        foreach ($certs as $c) {
            foreach (['leaf', 'revoked', 'int', 'intcopy', 'root'] as $n) {
                if (self::cert($n)->fingerprint === $c->fingerprint) {
                    $out[] = $n;
                }
            }
        }
        return $out;
    }

    private static function cert(string $name): Certificate
    {
        return Certificate::fromString(self::pem($name));
    }

    private static function pem(string $name): string
    {
        return (string) file_get_contents(self::$pki . "/$name.crt");
    }

    /**
     * CRL of $ca (root|int) revoking $revoked (names), generated with "openssl ca -gencrl".
     *
     * @param list<string> $revoked
     * @param list<string> $extLines extra lines: first the crl_extensions entries, then other sections
     */
    private static function crl(string $ca, array $revoked, array $extLines = [], ?string $tag = null): string
    {
        $d = self::$pki . '/crl-' . ($tag ?? $ca) . '-' . bin2hex(random_bytes(3));
        mkdir($d, 0700);
        $index = '';
        foreach ($revoked as $n) {
            $exp = gmdate('ymdHis', time() + 86400 * 365) . 'Z';
            $rev = gmdate('ymdHis', time() - 3600) . 'Z';
            $index .= "R\t$exp\t$rev,keyCompromise\t" . self::$serials[$n] . "\tunknown\t/CN=$n\n";
        }
        file_put_contents("$d/index.txt", $index);
        file_put_contents("$d/index.txt.attr", "unique_subject = no\n");
        file_put_contents("$d/crlnumber", "1000\n");
        $conf = "[ca]\ndefault_ca = c\n[c]\ndatabase = $d/index.txt\ncrlnumber = $d/crlnumber\ncertificate = " . self::$pki . "/$ca.crt\n"
            . 'private_key = ' . self::$pki . "/$ca.key\ndefault_md = sha256\ndefault_crl_days = 30\n";
        if ($extLines !== []) {
            $conf .= "crl_extensions = crlext\n[crlext]\n" . implode("\n", $extLines) . "\n";
        }
        file_put_contents("$d/ca.cnf", $conf);
        self::openssl(['ca', '-config', "$d/ca.cnf", '-gencrl', '-batch', '-out', "$d/crl.pem"]);
        self::openssl(['crl', '-in', "$d/crl.pem", '-outform', 'DER', '-out', "$d/crl.der"]);
        return (string) file_get_contents("$d/crl.der");
    }

    private static function key(string $name, bool $ec = false): void
    {
        $args = $ec ? ['-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256'] : ['-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'];
        self::openssl(['genpkey', ...$args, '-out', self::$pki . "/$name.key"]);
    }

    private static function issue(string $name, string $ca, string $subject, string $section, int $serial, string $san = 'none@example.test', ?bool $ec = null): void
    {
        $d = self::$pki;
        self::key($name, $ec === true);
        self::openssl(['req', '-new', '-key', "$d/$name.key", '-subj', $subject, '-config', "$d/ext.cnf", '-out', "$d/$name.csr"]);
        self::openssl(['x509', '-req', '-in', "$d/$name.csr", '-CA', "$d/$ca.crt", '-CAkey', "$d/$ca.key", '-set_serial', (string) $serial,
            '-days', '3650', '-sha256', '-extfile', "$d/ext.cnf", '-extensions', $section, '-out', "$d/$name.crt"], ['SAN' => $san]);
        self::$serials[$name] = strtoupper(dechex($serial));
    }

    /**
     * @param list<string>          $args
     * @param array<string, string> $env
     */
    private static function openssl(array $args, array $env = []): void
    {
        $p = proc_open(['/usr/bin/openssl', ...$args], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $env + ['SAN' => 'none@example.test', 'PATH' => '/usr/bin:/bin']);
        self::assertIsResource($p);
        $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        if (proc_close($p) !== 0) {
            self::fail('openssl ' . implode(' ', $args) . ' failed: ' . $out);
        }
    }

    private static function rmTree(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (scandir($dir) ?: [] as $f) {
            if ($f === '.' || $f === '..') {
                continue;
            }
            $p = $dir . '/' . $f;
            is_dir($p) && !is_link($p) ? self::rmTree($p) : @unlink($p);
        }
        @rmdir($dir);
    }
}
