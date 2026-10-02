<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Cert\Certificate;
use MimeShield\Cert\PublicCertImporter;
use MimeShield\Exception\ValidationException;
use MimeShield\Tests\TestPki;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PublicCertImporterTest extends TestCase
{
    private const OPENSSL = '/usr/bin/openssl';

    // ------------------------------------------------------------------ helpers

    /**
     * @param list<string> $args
     */
    private static function opensslOk(array $args, string $stdin = ''): string
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
        self::assertSame(0, proc_close($proc), 'openssl ' . implode(' ', $args) . ' failed: ' . $err);
        return $out;
    }

    /**
     * @param list<string> $certNames
     */
    private static function pkcs7(array $certNames, string $outform): string
    {
        $args = ['crl2pkcs7', '-nocrl', '-outform', $outform];
        foreach ($certNames as $n) {
            $args[] = '-certfile';
            $args[] = TestPki::path($n . '.crt');
        }
        return self::opensslOk($args);
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

    /**
     * @param list<Certificate> $certs
     *
     * @return list<string>
     */
    private static function fps(array $certs): array
    {
        return array_map(static fn (Certificate $c) => $c->fingerprint, $certs);
    }

    /**
     * @param list<string> $names
     *
     * @return list<string>
     */
    private static function expectedFps(array $names): array
    {
        return array_map(static fn (string $n) => TestPki::cert($n)->fingerprint, $names);
    }

    // ------------------------------------------------------------------ accepted formats

    public function testSinglePem(): void
    {
        $r = (new PublicCertImporter())->parse(TestPki::read('bob.crt'));
        self::assertSame(self::expectedFps(['bob']), self::fps($r['entities']));
        self::assertSame([], $r['cas']);
        self::assertSame(['bob@example.test'], $r['entities'][0]->emails());
    }

    public function testPemBundleSplitsEntitiesAndCas(): void
    {
        $data = TestPki::read('alice.crt') . TestPki::read('int.crt') . TestPki::read('carol.crt') . TestPki::read('root.crt');
        $r = (new PublicCertImporter())->parse($data);
        self::assertSame(self::expectedFps(['alice', 'carol']), self::fps($r['entities']));
        self::assertSame(self::expectedFps(['int', 'root']), self::fps($r['cas']));
    }

    public function testCaOnlyBundle(): void
    {
        $r = (new PublicCertImporter())->parse(TestPki::read('chain.pem'));
        self::assertSame([], $r['entities']);
        self::assertSame(self::expectedFps(['int', 'root']), self::fps($r['cas']));
    }

    public function testDer(): void
    {
        $r = (new PublicCertImporter())->parse(TestPki::read('bob.der'));
        self::assertSame(self::expectedFps(['bob']), self::fps($r['entities']));
        self::assertSame([], $r['cas']);
        $rootDer = TestPki::cert('root')->der;
        $r = (new PublicCertImporter())->parse($rootDer);
        self::assertSame([], $r['entities']);
        self::assertSame(self::expectedFps(['root']), self::fps($r['cas']));
    }

    public function testPkcs7Der(): void
    {
        $p7 = self::pkcs7(['alice', 'int', 'root'], 'DER');
        self::assertSame("\x30", $p7[0], 'precondition: DER');
        $r = (new PublicCertImporter())->parse($p7);
        self::assertSame(self::expectedFps(['alice']), self::fps($r['entities']));
        self::assertEqualsCanonicalizing(self::expectedFps(['int', 'root']), self::fps($r['cas']));
    }

    public function testPkcs7Pem(): void
    {
        $p7 = self::pkcs7(['carol', 'int'], 'PEM');
        self::assertStringContainsString('-----BEGIN PKCS7-----', $p7, 'precondition');
        $r = (new PublicCertImporter())->parse($p7);
        self::assertSame(self::expectedFps(['carol']), self::fps($r['entities']));
        self::assertSame(self::expectedFps(['int']), self::fps($r['cas']));
    }

    public function testPkcs7WithCmsLabel(): void
    {
        $p7 = str_replace('PKCS7-----', 'CMS-----', self::pkcs7(['bob'], 'PEM'));
        self::assertStringContainsString('-----BEGIN CMS-----', $p7);
        $r = (new PublicCertImporter())->parse($p7);
        self::assertSame(self::expectedFps(['bob']), self::fps($r['entities']));
    }

    public function testPkcs7CaOnly(): void
    {
        $r = (new PublicCertImporter())->parse(self::pkcs7(['int', 'root'], 'DER'));
        self::assertSame([], $r['entities']);
        self::assertCount(2, $r['cas']);
    }

    public function testEvilCertificateImportsWithoutEmails(): void
    {
        // the import itself succeeds, but the injected address is not bound to the certificate
        $r = (new PublicCertImporter())->parse(TestPki::read('evil.crt'));
        self::assertCount(1, $r['entities']);
        self::assertSame([], $r['entities'][0]->emails());
    }

    // ------------------------------------------------------------------ rejected input

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function privateKeyUploads(): iterable
    {
        $d = TestPki::dir();
        yield 'PKCS#8 key alone' => [(string) file_get_contents($d . '/alice.key')];
        yield 'cert + key bundle' => [(string) file_get_contents($d . '/alice-bundle.pem')];
        yield 'cert + encrypted key bundle' => [(string) file_get_contents($d . '/alice-bundle-enc.pem')];
        yield 'mismatch bundle' => [(string) file_get_contents($d . '/mismatch.pem')];
        yield 'EC key' => [(string) file_get_contents($d . '/carol.key')];
        yield 'traditional RSA label' => ["-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n" . file_get_contents($d . '/alice.crt')];
        yield 'EC label after cert' => [file_get_contents($d . '/alice.crt') . "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"];
    }

    #[DataProvider('privateKeyUploads')]
    public function testPrivateKeyIsRejected(string $data): void
    {
        self::expectLabel('publiccontainskey', static fn () => (new PublicCertImporter())->parse($data));
    }

    public function testDerPrivateKeyIsNotAccepted(): void
    {
        $b64 = (string) preg_replace('/-----[^-]+-----|\s+/', '', TestPki::key('carol'));
        $der = (string) base64_decode($b64, true);
        self::assertSame("\x30", $der[0]);
        $e = null;
        try {
            (new PublicCertImporter())->parse($der);
        } catch (ValidationException $e) {
        }
        self::assertInstanceOf(ValidationException::class, $e, 'a DER private key must never be accepted');
    }

    public function testTooManyCertificates(): void
    {
        $one = TestPki::read('alice.crt');
        self::expectLabel('importtoomany', static fn () => (new PublicCertImporter())->parse(str_repeat($one, 11)));
        $r = (new PublicCertImporter())->parse(str_repeat($one, 10));
        self::assertCount(10, $r['entities']);

        // custom limit, PEM bundle and PKCS#7
        self::expectLabel('importtoomany', static fn () => (new PublicCertImporter(65536, 2))->parse(TestPki::read('alice.crt') . TestPki::read('chain.pem')));
        $p7 = self::pkcs7(['alice', 'int', 'root'], 'DER');
        self::expectLabel('importtoomany', static fn () => (new PublicCertImporter(65536, 2))->parse($p7));
        self::assertCount(1, (new PublicCertImporter(65536, 3))->parse($p7)['entities']);
    }

    public function testEmptyAndOversized(): void
    {
        self::expectLabel('importempty', static fn () => (new PublicCertImporter())->parse(''));
        self::expectLabel('importtoolarge', static fn () => (new PublicCertImporter())->parse(str_repeat('A', 65537)));
        $pem = TestPki::read('alice.crt');
        self::expectLabel('importtoolarge', static fn () => (new PublicCertImporter(strlen($pem) - 1))->parse($pem));
        self::assertCount(1, (new PublicCertImporter(strlen($pem)))->parse($pem)['entities']);
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function garbage(): iterable
    {
        mt_srand(777);
        $g = '';
        for ($i = 0; $i < 2048; $i++) {
            $g .= chr(mt_rand(0, 255));
        }
        yield 'pseudo-random bytes' => [$g];
        yield 'text' => ['definitely not a certificate'];
        yield 'pem without certificate blocks' => ["-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"];
        yield 'pem with broken base64' => ["-----BEGIN CERTIFICATE-----\n####\n-----END CERTIFICATE-----\n"];
        yield 'broken PKCS7 PEM' => ["-----BEGIN PKCS7-----\nAAAA\n-----END PKCS7-----\n"];
        yield 'DER OID only' => ["\x30\x0b\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"];
        yield 'truncated DER' => [substr((string) file_get_contents(TestPki::dir() . '/bob.der'), 0, 300)];
    }

    #[DataProvider('garbage')]
    public function testGarbageIsCertInvalid(string $data): void
    {
        self::expectLabel('certinvalid', static fn () => (new PublicCertImporter())->parse($data));
    }

    public function testPkcs12IsNotAcceptedAsPublicCertificate(): void
    {
        $e = null;
        try {
            (new PublicCertImporter())->parse(TestPki::read('alice.p12'));
        } catch (ValidationException $e) {
        }
        self::assertInstanceOf(ValidationException::class, $e);
        self::assertContains($e->getUserLabel(), ['certinvalid', 'malformed']);
    }
}
