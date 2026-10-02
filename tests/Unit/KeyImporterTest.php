<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Cert\Certificate;
use MimeShield\Cert\ImportedKey;
use MimeShield\Cert\KeyImporter;
use MimeShield\Cert\LegacyPkcs12Converter;
use MimeShield\Exception\ValidationException;
use MimeShield\Tests\TestPki;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class KeyImporterTest extends TestCase
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
        return [proc_close($proc), $out, $err];
    }

    /**
     * @param list<string> $args
     */
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

    private static function assertKeyMatches(ImportedKey $k, string $expectedCert): void
    {
        $pem = $k->privateKeyPem();
        self::assertStringStartsWith('-----BEGIN PRIVATE KEY-----', $pem, 'unencrypted PKCS#8 expected');
        self::assertStringNotContainsString('ENCRYPTED', $pem);
        self::assertStringNotContainsString('RSA PRIVATE KEY', $pem);
        self::assertStringNotContainsString('EC PRIVATE KEY', $pem);
        $key = openssl_pkey_get_private($pem);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $key, 'exported key loads without password');
        self::assertTrue(openssl_x509_check_private_key($k->certificate->pem, $key));
        self::assertTrue(openssl_x509_check_private_key(TestPki::read($expectedCert . '.crt'), $pem));
        self::assertSame(TestPki::cert($expectedCert)->fingerprint, $k->certificate->fingerprint);
        self::assertFalse($k->certificate->isCa);
    }

    // ------------------------------------------------------------------ successful imports

    /**
     * @return iterable<string, array{0: string, 1: string, 2: string, 3: list<string>}>
     */
    public static function goodFiles(): iterable
    {
        yield 'alice.p12 (AES-256/PBKDF2)' => ['alice.p12', TestPki::PASSWORD, 'alice', ['int']];
        yield 'alice.pfx' => ['alice.pfx', TestPki::PASSWORD, 'alice', ['int']];
        yield 'alice-3des.p12 (3DES, SHA-1 MAC)' => ['alice-3des.p12', TestPki::PASSWORD, 'alice', ['int']];
        yield 'alice-nopass.p12 (empty password)' => ['alice-nopass.p12', '', 'alice', ['int']];
        yield 'carol.p12 (EC P-256)' => ['carol.p12', TestPki::PASSWORD, 'carol', ['int']];
        yield 'bob.p12 (RSA 3072)' => ['bob.p12', TestPki::PASSWORD, 'bob', ['int']];
        yield 'alice-bundle.pem' => ['alice-bundle.pem', '', 'alice', ['int']];
        yield 'alice-bundle.pem (password ignored for plain key)' => ['alice-bundle.pem', 'whatever', 'alice', ['int']];
        yield 'alice-bundle-enc.pem' => ['alice-bundle-enc.pem', TestPki::PASSWORD, 'alice', ['int']];
    }

    /**
     * @param list<string> $chainNames
     */
    #[DataProvider('goodFiles')]
    public function testImportSucceeds(string $file, string $password, string $leaf, array $chainNames): void
    {
        $k = (new KeyImporter())->import(TestPki::read($file), $password);
        self::assertKeyMatches($k, $leaf);
        self::assertCount(count($chainNames), $k->chain);
        foreach ($chainNames as $i => $n) {
            self::assertInstanceOf(Certificate::class, $k->chain[$i]);
            self::assertSame(TestPki::cert($n)->fingerprint, $k->chain[$i]->fingerprint);
            self::assertTrue($k->chain[$i]->isCa);
            self::assertNotSame($k->certificate->fingerprint, $k->chain[$i]->fingerprint);
        }
        $k->wipe();
    }

    public function testCarolKeyIsEc(): void
    {
        $k = (new KeyImporter())->import(TestPki::read('carol.p12'), TestPki::PASSWORD);
        $d = openssl_pkey_get_details(openssl_pkey_get_private($k->privateKeyPem()));
        self::assertIsArray($d);
        self::assertSame(OPENSSL_KEYTYPE_EC, $d['type']);
        self::assertSame('prime256v1', $d['ec']['curve_name']);
        self::assertSame('EC', $k->certificate->keyType);
    }

    public function testPemBundleOrderDoesNotMatter(): void
    {
        $data = TestPki::read('int.crt') . TestPki::key('alice') . TestPki::read('root.crt') . TestPki::read('alice.crt');
        $k = (new KeyImporter())->import($data, '');
        self::assertKeyMatches($k, 'alice');
        $fps = array_map(static fn (Certificate $c) => $c->fingerprint, $k->chain);
        self::assertSame([TestPki::cert('int')->fingerprint, TestPki::cert('root')->fingerprint], $fps);
    }

    public function testPemBundleWithOtherEndEntityDropsItFromChain(): void
    {
        // an unrelated end-entity certificate is never put into the CA chain
        $data = TestPki::read('bob.crt') . TestPki::read('alice.crt') . TestPki::key('alice') . TestPki::read('int.crt');
        $k = (new KeyImporter())->import($data, '');
        self::assertKeyMatches($k, 'alice');
        self::assertCount(1, $k->chain);
        self::assertSame(TestPki::cert('int')->fingerprint, $k->chain[0]->fingerprint);
    }

    public function testTraditionalEncryptedPemKey(): void
    {
        $enc = self::opensslOk(['rsa', '-aes256', '-traditional', '-passout', 'pass:trad-pass'], TestPki::key('alice'));
        self::assertStringContainsString('Proc-Type: 4,ENCRYPTED', $enc, 'precondition');
        $k = (new KeyImporter())->import(TestPki::read('alice.crt') . $enc, 'trad-pass');
        self::assertKeyMatches($k, 'alice');
        self::expectLabel('badpassword', static fn () => (new KeyImporter())->import(TestPki::read('alice.crt') . $enc, 'nope'));
    }

    public function testImportedKeyWipe(): void
    {
        $k = (new KeyImporter())->import(TestPki::read('alice.p12'), TestPki::PASSWORD);
        self::assertStringContainsString('PRIVATE KEY', $k->privateKeyPem());
        $k->wipe();
        self::assertSame('', $k->privateKeyPem());
        // certificate data stays available
        self::assertSame(TestPki::cert('alice')->fingerprint, $k->certificate->fingerprint);
        $k->wipe(); // idempotent
        self::assertSame('', $k->privateKeyPem());
    }

    // ------------------------------------------------------------------ failures

    /**
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function badFiles(): iterable
    {
        yield 'p12 wrong password' => ['alice.p12', 'wrong-password', 'badpassword'];
        yield 'pfx wrong password' => ['alice.pfx', 'wrong-password', 'badpassword'];
        yield '3des wrong password' => ['alice-3des.p12', 'wrong-password', 'badpassword'];
        yield 'carol wrong password' => ['carol.p12', '', 'badpassword'];
        yield 'nopass p12 given a password' => ['alice-nopass.p12', TestPki::PASSWORD, 'badpassword'];
        yield 'password without the non-ASCII part' => ['alice.p12', 'test-password-Zazolc', 'badpassword'];
        yield 'legacy RC2-40 cert bag' => ['alice-legacy.p12', TestPki::PASSWORD, 'p12legacy'];
        yield 'legacy wrong password' => ['alice-legacy.p12', 'wrong-password', 'badpassword'];
        yield 'p12 without key' => ['alice-nokey.p12', TestPki::PASSWORD, 'p12nokey'];
        yield 'cert + other key' => ['mismatch.pem', '', 'keymismatch'];
        yield 'encrypted PEM wrong password' => ['alice-bundle-enc.pem', 'wrong-password', 'badpassword'];
        yield 'encrypted PEM empty password' => ['alice-bundle-enc.pem', '', 'badpassword'];
        yield 'certificate only (PEM)' => ['alice.crt', '', 'p12nokey'];
        yield 'CA chain only (PEM)' => ['chain.pem', '', 'p12nokey'];
        yield 'key only (PEM)' => ['alice.key', '', 'importnocert'];
        yield 'DER certificate as p12' => ['bob.der', '', 'p12invalid'];
    }

    #[DataProvider('badFiles')]
    public function testImportFails(string $file, string $password, string $label): void
    {
        self::expectLabel($label, static fn () => (new KeyImporter())->import(TestPki::read($file), $password));
    }

    public function testKeyWithOnlyCaCertificatesIsNoCert(): void
    {
        self::expectLabel('importnocert', static fn () => (new KeyImporter())->import(TestPki::read('chain.pem') . TestPki::key('alice'), ''));
    }

    public function testEmptyAndOversized(): void
    {
        self::expectLabel('importempty', static fn () => (new KeyImporter())->import('', TestPki::PASSWORD));
        self::expectLabel('importtoolarge', static fn () => (new KeyImporter())->import(str_repeat('A', 102401), TestPki::PASSWORD));
        // a real p12 above a custom limit
        $p12 = TestPki::read('alice.p12');
        self::expectLabel('importtoolarge', static fn () => (new KeyImporter(strlen($p12) - 1))->import($p12, TestPki::PASSWORD));
        $k = (new KeyImporter(strlen($p12)))->import($p12, TestPki::PASSWORD);
        self::assertKeyMatches($k, 'alice');
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function garbage(): iterable
    {
        mt_srand(4242);
        $g = '';
        for ($i = 0; $i < 4096; $i++) {
            $g .= chr(mt_rand(0, 255));
        }
        yield 'pseudo-random bytes' => [$g];
        yield 'text' => ['hello, this is not a key'];
        yield 'DER SEQUENCE with zeros' => ["\x30\x82\x01\x00" . str_repeat("\x00", 256)];
        yield 'truncated p12' => [substr((string) file_get_contents(TestPki::dir() . '/alice.p12'), 0, 600)];
    }

    #[DataProvider('garbage')]
    public function testGarbageIsP12Invalid(string $data): void
    {
        self::expectLabel('p12invalid', static fn () => (new KeyImporter())->import($data, TestPki::PASSWORD));
    }

    public function testCorruptedPemKey(): void
    {
        $data = TestPki::read('alice.crt') . "-----BEGIN PRIVATE KEY-----\nAAAAAAAAAAAA\n-----END PRIVATE KEY-----\n";
        self::expectLabel('keyinvalid', static fn () => (new KeyImporter())->import($data, ''));
    }

    public function testWeak1024BitRsaKeyIsRejected(): void
    {
        $d = $this->tempDir();
        self::opensslOk([
            'req', '-x509', '-newkey', 'rsa:1024', '-nodes', '-keyout', $d . '/weak.key', '-out', $d . '/weak.crt',
            '-days', '30', '-subj', '/CN=weak (TEST ONLY)', '-addext', 'subjectAltName=email:weak@example.test',
            '-addext', 'basicConstraints=critical,CA:FALSE',
        ]);
        $pem = (string) file_get_contents($d . '/weak.crt') . (string) file_get_contents($d . '/weak.key');
        $e = self::expectLabel('keytooweak', static fn () => (new KeyImporter())->import($pem, ''));
        self::assertSame(['bits' => '1024'], $e->getVars());

        // the same as PKCS#12
        file_put_contents($d . '/pw', "p12pass\n");
        $p12 = self::opensslOk(['pkcs12', '-export', '-in', $d . '/weak.crt', '-inkey', $d . '/weak.key', '-passout', 'file:' . $d . '/pw']);
        self::expectLabel('keytooweak', static fn () => (new KeyImporter())->import($p12, 'p12pass'));
    }

    public function testMinRsaBitsIsConfigurable(): void
    {
        $e = self::expectLabel('keytooweak', static fn () => (new KeyImporter(102400, 4096))->import(TestPki::read('alice.p12'), TestPki::PASSWORD));
        self::assertSame(['bits' => '2048'], $e->getVars());
        // bob has RSA 3072
        self::expectLabel('keytooweak', static fn () => (new KeyImporter(102400, 4096))->import(TestPki::read('bob.p12'), TestPki::PASSWORD));
        $k = (new KeyImporter(102400, 3072))->import(TestPki::read('bob.p12'), TestPki::PASSWORD);
        self::assertKeyMatches($k, 'bob');
    }

    public function testUnsupportedKeyTypes(): void
    {
        $k1 = self::opensslOk(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:secp256k1']);
        self::expectLabel('keyunsupported', static fn () => (new KeyImporter())->import(TestPki::read('alice.crt') . $k1, ''));
        $k2 = self::opensslOk(['genpkey', '-algorithm', 'ED25519']);
        self::expectLabel('keyunsupported', static fn () => (new KeyImporter())->import(TestPki::read('alice.crt') . $k2, ''));
    }

    // ------------------------------------------------------------------ LegacyPkcs12Converter

    public function testLegacyConverterIsAvailable(): void
    {
        self::assertTrue(LegacyPkcs12Converter::isAvailable(self::OPENSSL));
        self::assertFalse(LegacyPkcs12Converter::isAvailable(''));
        self::assertFalse(LegacyPkcs12Converter::isAvailable('/nonexistent/bin/openssl'));
        self::assertFalse(LegacyPkcs12Converter::isAvailable('/usr/bin'));
        $d = $this->tempDir();
        file_put_contents($d . '/openssl', "#!/bin/sh\nexit 0\n");
        chmod($d . '/openssl', 0600);
        self::assertFalse(LegacyPkcs12Converter::isAvailable($d . '/openssl'), 'non-executable file');
    }

    public function testLegacyConverterMissingBinary(): void
    {
        $c = new LegacyPkcs12Converter('/nonexistent/bin/openssl');
        self::expectLabel('p12legacy', static fn () => $c->toPem(TestPki::read('alice-legacy.p12'), TestPki::PASSWORD));
    }

    public function testLegacyConverterConvertsAndImporterAcceptsResult(): void
    {
        $legacy = TestPki::read('alice-legacy.p12');
        self::expectLabel('p12legacy', static fn () => (new KeyImporter())->import($legacy, TestPki::PASSWORD));

        $pem = (new LegacyPkcs12Converter(self::OPENSSL))->toPem($legacy, TestPki::PASSWORD);
        self::assertStringContainsString('PRIVATE KEY-----', $pem);
        self::assertStringContainsString('-----BEGIN CERTIFICATE-----', $pem);
        self::assertStringNotContainsString('ENCRYPTED PRIVATE KEY', $pem, '-nodes: unencrypted output');

        $k = (new KeyImporter())->import($pem, '');
        self::assertKeyMatches($k, 'alice');
        self::assertCount(1, $k->chain);
        self::assertSame(TestPki::cert('int')->fingerprint, $k->chain[0]->fingerprint);
    }

    public function testLegacyConverterWrongPassword(): void
    {
        $c = new LegacyPkcs12Converter(self::OPENSSL);
        self::expectLabel('badpassword', static fn () => $c->toPem(TestPki::read('alice-legacy.p12'), 'wrong-password'));
    }

    public function testLegacyConverterGarbageInput(): void
    {
        $c = new LegacyPkcs12Converter(self::OPENSSL);
        self::expectLabel('p12legacy', static fn () => $c->toPem('this is not a pkcs12 file', TestPki::PASSWORD));
    }

    public function testLegacyConverterPasswordIsNotInterpretedByAShell(): void
    {
        $d = $this->tempDir();
        $marker = $d . '/PWNED';
        $password = "a'b\"c \$(touch " . $marker . ') `touch ' . $marker . '` ; | & -passin pass:x';
        file_put_contents($d . '/pw', $password . "\n");
        $p12 = self::opensslOk([
            'pkcs12', '-export', '-legacy', '-in', TestPki::path('alice.crt'), '-inkey', TestPki::path('alice.key'),
            '-certfile', TestPki::path('int.crt'), '-passout', 'file:' . $d . '/pw',
        ]);
        self::expectLabel('p12legacy', static fn () => (new KeyImporter())->import($p12, $password));

        $pem = (new LegacyPkcs12Converter(self::OPENSSL))->toPem($p12, $password);
        self::assertFileDoesNotExist($marker);
        self::assertKeyMatches((new KeyImporter())->import($pem, ''), 'alice');
    }

    public function testLegacyConverterUsesProcOpenArgumentArrayAndPipes(): void
    {
        $src = (string) file_get_contents((string) (new \ReflectionClass(LegacyPkcs12Converter::class))->getFileName());
        self::assertMatchesRegularExpression('/\$cmd\s*=\s*\[\$this->opensslBinary,\s*\'pkcs12\'/', $src, 'command is an argument array');
        self::assertMatchesRegularExpression('/proc_open\(\$cmd,/', $src);
        self::assertStringContainsString("'-passin', 'fd:3'", $src, 'password via pipe, not argv');
        foreach (['shell_exec(', 'passthru(', 'system(', 'popen(', 'escapeshellarg', 'tempnam(', 'file_put_contents(', 'tmpfile('] as $bad) {
            self::assertStringNotContainsString($bad, $src);
        }
        self::assertDoesNotMatchRegularExpression('/(?<![a-z_])exec\(/', $src);
    }

    public function testLegacyConversionCreatesNoTempFiles(): void
    {
        // run the conversion in a child PHP whose temp dir is a private, initially empty directory
        $watch = $this->tempDir();
        $work = $this->tempDir();
        $script = $work . '/convert.php';
        $autoload = var_export(dirname(__DIR__, 2) . '/lib/autoload.php', true);
        $p12 = var_export(TestPki::path('alice-legacy.p12'), true);
        $pw = var_export(TestPki::PASSWORD, true);
        file_put_contents($script, <<<PHP
            <?php
            require {$autoload};
            \$before = scandir(sys_get_temp_dir());
            \$pem = (new MimeShield\\Cert\\LegacyPkcs12Converter('/usr/bin/openssl'))->toPem(file_get_contents({$p12}), {$pw});
            \$after = scandir(sys_get_temp_dir());
            echo json_encode(['tmp' => sys_get_temp_dir(), 'before' => \$before, 'after' => \$after, 'ok' => str_contains(\$pem, 'PRIVATE KEY-----')]);
            PHP);
        $proc = proc_open(
            [PHP_BINARY, '-d', 'sys_temp_dir=' . $watch, $script],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            null,
            ['PATH' => '/usr/bin:/bin', 'TMPDIR' => $watch]
        );
        self::assertIsResource($proc);
        fclose($pipes[0]);
        $out = (string) stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        self::assertSame(0, proc_close($proc), $out . $err);
        $res = json_decode($out, true);
        self::assertIsArray($res, $out . $err);
        self::assertSame($watch, $res['tmp']);
        self::assertTrue($res['ok']);
        self::assertSame(['.', '..'], $res['before']);
        self::assertSame(['.', '..'], $res['after'], 'no temp file during conversion');
        self::assertSame(['.', '..'], scandir($watch));
    }
}
