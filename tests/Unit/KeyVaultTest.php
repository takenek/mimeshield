<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Exception\ConfigException;
use MimeShield\Exception\CryptoException;
use MimeShield\Exception\MimeShieldException;
use MimeShield\KeyStore\KeyVault;
use MimeShield\KeyStore\MasterKeyProvider;
use MimeShield\Tests\TestPki;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class KeyVaultTest extends TestCase
{
    private const CONTEXT = 'user:42|fp:0123456789abcdef';

    /** @var list<string> */
    private array $envNames = [];

    /** @var list<string> */
    private array $tempDirs = [];

    protected function tearDown(): void
    {
        foreach ($this->envNames as $name) {
            putenv($name);
        }
        foreach ($this->tempDirs as $dir) {
            foreach (glob($dir . '/*') ?: [] as $f) {
                @chmod($f, 0600);
                @unlink($f);
            }
            @rmdir($dir);
        }
    }

    /**
     * @return iterable<string, array{0: int}>
     */
    public static function algorithms(): iterable
    {
        yield 'xchacha20poly1305' => [KeyVault::ALG_XCHACHA20POLY1305];
        yield 'aes256gcm' => [KeyVault::ALG_AES256GCM];
    }

    /**
     * Provider backed by a private environment variable.
     *
     * @param array<string, string> $keys kid => raw 32-byte key
     */
    private function provider(array $keys, string $active = ''): MasterKeyProvider
    {
        $name = 'MIMESHIELD_TEST_MK_' . strtoupper(bin2hex(random_bytes(6)));
        $entries = [];
        foreach ($keys as $kid => $raw) {
            $entries[] = $kid . ':' . base64_encode($raw);
        }
        putenv($name . '=' . implode(',', $entries));
        $this->envNames[] = $name;
        return new MasterKeyProvider('', $name, $active);
    }

    /**
     * Provider backed by a 0400 key file (used for rotation, where the file is rewritten).
     *
     * @param array<string, string> $keys
     */
    private function fileProvider(string $dir, array $keys, string $active = ''): MasterKeyProvider
    {
        $path = $dir . '/master-' . bin2hex(random_bytes(4)) . '.key';
        $lines = ['# test master keys'];
        foreach ($keys as $kid => $raw) {
            $lines[] = $kid . ' ' . base64_encode($raw);
        }
        file_put_contents($path, implode("\n", $lines) . "\n");
        chmod($path, 0400);
        return new MasterKeyProvider($path, '', $active);
    }

    private static function decodeRaw(string $blob): string
    {
        $raw = base64_decode($blob, true);
        self::assertIsString($raw);
        return $raw;
    }

    private static function nonceLength(int $alg): int
    {
        return $alg === KeyVault::ALG_XCHACHA20POLY1305 ? SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES : 12;
    }

    private static function assertCorrupt(callable $fn, string $msg = ''): void
    {
        try {
            $fn();
        } catch (CryptoException $e) {
            self::assertSame('keystorecorrupt', $e->getUserLabel(), $msg . ' / ' . $e->getMessage());
            return;
        }
        self::fail('expected CryptoException keystorecorrupt ' . $msg);
    }

    #[DataProvider('algorithms')]
    public function testRoundtrip(int $alg): void
    {
        $vault = new KeyVault($this->provider(['k1' => random_bytes(32)]), $alg);
        foreach (['', 'x', TestPki::key('alice'), random_bytes(4096), "binary\0\xff\x00tail"] as $pt) {
            $blob = $vault->encrypt($pt, self::CONTEXT);
            self::assertNotSame($pt, $blob);
            self::assertStringNotContainsString('PRIVATE KEY', $blob);
            self::assertSame($pt, $vault->decrypt($blob, self::CONTEXT));
        }
    }

    #[DataProvider('algorithms')]
    public function testBlobFormat(int $alg): void
    {
        $vault = new KeyVault($this->provider(['old' => random_bytes(32), 'k2026a' => random_bytes(32)]), $alg);
        $pt = 'plaintext-of-known-length';
        $raw = self::decodeRaw($vault->encrypt($pt, self::CONTEXT));

        self::assertSame('MSK', substr($raw, 0, 3));
        self::assertSame(KeyVault::FORMAT_VERSION, ord($raw[3]));
        self::assertSame(1, ord($raw[3]));
        self::assertSame($alg, ord($raw[4]));
        self::assertSame(6, ord($raw[5]));
        self::assertSame('k2026a', substr($raw, 6, 6), 'active kid = last listed key');
        self::assertSame(6 + 6 + self::nonceLength($alg) + strlen($pt) + 16, strlen($raw));
        self::assertStringNotContainsString($pt, $raw);
    }

    public function testDefaultAlgorithmIsPreferred(): void
    {
        $vault = new KeyVault($this->provider(['k1' => random_bytes(32)]));
        $raw = self::decodeRaw($vault->encrypt('abc', self::CONTEXT));
        self::assertSame(KeyVault::preferredAlgorithm(), ord($raw[4]));
        self::assertSame(KeyVault::ALG_XCHACHA20POLY1305, KeyVault::preferredAlgorithm(), 'sodium is available on all test PHPs');
    }

    #[DataProvider('algorithms')]
    public function testCrossAlgorithmDecryptUsesBlobHeader(int $alg): void
    {
        $p = $this->provider(['k1' => random_bytes(32)]);
        $other = $alg === KeyVault::ALG_AES256GCM ? KeyVault::ALG_XCHACHA20POLY1305 : KeyVault::ALG_AES256GCM;
        $blob = (new KeyVault($p, $alg))->encrypt('secret', self::CONTEXT);
        self::assertSame('secret', (new KeyVault($p, $other))->decrypt($blob, self::CONTEXT));
    }

    #[DataProvider('algorithms')]
    public function testNonceUniqueAcross1000Encryptions(int $alg): void
    {
        $vault = new KeyVault($this->provider(['k1' => random_bytes(32)]), $alg);
        $nl = self::nonceLength($alg);
        $nonces = [];
        $cts = [];
        for ($i = 0; $i < 1000; $i++) {
            $raw = self::decodeRaw($vault->encrypt('same plaintext', self::CONTEXT));
            $nonces[substr($raw, 8, $nl)] = true;
            $cts[substr($raw, 8 + $nl)] = true;
        }
        self::assertCount(1000, $nonces);
        self::assertCount(1000, $cts);
    }

    #[DataProvider('algorithms')]
    public function testContextBinding(int $alg): void
    {
        $vault = new KeyVault($this->provider(['k1' => random_bytes(32)]), $alg);
        $blob = $vault->encrypt('secret', 'user:1|fp:aa');
        self::assertSame('secret', $vault->decrypt($blob, 'user:1|fp:aa'));
        foreach (['user:2|fp:aa', 'user:1|fp:ab', '', 'user:1|fp:aa ', 'user:1'] as $ctx) {
            self::assertCorrupt(static fn () => $vault->decrypt($blob, $ctx), 'context ' . $ctx);
        }
    }

    /**
     * Flip bits in every byte of the blob: decryption must never return data and must fail closed.
     */
    #[DataProvider('algorithms')]
    public function testTamperingEveryByteNeverDecrypts(int $alg): void
    {
        $vault = new KeyVault($this->provider(['k2026' => random_bytes(32)]), $alg);
        $raw = self::decodeRaw($vault->encrypt('secret key material', self::CONTEXT));
        for ($i = 0, $n = strlen($raw); $i < $n; $i++) {
            foreach ([0x01, 0x80, 0xff] as $mask) {
                $t = $raw;
                $t[$i] = chr(ord($t[$i]) ^ $mask);
                try {
                    $out = $vault->decrypt(base64_encode($t), self::CONTEXT);
                    self::fail(sprintf('tampered byte %d (mask %02x) decrypted to %s', $i, $mask, bin2hex($out)));
                } catch (MimeShieldException $e) {
                    self::assertContains($e->getUserLabel(), ['keystorecorrupt', 'keystoreunavailable']);
                }
            }
        }
    }

    /**
     * Strict requirement: every tampered byte yields CryptoException 'keystorecorrupt'.
     * Fails today for the kid length byte and the kid bytes: a tampered kid that is syntactically valid
     * but unknown escapes as ConfigException 'keystoreunavailable' (deriveKey() runs before the try).
     */
    #[DataProvider('algorithms')]
    public function testTamperingEveryByteIsKeystoreCorrupt(int $alg): void
    {
        $vault = new KeyVault($this->provider(['k2026' => random_bytes(32)]), $alg);
        $raw = self::decodeRaw($vault->encrypt('secret key material', self::CONTEXT));
        $wrong = [];
        for ($i = 0, $n = strlen($raw); $i < $n; $i++) {
            foreach ([0x01, 0x80, 0xff] as $mask) {
                $t = $raw;
                $t[$i] = chr(ord($t[$i]) ^ $mask);
                try {
                    $vault->decrypt(base64_encode($t), self::CONTEXT);
                    $wrong[] = $i . ':decrypted';
                } catch (CryptoException $e) {
                    if ($e->getUserLabel() !== 'keystorecorrupt') {
                        $wrong[] = $i . ':' . $e->getUserLabel();
                    }
                } catch (\Throwable $e) {
                    $wrong[] = sprintf('byte %d mask %02x: %s(%s)', $i, $mask, $e::class, $e->getMessage());
                }
            }
        }
        self::assertSame([], $wrong);
    }

    #[DataProvider('algorithms')]
    public function testTamperedKidToOtherKnownKidFails(int $alg): void
    {
        $p = $this->provider(['ka' => random_bytes(32), 'kb' => random_bytes(32)], 'ka');
        $vault = new KeyVault($p, $alg);
        $raw = self::decodeRaw($vault->encrypt('secret', self::CONTEXT));
        self::assertSame('ka', substr($raw, 6, 2));
        $raw[7] = 'b';
        self::assertCorrupt(static fn () => $vault->decrypt(base64_encode($raw), self::CONTEXT));
    }

    #[DataProvider('algorithms')]
    public function testTruncatedAndExtendedBlobs(int $alg): void
    {
        $vault = new KeyVault($this->provider(['k1' => random_bytes(32)]), $alg);
        $raw = self::decodeRaw($vault->encrypt('secret', self::CONTEXT));
        for ($len = 0, $n = strlen($raw); $len < $n; $len++) {
            self::assertCorrupt(static fn () => $vault->decrypt(base64_encode(substr($raw, 0, $len)), self::CONTEXT), 'len ' . $len);
        }
        self::assertCorrupt(static fn () => $vault->decrypt(base64_encode($raw . "\0"), self::CONTEXT), 'appended byte');
        self::assertCorrupt(static fn () => $vault->decrypt(base64_encode(substr($raw, 0, -1)), self::CONTEXT), 'last byte dropped');
    }

    public function testNonBase64AndGarbage(): void
    {
        $vault = new KeyVault($this->provider(['k1' => random_bytes(32)]));
        foreach (['', '!!!not base64!!!', base64_encode('MSX' . str_repeat("\x01", 60)), base64_encode(random_bytes(80))] as $b) {
            self::assertCorrupt(static fn () => $vault->decrypt($b, self::CONTEXT));
        }
        $blob = $vault->encrypt('secret', self::CONTEXT);
        self::assertCorrupt(static fn () => $vault->decrypt('*' . $blob, self::CONTEXT), 'strict base64');
        self::assertSame('secret', $vault->decrypt(" \n" . $blob, self::CONTEXT), 'base64 whitespace is harmless');
    }

    #[DataProvider('algorithms')]
    public function testUnknownVersion(int $alg): void
    {
        $vault = new KeyVault($this->provider(['k1' => random_bytes(32)]), $alg);
        $raw = self::decodeRaw($vault->encrypt('secret', self::CONTEXT));
        foreach ([0, 2, 255] as $v) {
            $t = $raw;
            $t[3] = chr($v);
            try {
                $vault->decrypt(base64_encode($t), self::CONTEXT);
                self::fail('unknown version accepted');
            } catch (CryptoException $e) {
                self::assertSame('keystorecorrupt', $e->getUserLabel());
                self::assertStringContainsString('version', $e->getMessage());
            }
        }
    }

    #[DataProvider('algorithms')]
    public function testUnknownAlgorithm(int $alg): void
    {
        $vault = new KeyVault($this->provider(['k1' => random_bytes(32)]), $alg);
        $raw = self::decodeRaw($vault->encrypt('secret', self::CONTEXT));
        foreach ([0, 3, 255] as $a) {
            $t = $raw;
            $t[4] = chr($a);
            try {
                $vault->decrypt(base64_encode($t), self::CONTEXT);
                self::fail('unknown alg accepted');
            } catch (CryptoException $e) {
                self::assertSame('keystorecorrupt', $e->getUserLabel());
                self::assertStringContainsString('algorithm', $e->getMessage());
            }
        }
    }

    public function testEncryptWithUnsupportedForcedAlgorithm(): void
    {
        $vault = new KeyVault($this->provider(['k1' => random_bytes(32)]), 9);
        try {
            $vault->encrypt('secret', self::CONTEXT);
            self::fail('unsupported algorithm accepted');
        } catch (CryptoException $e) {
            self::assertSame('keystoreunavailable', $e->getUserLabel());
        }
    }

    #[DataProvider('algorithms')]
    public function testWrongMasterKey(int $alg): void
    {
        $blob = (new KeyVault($this->provider(['k1' => random_bytes(32)]), $alg))->encrypt('secret', self::CONTEXT);
        $other = new KeyVault($this->provider(['k1' => random_bytes(32)]), $alg);
        $before = count($GLOBALS['mimeshield_test_log'] ?? []);
        self::assertCorrupt(static fn () => $other->decrypt($blob, self::CONTEXT));
        $log = array_slice($GLOBALS['mimeshield_test_log'] ?? [], $before);
        self::assertNotEmpty($log);
        self::assertStringContainsString('failed authentication', implode("\n", $log));
        self::assertStringContainsString('kid=k1', implode("\n", $log));
    }

    /**
     * A blob whose master key id is not configured (retired too early, or tampered kid) is reported
     * as a corrupt key store entry; the precise cause is logged for the administrator.
     */
    public function testBlobFromUnavailableKidIsKeystoreCorrupt(): void
    {
        $blob = (new KeyVault($this->provider(['gone' => random_bytes(32)])))->encrypt('secret', self::CONTEXT);
        $vault = new KeyVault($this->provider(['k2' => random_bytes(32)]));
        $before = count($GLOBALS['mimeshield_test_log'] ?? []);
        self::assertCorrupt(static fn () => $vault->decrypt($blob, self::CONTEXT));
        self::assertStringContainsString('unknown master key id', implode("\n", array_slice($GLOBALS['mimeshield_test_log'] ?? [], $before)));
    }

    #[DataProvider('algorithms')]
    public function testRotationRewrap(int $alg): void
    {
        $dir = TestPki::tempDir();
        $this->tempDirs[] = $dir;
        $k1 = random_bytes(32);
        $k2 = random_bytes(32);

        $before = new KeyVault($this->fileProvider($dir, ['k1' => $k1]), $alg);
        $old = $before->encrypt('private key', self::CONTEXT);
        self::assertSame('k1', KeyVault::blobKid($old));

        // rotation: k2 appended, becomes active (last); explicit selection of k1 keeps k1 active
        $pinned = new KeyVault($this->fileProvider($dir, ['k1' => $k1, 'k2' => $k2], 'k1'), $alg);
        self::assertSame($old, $pinned->rewrap($old, self::CONTEXT), 'already current blob unchanged');

        $p = $this->fileProvider($dir, ['k1' => $k1, 'k2' => $k2]);
        self::assertSame('k2', $p->activeKid());
        $vault = new KeyVault($p, $alg);
        self::assertSame('private key', $vault->decrypt($old, self::CONTEXT), 'old blob still decryptable');

        $new = $vault->rewrap($old, self::CONTEXT);
        self::assertNotSame($old, $new);
        self::assertSame('k2', KeyVault::blobKid($new));
        self::assertSame($alg, ord(self::decodeRaw($new)[4]));
        self::assertSame('private key', $vault->decrypt($new, self::CONTEXT));
        self::assertSame($new, $vault->rewrap($new, self::CONTEXT));

        // fresh encryptions use k2
        self::assertSame('k2', KeyVault::blobKid($vault->encrypt('x', self::CONTEXT)));

        // after k1 is retired, the rewrapped blob still works, the old one not
        $retired = new KeyVault($this->fileProvider($dir, ['k2' => $k2]), $alg);
        self::assertSame('private key', $retired->decrypt($new, self::CONTEXT));
        self::assertCorrupt(static fn () => $retired->decrypt($old, self::CONTEXT));
    }

    public function testRewrapWithWrongContextFails(): void
    {
        $k1 = random_bytes(32);
        $old = (new KeyVault($this->provider(['k1' => $k1])))->encrypt('secret', self::CONTEXT);
        $vault = new KeyVault($this->provider(['k1' => $k1, 'k2' => random_bytes(32)]));
        self::assertCorrupt(static fn () => $vault->rewrap($old, 'other context'));
    }

    public function testBlobKid(): void
    {
        $vault = new KeyVault($this->provider(['abc123' => random_bytes(32)]));
        $blob = $vault->encrypt('x', self::CONTEXT);
        self::assertSame('abc123', KeyVault::blobKid($blob));

        self::assertNull(KeyVault::blobKid(''));
        self::assertNull(KeyVault::blobKid('%%%'));
        self::assertNull(KeyVault::blobKid(base64_encode('MSK')));
        self::assertNull(KeyVault::blobKid(base64_encode('XYZ' . "\x01\x01\x02k1" . str_repeat('A', 40))));
        self::assertNull(KeyVault::blobKid(base64_encode("MSK\x01\x01\x00" . str_repeat("\x00", 40))), 'empty kid');
        self::assertNull(KeyVault::blobKid(base64_encode("MSK\x01\x01\x02K!" . str_repeat("\x00", 40))), 'invalid kid chars');
    }

    public function testWipe(): void
    {
        $s = 'top secret';
        KeyVault::wipe($s);
        self::assertSame('', $s);
    }
}
