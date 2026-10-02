<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Crypto\Asn1;
use MimeShield\Crypto\CmsInspector;
use MimeShield\Crypto\CmsService;
use MimeShield\Exception\ValidationException;
use MimeShield\Tests\TestPki;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * CMS inspection (lib/MimeShield/Crypto/CmsInspector.php) against real structures produced by the
 * openssl CLI at test runtime, plus the AES-GCM aes-ICVlen fix-up used by CmsService::decrypt().
 */
final class CmsInspectorTest extends TestCase
{
    private const OPENSSL = '/usr/bin/openssl';
    private const PLAINTEXT = "Content-Type: text/plain; charset=utf-8\r\n\r\nZa\xC5\xBC\xC3\xB3\xC5\x82\xC4\x87 g\xC4\x99\xC5\x9Bl\xC4\x85 ja\xC5\xBA\xC5\x84\r\n";

    private const OID_RSA = '1.2.840.113549.1.1.1';
    private const OID_RSA_OAEP = '1.2.840.113549.1.1.7';

    private static string $dir = '';

    /** @var array<string, string> */
    private static array $cms = [];

    private static int $createdAt = 0;

    public static function setUpBeforeClass(): void
    {
        self::$dir = TestPki::tempDir();
        self::$createdAt = time();
        $msg = self::$dir . '/msg.txt';
        file_put_contents($msg, self::PLAINTEXT);
        $p = static fn (string $n): string => escapeshellarg(TestPki::path($n));
        $in = escapeshellarg($msg);

        $jobs = [
            'signed' => "cms -sign -binary -in $in -signer {$p('alice.crt')} -inkey {$p('alice.key')}",
            'signed_opaque_keyid' => "cms -sign -binary -nodetach -keyid -md sha384 -certfile {$p('int.crt')} -in $in -signer {$p('alice.crt')} -inkey {$p('alice.key')}",
            'signed_ber' => "cms -sign -binary -stream -indef -nodetach -in $in -signer {$p('alice.crt')} -inkey {$p('alice.key')}",
            'signed_ber_detached' => "cms -sign -binary -stream -indef -in $in -signer {$p('bob.crt')} -inkey {$p('bob.key')} -md sha512",
            'signed_ec' => "cms -sign -binary -in $in -signer {$p('carol.crt')} -inkey {$p('carol.key')}",
            'signed_nosigningtime' => "cms -sign -binary -noattr -in $in -signer {$p('alice.crt')} -inkey {$p('alice.key')}",
            'signed_two' => "cms -sign -binary -in $in -signer {$p('alice.crt')} -inkey {$p('alice.key')} -signer {$p('carol.crt')} -inkey {$p('carol.key')}",
            'env_cbc' => "cms -encrypt -binary -aes-256-cbc -in $in {$p('bob.crt')}",
            'env_cbc128' => "cms -encrypt -binary -aes-128-cbc -in $in {$p('alice.crt')}",
            'env_3des' => "cms -encrypt -binary -des3 -in $in {$p('alice.crt')}",
            'env_oaep' => "cms -encrypt -binary -aes-256-cbc -recip {$p('bob.crt')} -keyopt rsa_padding_mode:oaep -in $in",
            'env_keyid' => "cms -encrypt -binary -aes-256-cbc -keyid -in $in {$p('bob.crt')}",
            'env_ec' => "cms -encrypt -binary -aes-128-cbc -in $in {$p('carol.crt')}",
            'env_ec_keyid' => "cms -encrypt -binary -aes-128-cbc -keyid -in $in {$p('carol.crt')}",
            'env_multi' => "cms -encrypt -binary -aes-256-cbc -in $in {$p('alice.crt')} {$p('carol.crt')} {$p('bob.crt')}",
            'env_ber' => "cms -encrypt -binary -stream -indef -aes-256-cbc -in $in {$p('bob.crt')}",
            'gcm' => "cms -encrypt -binary -aes-256-gcm -in $in {$p('bob.crt')}",
            'gcm128' => "cms -encrypt -binary -aes-128-gcm -in $in {$p('alice.crt')}",
            'gcm_ber' => "cms -encrypt -binary -stream -indef -aes-256-gcm -in $in {$p('bob.crt')}",
            'gcm_ec' => "cms -encrypt -binary -aes-256-gcm -in $in {$p('carol.crt')}",
        ];
        foreach ($jobs as $name => $args) {
            $out = self::$dir . '/' . $name . '.der';
            // positional recipient certificates must come last
            $cmd = self::OPENSSL . ' cms -outform DER -out ' . escapeshellarg($out) . ' ' . substr($args, 4) . ' 2>&1';
            $lines = [];
            exec($cmd, $lines, $rc);
            if ($rc !== 0 || !is_file($out)) {
                self::rmTree(self::$dir); // tearDownAfterClass is not run when setUpBeforeClass fails
                throw new \RuntimeException("openssl failed for $name: " . implode("\n", $lines));
            }
            self::$cms[$name] = (string) file_get_contents($out);
        }
    }

    public static function tearDownAfterClass(): void
    {
        self::rmTree(self::$dir);
        self::$cms = [];
    }

    private static function rmTree(string $dir): void
    {
        if ($dir === '' || !is_dir($dir)) {
            return;
        }
        foreach (scandir($dir) ?: [] as $f) {
            if ($f === '.' || $f === '..') {
                continue;
            }
            $path = $dir . '/' . $f;
            is_dir($path) && !is_link($path) ? self::rmTree($path) : unlink($path);
        }
        rmdir($dir);
    }

    // ------------------------------------------------------------------ independent DER helpers

    private static function len(int $n): string
    {
        if ($n < 0x80) {
            return chr($n);
        }
        $b = ltrim(pack('J', $n), "\x00");
        return chr(0x80 | strlen($b)) . $b;
    }

    /**
     * Minimal TLV header reader (DER/BER, independent of the code under test).
     *
     * @return array{id: string, content: int, len: int, end: int, indef: bool}
     */
    private static function header(string $d, int $pos): array
    {
        $start = $pos;
        $first = ord($d[$pos++]);
        if (($first & 0x1F) === 0x1F) {
            while (ord($d[$pos++]) & 0x80) {
            }
        }
        $id = substr($d, $start, $pos - $start);
        $l = ord($d[$pos++]);
        if ($l === 0x80) {
            $p = $pos;
            while (!($d[$p] === "\x00" && $d[$p + 1] === "\x00")) {
                $p = self::header($d, $p)['end'];
            }
            return ['id' => $id, 'content' => $pos, 'len' => $p - $pos, 'end' => $p + 2, 'indef' => true];
        }
        if ($l & 0x80) {
            $n = $l & 0x7F;
            $l = 0;
            for ($i = 0; $i < $n; $i++) {
                $l = ($l << 8) | ord($d[$pos++]);
            }
        }
        return ['id' => $id, 'content' => $pos, 'len' => $l, 'end' => $pos + $l, 'indef' => false];
    }

    /**
     * @return list<array{start: int, end: int}>
     */
    private static function childSpans(string $d, int $pos): array
    {
        $h = self::header($d, $pos);
        $out = [];
        $p = $h['content'];
        $end = $h['content'] + $h['len'];
        while ($p < $end) {
            $c = self::header($d, $p);
            $out[] = ['start' => $p, 'end' => $c['end']];
            $p = $c['end'];
        }
        return $out;
    }

    /**
     * Re-encode the element at $pos with the descendant at $path transformed by $leaf. Definite-length
     * ancestors get recomputed lengths; indefinite-length ancestors stay indefinite.
     *
     * @param list<int> $path
     * @param callable(string): string $leaf
     */
    private static function rewrite(string $d, int $pos, array $path, callable $leaf): string
    {
        $h = self::header($d, $pos);
        if ($path === []) {
            return $leaf(substr($d, $pos, $h['end'] - $pos));
        }
        $idx = array_shift($path);
        $content = '';
        $found = false;
        foreach (self::childSpans($d, $pos) as $i => $span) {
            if ($i === $idx) {
                $content .= self::rewrite($d, $span['start'], $path, $leaf);
                $found = true;
            } else {
                $content .= substr($d, $span['start'], $span['end'] - $span['start']);
            }
        }
        if (!$found) {
            throw new \RuntimeException('path not found');
        }
        return $h['indef'] ? $h['id'] . "\x80" . $content . "\x00\x00" : $h['id'] . self::len(strlen($content)) . $content;
    }

    /** Path ContentInfo -> [0] -> AuthEnvelopedData -> authEncryptedContentInfo -> alg -> params. */
    private const GCM_PARAMS_PATH = [1, 0, 2, 1, 1];

    /** Path ContentInfo -> [0] -> AuthEnvelopedData -> mac. */
    private const GCM_MAC_PATH = [1, 0, 3];

    /** Drop aes-ICVlen from GCMParameters (keep only aes-nonce). */
    private static function stripIcvLen(string $der): string
    {
        return self::rewrite($der, 0, self::GCM_PARAMS_PATH, static function (string $params): string {
            $spans = self::childSpans($params, 0);
            self::assertCount(2, $spans, 'GCMParameters from openssl must carry nonce + ICVlen');
            $nonce = substr($params, $spans[0]['start'], $spans[0]['end'] - $spans[0]['start']);
            self::assertSame("\x04\x0C", substr($nonce, 0, 2), '12 byte nonce');
            self::assertSame("\x02\x01\x10", substr($params, $spans[1]['start']), 'ICVlen 16');
            return "\x30" . self::len(strlen($nonce)) . $nonce;
        });
    }

    private static function replaceMac(string $der, callable $fn): string
    {
        return self::rewrite($der, 0, self::GCM_MAC_PATH, static function (string $mac) use ($fn): string {
            self::assertSame("\x04\x10", substr($mac, 0, 2));
            $new = $fn(substr($mac, 2));
            return "\x04" . self::len(strlen($new)) . $new;
        });
    }

    /**
     * Raw PHP openssl_cms_decrypt (no fix-up).
     */
    private static function rawDecrypt(string $der, string $certName): string|false
    {
        $in = self::$dir . '/raw-in-' . bin2hex(random_bytes(4));
        $out = $in . '.out';
        file_put_contents($in, $der);
        touch($out);
        try {
            $ok = openssl_cms_decrypt($in, $out, TestPki::read($certName . '.crt'), TestPki::read($certName . '.key'), OPENSSL_ENCODING_DER);
            while (openssl_error_string() !== false) {
            }
            return $ok === true ? (string) file_get_contents($out) : false;
        } finally {
            @unlink($in);
            @unlink($out);
        }
    }

    private static function service(): CmsService
    {
        return new CmsService(self::$dir . '/svc');
    }

    private static function assertRejects(callable $fn, string $messagePart = ''): void
    {
        try {
            $fn();
        } catch (ValidationException $e) {
            self::assertStringContainsString($messagePart, $e->getMessage());
            return;
        }
        self::fail('expected ValidationException');
    }

    // ------------------------------------------------------------------ contentType

    /**
     * @return iterable<string, array{0: string, 1: string, 2: string}>
     */
    public static function contentTypes(): iterable
    {
        yield 'signed' => ['signed', CmsInspector::OID_SIGNED_DATA, 'signed-data'];
        yield 'signed opaque' => ['signed_opaque_keyid', CmsInspector::OID_SIGNED_DATA, 'signed-data'];
        yield 'signed BER' => ['signed_ber', CmsInspector::OID_SIGNED_DATA, 'signed-data'];
        yield 'enveloped CBC' => ['env_cbc', CmsInspector::OID_ENVELOPED_DATA, 'enveloped-data'];
        yield 'enveloped OAEP' => ['env_oaep', CmsInspector::OID_ENVELOPED_DATA, 'enveloped-data'];
        yield 'enveloped EC' => ['env_ec', CmsInspector::OID_ENVELOPED_DATA, 'enveloped-data'];
        yield 'enveloped BER' => ['env_ber', CmsInspector::OID_ENVELOPED_DATA, 'enveloped-data'];
        yield 'authEnveloped GCM' => ['gcm', CmsInspector::OID_AUTH_ENVELOPED_DATA, 'authEnveloped-data'];
        yield 'authEnveloped GCM BER' => ['gcm_ber', CmsInspector::OID_AUTH_ENVELOPED_DATA, 'authEnveloped-data'];
    }

    #[DataProvider('contentTypes')]
    public function testContentType(string $name, string $oid, string $label): void
    {
        $type = CmsInspector::contentType(self::$cms[$name]);
        self::assertSame($oid, $type);
        self::assertSame($label, CmsInspector::contentTypeName($type));
    }

    public function testContentTypeNames(): void
    {
        self::assertSame('data', CmsInspector::contentTypeName(CmsInspector::OID_DATA));
        self::assertSame('compressed-data', CmsInspector::contentTypeName(CmsInspector::OID_COMPRESSED_DATA));
        self::assertSame('unknown', CmsInspector::contentTypeName('1.2.3.4'));
        self::assertSame('unknown', CmsInspector::contentTypeName(''));
    }

    public function testBerInputIsReallyIndefiniteLength(): void
    {
        foreach (['signed_ber', 'signed_ber_detached', 'env_ber', 'gcm_ber'] as $name) {
            self::assertSame("\x30\x80", substr(self::$cms[$name], 0, 2), $name . ' must be BER indefinite');
            // strict DER parsing refuses it, BER inspection accepts it
            self::assertRejects(static fn () => Asn1::parse(self::$cms[$name]), 'indefinite');
        }
    }

    public function testContentTypeToleratesTrailingData(): void
    {
        self::assertSame(CmsInspector::OID_SIGNED_DATA, CmsInspector::contentType(self::$cms['signed'] . "\r\n"));
    }

    public function testContentTypeRejectsGarbage(): void
    {
        self::assertRejects(static fn () => CmsInspector::contentType(''), 'truncated');
        self::assertRejects(static fn () => CmsInspector::contentType("\x31\x00"), 'expected tag');
        self::assertRejects(static fn () => CmsInspector::contentType("\x30\x03\x02\x01\x01"), 'OID expected');
        self::assertRejects(static fn () => CmsInspector::contentType("\x30\x00"), 'missing element 0');
        self::assertRejects(static fn () => CmsInspector::contentType(TestPki::cert('alice')->pem), '');
    }

    // ------------------------------------------------------------------ signedData

    public function testSignedDataDetachedIssuerSerial(): void
    {
        $alice = TestPki::cert('alice');
        $sd = CmsInspector::signedData(self::$cms['signed']);
        self::assertTrue($sd['detached']);
        self::assertSame(['sha256'], $sd['digests']);
        self::assertSame(1, $sd['certificates']);
        self::assertCount(1, $sd['signers']);
        $s = $sd['signers'][0];
        self::assertSame('sha256', $s['digest']);
        self::assertSame('rsa', $s['signature']);
        self::assertSame(['issuer' => $alice->issuerNameDer, 'serial' => $alice->serialHex], $s['sid']);
        self::assertSame(TestPki::cert('int')->subjectNameDer, $s['sid']['issuer']);
        self::assertIsInt($s['signingTime']);
        self::assertGreaterThanOrEqual(self::$createdAt - 5, $s['signingTime']);
        self::assertLessThanOrEqual(time() + 5, $s['signingTime']);
    }

    public function testSignedDataOpaqueSubjectKeyIdentifier(): void
    {
        $alice = TestPki::cert('alice');
        self::assertNotSame('', $alice->subjectKeyId);
        $sd = CmsInspector::signedData(self::$cms['signed_opaque_keyid']);
        self::assertFalse($sd['detached']);
        self::assertSame(['sha384'], $sd['digests']);
        self::assertSame(2, $sd['certificates']); // signer + -certfile int.crt
        $s = $sd['signers'][0];
        self::assertSame('sha384', $s['digest']);
        self::assertSame(['ski' => $alice->subjectKeyId], $s['sid']);
        self::assertNotNull($s['signingTime']);
    }

    public function testSignedDataBerOpaque(): void
    {
        $alice = TestPki::cert('alice');
        $sd = CmsInspector::signedData(self::$cms['signed_ber']);
        self::assertFalse($sd['detached']);
        self::assertSame(['sha256'], $sd['digests']);
        self::assertSame(1, $sd['certificates']);
        self::assertSame(['issuer' => $alice->issuerNameDer, 'serial' => $alice->serialHex], $sd['signers'][0]['sid']);
        self::assertSame('rsa', $sd['signers'][0]['signature']);
        self::assertGreaterThanOrEqual(self::$createdAt - 5, (int) $sd['signers'][0]['signingTime']);

        // the BER constructed eContent OCTET STRING is reassembled by CmsService::extractOpaqueContent
        self::assertSame(self::PLAINTEXT, self::service()->extractOpaqueContent(self::$cms['signed_ber']));
        self::assertSame(self::PLAINTEXT, self::service()->extractOpaqueContent(self::$cms['signed_opaque_keyid']));
        self::assertNull(self::service()->extractOpaqueContent(self::$cms['signed']));
    }

    public function testSignedDataBerDetached(): void
    {
        $bob = TestPki::cert('bob');
        // openssl -stream -indef always embeds the content in DER output: build the detached BER form
        // by dropping eContent from the (indefinite-length) encapContentInfo
        $ber = self::$cms['signed_ber_detached'];
        self::assertFalse(CmsInspector::signedData($ber)['detached']);
        $detached = self::rewrite($ber, 0, [1, 0, 2], static function (string $eci): string {
            $spans = self::childSpans($eci, 0);
            self::assertCount(2, $spans);
            self::assertSame("\x30\x80", substr($eci, 0, 2));
            return "\x30\x80" . substr($eci, $spans[0]['start'], $spans[0]['end'] - $spans[0]['start']) . "\x00\x00";
        });
        self::assertSame("\x30\x80", substr($detached, 0, 2));
        $sd = CmsInspector::signedData($detached);
        self::assertTrue($sd['detached']);
        self::assertSame(['sha512'], $sd['digests']);
        self::assertSame('sha512', $sd['signers'][0]['digest']);
        self::assertSame($bob->serialHex, $sd['signers'][0]['sid']['serial']);
        self::assertSame($bob->issuerNameDer, $sd['signers'][0]['sid']['issuer']);
        self::assertNull(self::service()->extractOpaqueContent($detached));
    }

    public function testSignedDataEcdsa(): void
    {
        $carol = TestPki::cert('carol');
        $sd = CmsInspector::signedData(self::$cms['signed_ec']);
        self::assertSame('ecdsa-sha256', $sd['signers'][0]['signature']);
        self::assertSame('sha256', $sd['signers'][0]['digest']);
        self::assertSame($carol->serialHex, $sd['signers'][0]['sid']['serial']);
    }

    public function testSignedDataWithoutSignedAttributes(): void
    {
        $sd = CmsInspector::signedData(self::$cms['signed_nosigningtime']);
        $s = $sd['signers'][0];
        self::assertNull($s['signingTime']);
        // without signedAttrs the signatureAlgorithm is at index 3 and must still be found
        self::assertSame('rsa', $s['signature']);
        self::assertSame('sha256', $s['digest']);
    }

    public function testSignedDataTwoSigners(): void
    {
        $sd = CmsInspector::signedData(self::$cms['signed_two']);
        self::assertCount(2, $sd['signers']);
        self::assertSame(2, $sd['certificates']);
        // SET OF SignerInfo: DER sorts the elements, so compare order-independently
        $bySerial = [];
        foreach ($sd['signers'] as $s) {
            $bySerial[$s['sid']['serial']] = $s['signature'];
        }
        ksort($bySerial);
        $expected = [TestPki::cert('alice')->serialHex => 'rsa', TestPki::cert('carol')->serialHex => 'ecdsa-sha256'];
        ksort($expected);
        self::assertSame($expected, $bySerial);
        self::assertSame(['sha256'], array_values(array_unique($sd['digests'])));
    }

    public function testSignedDataRejectsOtherTypes(): void
    {
        self::assertRejects(static fn () => CmsInspector::signedData(self::$cms['env_cbc']), 'unexpected content type');
        self::assertRejects(static fn () => CmsInspector::signedData(self::$cms['gcm']), 'unexpected content type');
    }

    // ------------------------------------------------------------------ envelopedData

    public function testEnvelopedCbcIssuerSerial(): void
    {
        $bob = TestPki::cert('bob');
        $ed = CmsInspector::envelopedData(self::$cms['env_cbc']);
        self::assertSame('enveloped-data', $ed['type']);
        self::assertSame('aes-256-cbc', $ed['cipher']);
        self::assertSame([['type' => 'ktri', 'alg' => self::OID_RSA, 'issuer' => $bob->issuerNameDer, 'serial' => $bob->serialHex]], $ed['recipients']);
        self::assertSame('aes-128-cbc', CmsInspector::envelopedData(self::$cms['env_cbc128'])['cipher']);
        self::assertSame('des-ede3-cbc', CmsInspector::envelopedData(self::$cms['env_3des'])['cipher']);
    }

    public function testEnvelopedOaep(): void
    {
        $bob = TestPki::cert('bob');
        $ed = CmsInspector::envelopedData(self::$cms['env_oaep']);
        self::assertSame('aes-256-cbc', $ed['cipher']);
        self::assertCount(1, $ed['recipients']);
        self::assertSame('ktri', $ed['recipients'][0]['type']);
        self::assertSame(self::OID_RSA_OAEP, $ed['recipients'][0]['alg']);
        self::assertSame($bob->serialHex, $ed['recipients'][0]['serial']);
    }

    public function testEnvelopedKtriSubjectKeyIdentifier(): void
    {
        $bob = TestPki::cert('bob');
        $ed = CmsInspector::envelopedData(self::$cms['env_keyid']);
        self::assertSame([['type' => 'ktri', 'alg' => self::OID_RSA, 'ski' => $bob->subjectKeyId]], $ed['recipients']);
    }

    public function testEnvelopedKariForEcRecipient(): void
    {
        $carol = TestPki::cert('carol');
        $ed = CmsInspector::envelopedData(self::$cms['env_ec']);
        self::assertSame('aes-128-cbc', $ed['cipher']);
        self::assertSame([['type' => 'kari', 'issuer' => $carol->issuerNameDer, 'serial' => $carol->serialHex]], $ed['recipients']);

        $ed = CmsInspector::envelopedData(self::$cms['env_ec_keyid']);
        self::assertSame([['type' => 'kari', 'ski' => $carol->subjectKeyId]], $ed['recipients']);
    }

    public function testEnvelopedMultipleRecipients(): void
    {
        $ed = CmsInspector::envelopedData(self::$cms['env_multi']);
        // SET OF RecipientInfo is DER-sorted: compare order-independently
        $bySerial = array_column($ed['recipients'], 'type', 'serial');
        ksort($bySerial);
        $expected = [
            TestPki::cert('alice')->serialHex => 'ktri',
            TestPki::cert('carol')->serialHex => 'kari',
            TestPki::cert('bob')->serialHex => 'ktri',
        ];
        ksort($expected);
        self::assertSame($expected, $bySerial);
        self::assertCount(3, $ed['recipients']);
    }

    public function testEnvelopedBer(): void
    {
        $bob = TestPki::cert('bob');
        $ed = CmsInspector::envelopedData(self::$cms['env_ber']);
        self::assertSame('enveloped-data', $ed['type']);
        self::assertSame('aes-256-cbc', $ed['cipher']);
        self::assertSame($bob->serialHex, $ed['recipients'][0]['serial']);
        // and it still decrypts through the service
        self::assertSame(self::PLAINTEXT, self::service()->decrypt(self::$cms['env_ber'], $bob, TestPki::key('bob')));
    }

    public function testAuthEnvelopedGcm(): void
    {
        $bob = TestPki::cert('bob');
        $ed = CmsInspector::envelopedData(self::$cms['gcm']);
        self::assertSame('authEnveloped-data', $ed['type']);
        self::assertSame('aes-256-gcm', $ed['cipher']);
        self::assertSame([['type' => 'ktri', 'alg' => self::OID_RSA, 'issuer' => $bob->issuerNameDer, 'serial' => $bob->serialHex]], $ed['recipients']);
        self::assertSame('aes-128-gcm', CmsInspector::envelopedData(self::$cms['gcm128'])['cipher']);
        self::assertSame('aes-256-gcm', CmsInspector::envelopedData(self::$cms['gcm_ber'])['cipher']);
        $ec = CmsInspector::envelopedData(self::$cms['gcm_ec']);
        self::assertSame('kari', $ec['recipients'][0]['type']);
    }

    public function testEnvelopedRejectsSigned(): void
    {
        self::assertRejects(static fn () => CmsInspector::envelopedData(self::$cms['signed']), 'not enveloped');
    }

    public function testEnvelopedUnknownCipherOidPassedThrough(): void
    {
        // replace the content-encryption OID by an unknown one (same length)
        $der = self::rewrite(self::$cms['env_cbc'], 0, [1, 0, 2, 1, 0], static fn (string $oid): string => "\x06\x09" . "\x2B\x06\x01\x04\x01\x82\x37\x01\x01");
        self::assertSame('1.3.6.1.4.1.311.1.1', CmsInspector::envelopedData($der)['cipher']);
    }

    // ------------------------------------------------------------------ GCM aes-ICVlen fix-up

    public function testGcmFromOpensslDecryptsUnmodified(): void
    {
        // sanity: the reference structure itself is decryptable by PHP and by the service
        self::assertSame(self::PLAINTEXT, self::rawDecrypt(self::$cms['gcm'], 'bob'));
        self::assertSame(self::PLAINTEXT, self::service()->decrypt(self::$cms['gcm'], TestPki::cert('bob'), TestPki::key('bob')));
        self::assertSame(self::PLAINTEXT, self::service()->decrypt(self::$cms['gcm_ec'], TestPki::cert('carol'), TestPki::key('carol')));
    }

    public function testFixGcmIcvLengthRestoresStrippedParameters(): void
    {
        $orig = self::$cms['gcm'];
        $stripped = self::stripIcvLen($orig);
        self::assertSame(strlen($orig) - 3, strlen($stripped));
        // the stripped structure is still well-formed DER and inspectable
        self::assertSame('aes-256-gcm', CmsInspector::envelopedData($stripped)['cipher']);

        // OpenSSL refuses GCMParameters without aes-ICVlen
        self::assertFalse(self::rawDecrypt($stripped, 'bob'));

        // the fix inserts INTEGER 16 (= mac length) and yields exactly the original encoding
        $fixed = CmsInspector::fixGcmIcvLength($stripped);
        self::assertNotNull($fixed);
        self::assertSame(bin2hex($orig), bin2hex($fixed));

        // CmsService::decrypt applies the fix transparently
        self::assertSame(self::PLAINTEXT, self::service()->decrypt($stripped, TestPki::cert('bob'), TestPki::key('bob')));
    }

    public function testFixGcmIcvLengthAes128AndKari(): void
    {
        $stripped = self::stripIcvLen(self::$cms['gcm128']);
        self::assertFalse(self::rawDecrypt($stripped, 'alice'));
        self::assertSame(self::$cms['gcm128'], CmsInspector::fixGcmIcvLength($stripped));
        self::assertSame(self::PLAINTEXT, self::service()->decrypt($stripped, TestPki::cert('alice'), TestPki::key('alice')));

        $strippedEc = self::stripIcvLen(self::$cms['gcm_ec']);
        self::assertSame(self::$cms['gcm_ec'], CmsInspector::fixGcmIcvLength($strippedEc));
        self::assertSame(self::PLAINTEXT, self::service()->decrypt($strippedEc, TestPki::cert('carol'), TestPki::key('carol')));
    }

    public function testFixGcmIcvLengthUsesActualMacLength(): void
    {
        // RFC 5084: 12-byte ICV (truncated GCM tag) with aes-ICVlen omitted (DEFAULT 12)
        $stripped12 = self::replaceMac(self::stripIcvLen(self::$cms['gcm']), static fn (string $tag): string => substr($tag, 0, 12));
        $fixed = CmsInspector::fixGcmIcvLength($stripped12);
        self::assertNotNull($fixed);
        $params = Asn1::parse($fixed)->child(1)->child(0)->child(2)->child(1)->child(1);
        self::assertCount(2, $params->children());
        self::assertSame(12, Asn1::integer($params->child(1)));
        self::assertSame(12, strlen(Asn1::parse($fixed)->child(1)->child(0)->child(3)->content()));
    }

    public function testFixedGcmStillAuthenticates(): void
    {
        // tampered tag: fix-up is applied but GCM authentication must still fail -> no plaintext
        $tampered = self::replaceMac(self::stripIcvLen(self::$cms['gcm']), static fn (string $tag): string => $tag ^ str_repeat("\x00", 15) . "\x01");
        self::assertNotNull(CmsInspector::fixGcmIcvLength($tampered));
        self::assertNull(self::service()->decrypt($tampered, TestPki::cert('bob'), TestPki::key('bob')));

        // tampered ciphertext with intact tag
        $ctTampered = self::rewrite(self::stripIcvLen(self::$cms['gcm']), 0, [1, 0, 2, 2], static function (string $ec): string {
            $ec[5] = chr(ord($ec[5]) ^ 0x01);
            return $ec;
        });
        self::assertNull(self::service()->decrypt($ctTampered, TestPki::cert('bob'), TestPki::key('bob')));

        // wrong key: not decryptable, no exception
        self::assertNull(self::service()->decrypt(self::stripIcvLen(self::$cms['gcm']), TestPki::cert('alice'), TestPki::key('alice')));
    }

    public function testFixGcmIcvLengthReturnsNullWhenNotApplicable(): void
    {
        self::assertNull(CmsInspector::fixGcmIcvLength(self::$cms['gcm']), 'ICVlen already present');
        self::assertNull(CmsInspector::fixGcmIcvLength(self::$cms['gcm128']), 'ICVlen already present');
        self::assertNull(CmsInspector::fixGcmIcvLength(self::$cms['env_cbc']), 'EnvelopedData');
        self::assertNull(CmsInspector::fixGcmIcvLength(self::$cms['env_ec']), 'EnvelopedData kari');
        self::assertNull(CmsInspector::fixGcmIcvLength(self::$cms['signed']), 'SignedData');
        self::assertNull(CmsInspector::fixGcmIcvLength(''), 'empty');
        self::assertNull(CmsInspector::fixGcmIcvLength("\x30\x03\x02\x01\x01"), 'garbage');
        self::assertNull(CmsInspector::fixGcmIcvLength(str_repeat("\xA5\x30", 32)), 'junk');

        // mac shorter than 12 or longer than 16: not a valid ICV length -> no fix
        $stripped = self::stripIcvLen(self::$cms['gcm']);
        self::assertNull(CmsInspector::fixGcmIcvLength(self::replaceMac($stripped, static fn (string $t): string => substr($t, 0, 8))));
        self::assertNull(CmsInspector::fixGcmIcvLength(self::replaceMac($stripped, static fn (string $t): string => $t . "\x00")));
        self::assertNull(CmsInspector::fixGcmIcvLength(self::replaceMac($stripped, static fn (string $t): string => substr($t, 0, 11))));
        self::assertNotNull(CmsInspector::fixGcmIcvLength(self::replaceMac($stripped, static fn (string $t): string => substr($t, 0, 13))));

        // trailing bytes after the DER structure: strict parse -> no fix
        self::assertNull(CmsInspector::fixGcmIcvLength($stripped . "\x00"));
    }

    /**
     * The fix-up only works on DER (Asn1::parse strict, replaceAt refuses indefinite lengths), so an
     * indefinite-length (BER) AuthEnvelopedData with omitted aes-ICVlen - a streaming encoder's natural
     * output - is still undecryptable. BER is otherwise accepted for CMS inspection (contentType,
     * envelopedData) and OpenSSL decrypts BER GCM when aes-ICVlen is present.
     */
    public function testFixGcmIcvLengthHandlesBerAuthEnvelopedData(): void
    {
        $bob = TestPki::cert('bob');
        self::assertSame(self::PLAINTEXT, self::rawDecrypt(self::$cms['gcm_ber'], 'bob'));
        $strippedBer = self::stripIcvLen(self::$cms['gcm_ber']);
        self::assertSame("\x30\x80", substr($strippedBer, 0, 2));
        self::assertFalse(self::rawDecrypt($strippedBer, 'bob'));
        self::assertSame(self::PLAINTEXT, self::service()->decrypt($strippedBer, $bob, TestPki::key('bob')));
    }

    // ------------------------------------------------------------------ micalg / digest names

    /**
     * @return iterable<string, array{0: string, 1: ?string}>
     */
    public static function micalgCases(): iterable
    {
        yield 'sha256' => ['sha256', 'sha-256'];
        yield 'sha384' => ['sha384', 'sha-384'];
        yield 'sha512' => ['sha512', 'sha-512'];
        yield 'sha1 (not used for new signatures)' => ['sha1', null];
        yield 'md5' => ['md5', null];
        yield 'sha224' => ['sha224', null];
        yield 'unknown oid' => ['1.2.3.4', null];
        yield 'case sensitive' => ['SHA256', null];
        yield 'empty' => ['', null];
    }

    #[DataProvider('micalgCases')]
    public function testMicalg(string $digest, ?string $expected): void
    {
        self::assertSame($expected, CmsInspector::micalg($digest));
    }

    public function testDigestName(): void
    {
        self::assertSame('sha256', CmsInspector::digestName('2.16.840.1.101.3.4.2.1'));
        self::assertSame('sha384', CmsInspector::digestName('2.16.840.1.101.3.4.2.2'));
        self::assertSame('sha512', CmsInspector::digestName('2.16.840.1.101.3.4.2.3'));
        self::assertSame('sha224', CmsInspector::digestName('2.16.840.1.101.3.4.2.4'));
        self::assertSame('sha1', CmsInspector::digestName('1.3.14.3.2.26'));
        self::assertSame('md5', CmsInspector::digestName('1.2.840.113549.2.5'));
        self::assertSame('1.2.3.4', CmsInspector::digestName('1.2.3.4'));
    }

    public function testMicalgForProducedSignatures(): void
    {
        $map = [];
        foreach (['signed', 'signed_opaque_keyid', 'signed_ber_detached'] as $name) {
            $d = CmsInspector::signedData(self::$cms[$name])['signers'][0]['digest'];
            $map[$name] = CmsInspector::micalg($d);
        }
        self::assertSame(['signed' => 'sha-256', 'signed_opaque_keyid' => 'sha-384', 'signed_ber_detached' => 'sha-512'], $map);
    }

    // ------------------------------------------------------------------ fuzzing

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function fuzzSeeds(): iterable
    {
        yield 'signed DER' => ['signed'];
        yield 'signed BER' => ['signed_ber'];
        yield 'enveloped kari' => ['env_multi'];
        yield 'authEnveloped' => ['gcm'];
        yield 'authEnveloped stripped' => ['gcm:stripped'];
    }

    #[DataProvider('fuzzSeeds')]
    public function testFuzzInspectorOnlyValidationException(string $spec): void
    {
        $seed = $spec === 'gcm:stripped' ? self::stripIcvLen(self::$cms['gcm']) : self::$cms[$spec];
        $len = strlen($seed);
        mt_srand(crc32($spec));
        set_error_handler(static function (int $no, string $str, string $file = '', int $line = 0): bool {
            throw new \ErrorException($str, 0, $no, $file, $line);
        });
        $t = microtime(true);
        $fixedCount = 0;
        try {
            for ($i = 0; $i < 2000; $i++) {
                $buf = $seed;
                switch ($i % 4) {
                    case 0:
                        $buf = substr($seed, 0, mt_rand(0, $len - 1));
                        break;
                    case 1:
                        for ($f = mt_rand(1, 6); $f > 0; $f--) {
                            $p = mt_rand(0, $len - 1);
                            $buf[$p] = chr(ord($buf[$p]) ^ (1 << mt_rand(0, 7)));
                        }
                        break;
                    case 2:
                        $p = mt_rand(0, $len - 1);
                        $vals = [0x00, 0x30, 0x31, 0x80, 0x81, 0x82, 0xA0, 0xA1, 0xFF];
                        $buf[$p] = chr($vals[mt_rand(0, count($vals) - 1)]);
                        break;
                    default:
                        $p = mt_rand(0, $len - 1);
                        $buf = substr($seed, 0, $p) . substr($seed, $p + mt_rand(1, 4));
                        break;
                }
                foreach ([
                    static fn () => CmsInspector::contentType($buf),
                    static fn () => CmsInspector::signedData($buf),
                    static fn () => CmsInspector::envelopedData($buf),
                ] as $fn) {
                    try {
                        $fn();
                    } catch (ValidationException) {
                    } catch (\Throwable $e) {
                        self::fail(sprintf('%s for input %s: %s', get_class($e), bin2hex($buf), $e->getMessage()));
                    }
                }
                try {
                    $fixed = CmsInspector::fixGcmIcvLength($buf);
                } catch (\Throwable $e) {
                    self::fail(sprintf('fixGcmIcvLength threw %s for input %s: %s', get_class($e), bin2hex($buf), $e->getMessage()));
                }
                if ($fixed !== null) {
                    $fixedCount++;
                    // anything returned must be well-formed DER of the same content type
                    self::assertSame(CmsInspector::OID_AUTH_ENVELOPED_DATA, Asn1::oid(Asn1::parse($fixed)->child(0)));
                }
            }
        } finally {
            restore_error_handler();
        }
        self::assertLessThan(45.0, microtime(true) - $t, 'possible hang');
        if ($spec === 'gcm:stripped') {
            // truncations/flips usually break it, but unrelated mutations keep it fixable
            self::assertGreaterThan(0, $fixedCount);
        } elseif ($spec !== 'gcm') {
            self::assertSame(0, $fixedCount, 'non-AuthEnvelopedData must never be patched');
        }
    }
}
