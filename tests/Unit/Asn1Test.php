<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Crypto\Asn1;
use MimeShield\Crypto\Asn1Node;
use MimeShield\Crypto\CmsInspector;
use MimeShield\Exception\ValidationException;
use MimeShield\Tests\TestPki;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Hardened DER reader (lib/MimeShield/Crypto/Asn1.php, Asn1Node.php).
 *
 * The TLV builders in this test are written independently of Asn1::encode()/encodeLength(), so the
 * parser is never tested against its own encoder.
 */
final class Asn1Test extends TestCase
{
    // ------------------------------------------------------------------ helpers

    /** Independent DER length encoder. */
    private static function len(int $n): string
    {
        if ($n < 0x80) {
            return chr($n);
        }
        $b = ltrim(pack('J', $n), "\x00");
        return chr(0x80 | strlen($b)) . $b;
    }

    private static function tlv(int $id, string $content): string
    {
        return chr($id) . self::len(strlen($content)) . $content;
    }

    private static function seq(string ...$items): string
    {
        return self::tlv(0x30, implode('', $items));
    }

    private static function oidNode(string $contentHex): Asn1Node
    {
        return Asn1::parse("\x06" . self::len(strlen(hex2bin($contentHex))) . hex2bin($contentHex));
    }

    private static function certDer(string $name = 'alice'): string
    {
        return TestPki::cert($name)->der;
    }

    /**
     * Run $fn and assert it throws ValidationException (and nothing else).
     */
    private static function assertRejects(callable $fn, string $messagePart = ''): void
    {
        try {
            $fn();
        } catch (ValidationException $e) {
            if ($messagePart !== '') {
                self::assertStringContainsString($messagePart, $e->getMessage());
            } else {
                self::assertInstanceOf(ValidationException::class, $e);
            }
            return;
        }
        self::fail('expected ValidationException' . ($messagePart !== '' ? ' (' . $messagePart . ')' : ''));
    }

    // ------------------------------------------------------------------ basic structure

    public function testParsesSimpleSequence(): void
    {
        $der = self::seq(self::tlv(0x02, "\x05"), self::tlv(0x05, ''), self::tlv(0x04, 'abc'));
        $n = Asn1::parse($der);
        self::assertSame(Asn1::CLASS_UNIVERSAL, $n->class);
        self::assertTrue($n->constructed);
        self::assertSame(Asn1::TAG_SEQUENCE, $n->tag);
        self::assertSame(0, $n->offset);
        self::assertSame(2, $n->contentOffset);
        self::assertSame(strlen($der) - 2, $n->length);
        self::assertSame(strlen($der), $n->end());
        self::assertSame($der, $n->raw());
        self::assertFalse($n->indefinite);

        $c = $n->children();
        self::assertCount(3, $c);
        self::assertSame(5, Asn1::integer($c[0]));
        self::assertTrue($c[1]->isUniversal(Asn1::TAG_NULL));
        self::assertSame('', $c[1]->content());
        self::assertSame('abc', $c[2]->content());
        self::assertSame("\x04\x03abc", $c[2]->raw());
        self::assertSame($c[2]->raw(), $n->child(2)->raw());
    }

    public function testParsesRealCertificate(): void
    {
        $der = self::certDer();
        $n = Asn1::parse($der);
        $n->expect(Asn1::TAG_SEQUENCE, true);
        $c = $n->children();
        self::assertCount(3, $c); // tbsCertificate, signatureAlgorithm, signature
        self::assertSame('1.2.840.113549.1.1.11', Asn1::oid($c[1]->child(0)));
        [$sig, $unused] = Asn1::bitString($c[2]);
        self::assertSame(0, $unused);
        self::assertGreaterThanOrEqual(256, strlen($sig));
        $tbs = $c[0]->children();
        self::assertTrue($tbs[0]->isContext(0)); // [0] version
        self::assertSame(2, Asn1::integer($tbs[0]->child(0)));
        self::assertSame(TestPki::cert('alice')->serialHex, Asn1::integerHex($tbs[1]));
    }

    public function testChildOutOfRangeAndPrimitiveChildren(): void
    {
        $n = Asn1::parse(self::seq(self::tlv(0x05, '')));
        self::assertRejects(static fn () => $n->child(1), 'missing element 1');
        self::assertRejects(static fn () => $n->child(0)->children(), 'primitive node has no children');
        self::assertRejects(static fn () => Asn1::iterate($n->child(0))->current(), 'primitive');
    }

    public function testExpect(): void
    {
        $n = Asn1::parse(self::seq());
        self::assertSame($n, $n->expect(Asn1::TAG_SEQUENCE, true));
        self::assertRejects(static fn () => $n->expect(Asn1::TAG_SEQUENCE, false), 'expected tag');
        self::assertRejects(static fn () => $n->expect(Asn1::TAG_SET, true), 'expected tag');
        // context tag 16 constructed is NOT a universal SEQUENCE
        $ctx = Asn1::parse("\xB0\x00");
        self::assertSame(Asn1::CLASS_CONTEXT, $ctx->class);
        self::assertSame(16, $ctx->tag);
        self::assertRejects(static fn () => $ctx->expect(Asn1::TAG_SEQUENCE, true));
        self::assertTrue($ctx->isContext(16));
        self::assertFalse($ctx->isUniversal(16));
        self::assertTrue($ctx->is(Asn1::CLASS_CONTEXT, 16));
    }

    public function testClasses(): void
    {
        self::assertSame(Asn1::CLASS_APPLICATION, Asn1::parse("\x41\x00")->class);
        self::assertSame(Asn1::CLASS_CONTEXT, Asn1::parse("\x81\x00")->class);
        self::assertSame(Asn1::CLASS_PRIVATE, Asn1::parse("\xC1\x00")->class);
        self::assertFalse(Asn1::parse("\xC1\x00")->constructed);
        self::assertTrue(Asn1::parse("\xE1\x00")->constructed);
    }

    // ------------------------------------------------------------------ length rules

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function malformedDer(): iterable
    {
        yield 'empty' => ['', 'truncated header'];
        yield 'one byte' => ["\x30", 'truncated header'];
        yield 'indefinite constructed in DER' => ["\x30\x80\x00\x00", 'indefinite length not allowed'];
        yield 'indefinite primitive in DER' => ["\x04\x80\x00\x00", 'indefinite length not allowed'];
        yield 'long form for short length (81 05)' => ["\x04\x81\x05" . 'abcde', 'non-minimal length'];
        yield 'long form 81 7F' => ["\x04\x81\x7F" . str_repeat('a', 127), 'non-minimal length'];
        yield 'leading zero length octet (82 00 80)' => ["\x04\x82\x00\x80" . str_repeat('a', 128), 'non-minimal length'];
        yield 'leading zero length octet (83 00 01 00)' => ["\x04\x83\x00\x01\x00" . str_repeat('a', 256), 'non-minimal length'];
        yield 'five length octets' => ["\x04\x85\x01\x00\x00\x00\x00", 'bad length'];
        yield 'reserved 0xFF length' => ["\x04\xFF", 'bad length'];
        yield 'length octets beyond buffer' => ["\x04\x82\x01", 'bad length'];
        yield 'length beyond buffer (short)' => ["\x04\x05abcd", 'length exceeds buffer'];
        yield 'length beyond buffer (long)' => ["\x04\x82\x01\x00" . str_repeat('a', 255), 'length exceeds buffer'];
        yield 'huge length' => ["\x04\x84\xFF\xFF\xFF\xFF" . 'abc', 'length exceeds buffer'];
        yield 'trailing data' => ["\x05\x00\x00", 'trailing data'];
        yield 'trailing data after sequence' => ["\x30\x00\x05\x00", 'trailing data'];
        yield 'child exceeds parent' => ["\x30\x03\x04\x05abc", 'length exceeds buffer'];
        yield 'child truncated header inside parent' => ["\x30\x01\x05", 'truncated header'];
        yield 'nested indefinite in DER' => ["\x30\x04\x30\x80\x00\x00", 'indefinite length not allowed'];
        yield 'high tag truncated' => ["\x1F\x81", 'bad tag'];
        yield 'high tag missing length' => ["\x1F\x81\x01", 'truncated length'];
        yield 'high tag more than 4 octets' => ["\x1F\x81\x81\x81\x81\x01\x00", 'bad tag'];
    }

    #[DataProvider('malformedDer')]
    public function testRejectsMalformedDer(string $der, string $message): void
    {
        self::assertRejects(static fn () => Asn1::parse($der), $message);
    }

    public function testAllowTrailing(): void
    {
        $n = Asn1::parse("\x04\x01a\xFF\xFF", true);
        self::assertSame('a', $n->content());
        self::assertSame(3, $n->end());
        // the element itself must still be valid
        self::assertRejects(static fn () => Asn1::parse("\x04\x05a", true), 'length exceeds buffer');
    }

    /**
     * @return iterable<string, array{0: int, 1: string}>
     */
    public static function lengthBoundaries(): iterable
    {
        yield '0' => [0, '00'];
        yield '1' => [1, '01'];
        yield '127' => [127, '7f'];
        yield '128' => [128, '8180'];
        yield '255' => [255, '81ff'];
        yield '256' => [256, '820100'];
        yield '65535' => [65535, '82ffff'];
        yield '65536' => [65536, '83010000'];
        yield '16777216' => [16777216, '8401000000'];
    }

    #[DataProvider('lengthBoundaries')]
    public function testEncodeLengthAndMinimalParse(int $len, string $hex): void
    {
        self::assertSame($hex, bin2hex(Asn1::encodeLength($len)));
        if ($len <= 65536) {
            $der = "\x04" . hex2bin($hex) . str_repeat('x', $len);
            $n = Asn1::parse($der);
            self::assertSame($len, $n->length);
            self::assertSame(1 + strlen($hex) / 2, $n->contentOffset);
            self::assertSame(strlen($der), $n->end());
            self::assertSame($der, Asn1::encode("\x04", str_repeat('x', $len)));
        }
    }

    // ------------------------------------------------------------------ BER mode

    public function testBerIndefiniteConstructedAccepted(): void
    {
        // SEQUENCE (indef) { INTEGER 1, OCTET STRING (indef, constructed) { "ab", "cd" } }
        $der = "\x30\x80" . "\x02\x01\x01" . "\x24\x80\x04\x02ab\x04\x02cd\x00\x00" . "\x00\x00";
        self::assertRejects(static fn () => Asn1::parse($der), 'indefinite length not allowed');

        $n = Asn1::parse($der, false, true);
        self::assertTrue($n->indefinite);
        self::assertTrue($n->ber);
        self::assertSame(strlen($der), $n->end());
        self::assertSame($der, $n->raw());
        $c = $n->children();
        self::assertCount(2, $c);
        self::assertSame(1, Asn1::integer($c[0]));
        self::assertTrue($c[1]->indefinite);
        self::assertTrue($c[1]->constructed);
        // BER constructed OCTET STRING: chunks concatenated
        self::assertSame('abcd', $c[1]->content());
    }

    public function testBerDefiniteConstructedOctetStringConcatenated(): void
    {
        $der = "\x24\x08\x04\x02ab\x04\x02cd";
        self::assertSame('abcd', Asn1::parse($der, false, true)->content());
        // in DER mode the raw content is returned (constructed strings are not DER at all)
        self::assertSame("\x04\x02ab\x04\x02cd", Asn1::parse($der)->content());
    }

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function malformedBer(): iterable
    {
        yield 'indefinite primitive' => ["\x04\x80ab\x00\x00", 'indefinite length not allowed'];
        yield 'missing end-of-contents' => ["\x30\x80\x02\x01\x01", 'missing end-of-contents'];
        yield 'only one EOC byte' => ["\x30\x80\x02\x01\x01\x00", 'missing end-of-contents'];
        yield 'trailing after EOC' => ["\x30\x80\x00\x00\x05\x00", 'trailing data'];
        yield 'bad child in indefinite' => ["\x30\x80\x02\x05\x01\x00\x00", 'length exceeds buffer'];
        yield 'non-minimal length in BER mode' => ["\x30\x80\x04\x81\x01a\x00\x00", 'non-minimal length'];
        yield 'nested indefinite beyond parent' => ["\x30\x03\x30\x80\x00\x00", 'missing end-of-contents'];
    }

    #[DataProvider('malformedBer')]
    public function testRejectsMalformedBer(string $der, string $message): void
    {
        self::assertRejects(static fn () => Asn1::parse($der, false, true), $message);
    }

    public function testBerIndefiniteDepthLimited(): void
    {
        $ok = str_repeat("\x30\x80", 30) . str_repeat("\x00\x00", 30);
        self::assertTrue(Asn1::parse($ok, false, true)->indefinite);

        $deep = str_repeat("\x30\x80", 40) . str_repeat("\x00\x00", 40);
        self::assertRejects(static fn () => Asn1::parse($deep, false, true), 'nesting too deep');

        // very deep (stack exhaustion attempt) is rejected quickly as well
        $veryDeep = str_repeat("\x30\x80", 100000) . str_repeat("\x00\x00", 100000);
        $t = microtime(true);
        self::assertRejects(static fn () => Asn1::parse($veryDeep, false, true), 'nesting too deep');
        self::assertLessThan(2.0, microtime(true) - $t);
    }

    public function testReplaceAtReencodesIndefiniteRootWithDefiniteLength(): void
    {
        // SEQUENCE (indefinite) { NULL, INTEGER 7 } -> replace NULL by INTEGER 1
        $n = Asn1::parse("\x30\x80\x05\x00\x02\x01\x07\x00\x00", false, true);
        $out = Asn1::replaceAt($n, [0], "\x02\x01\x01");
        self::assertSame("\x30\x06\x02\x01\x01\x02\x01\x07", $out);
        self::assertSame(1, Asn1::integer(Asn1::parse($out)->child(0)));
        // empty path just returns the replacement
        self::assertSame("\x02\x01\x01", Asn1::replaceAt($n, [], "\x02\x01\x01"));
    }

    // ------------------------------------------------------------------ depth / node limits

    /**
     * Definite-length nesting: eager validation is bounded (MAX_DEPTH) and never recurses unboundedly,
     * while elements deeper than the bound are validated as soon as they are traversed.
     */
    public function testDefiniteNestingDepthBounded(): void
    {
        $levels = 5000;
        $inner = "\x04\x05abc"; // malformed: length exceeds parent
        // build nested SEQUENCEs without quadratic concatenation
        $headers = [];
        $len = strlen($inner);
        for ($i = 0; $i < $levels; $i++) {
            $h = "\x30" . self::len($len);
            $headers[] = $h;
            $len += strlen($h);
        }
        $der = implode('', array_reverse($headers)) . $inner;

        $t = microtime(true);
        $root = Asn1::parse($der); // bounded eager validation does not reach the bad leaf
        self::assertSame(strlen($der), $root->end());

        // walking down validates; the malformed leaf is reported as ValidationException
        $node = $root;
        $caught = null;
        try {
            for ($i = 0; $i < $levels; $i++) {
                $node = $node->child(0);
            }
        } catch (ValidationException $e) {
            $caught = $e;
        }
        self::assertNotNull($caught, 'malformed deep leaf must be rejected on traversal');
        self::assertStringContainsString('length exceeds buffer', $caught->getMessage());
        self::assertLessThan(10.0, microtime(true) - $t);
    }

    public function testMalformedLeafWithinDepthBoundRejectedAtParse(): void
    {
        $der = "\x04\x05abc";
        for ($i = 0; $i < 20; $i++) {
            $der = self::seq($der);
        }
        self::assertRejects(static fn () => Asn1::parse($der), 'length exceeds buffer');
    }

    public function testNodeLimit(): void
    {
        $ok = self::tlv(0x30, str_repeat("\x05\x00", 19999)); // 1 + 19999 = 20000 nodes
        self::assertCount(19999, Asn1::parse($ok)->children());

        $tooMany = self::tlv(0x30, str_repeat("\x05\x00", 20000));
        self::assertRejects(static fn () => Asn1::parse($tooMany), 'too many');

        // children() of a shallow-parsed list is limited as well
        self::assertCount(20000, Asn1::parseShallow($tooMany)->children());
        $shallow = Asn1::parseShallow(self::tlv(0x30, str_repeat("\x05\x00", 20001)));
        self::assertRejects(static fn () => $shallow->children(), 'too many');

        // nested: total node count across the tree is limited
        $nested = self::tlv(0x30, str_repeat(self::seq("\x05\x00", "\x05\x00", "\x05\x00"), 6000));
        self::assertRejects(static fn () => Asn1::parse($nested), 'too many');
    }

    // ------------------------------------------------------------------ shallow parse / iterate

    public function testParseShallowAndIterateLargeList(): void
    {
        $count = 100000;
        // CRL-like entry: SEQUENCE { INTEGER serial, UTCTime }
        $entries = [];
        for ($i = 0; $i < $count; $i++) {
            $serial = pack('N', $i + 0x01000000);
            $entries[] = self::seq(self::tlv(0x02, $serial), self::tlv(0x17, '250101000000Z'));
        }
        $list = self::tlv(0x30, implode('', $entries));
        unset($entries);

        // full parse refuses (node limit) - fast
        $t = microtime(true);
        self::assertRejects(static fn () => Asn1::parse($list), 'too many');

        $memBefore = memory_get_usage();
        $root = Asn1::parseShallow($list);
        $n = 0;
        $last = '';
        foreach (Asn1::iterate($root) as $entry) {
            $c = $entry->children();
            $last = Asn1::integerHex($c[0]);
            if ($n === 0) {
                self::assertSame(1735689600, Asn1::time($c[1]));
            }
            $n++;
        }
        $elapsed = microtime(true) - $t;
        self::assertSame($count, $n);
        self::assertSame(strtoupper(bin2hex(pack('N', $count - 1 + 0x01000000))), $last);
        self::assertLessThan(30.0, $elapsed);
        // streaming: no per-entry objects retained
        self::assertLessThan(8 * 1024 * 1024, memory_get_usage() - $memBefore);
    }

    public function testIterateMaxAndMalformedEntries(): void
    {
        $list = self::tlv(0x30, str_repeat("\x05\x00", 10));
        $root = Asn1::parseShallow($list);
        $n = 0;
        self::assertRejects(static function () use ($root, &$n) {
            foreach (Asn1::iterate($root, 5) as $_) {
                $n++;
            }
        }, 'too many elements');
        self::assertSame(6, $n);

        // shallow parse does not validate entries; iterate reports a broken entry on reach
        $broken = self::tlv(0x30, "\x05\x00\x05\x00\x04\x09abc");
        $root = Asn1::parseShallow($broken);
        $seen = 0;
        self::assertRejects(static function () use ($root, &$seen) {
            foreach (Asn1::iterate($root) as $_) {
                $seen++;
            }
        }, 'length exceeds buffer');
        self::assertSame(2, $seen);

        // the top element itself is length-checked
        self::assertRejects(static fn () => Asn1::parseShallow("\x30\x05\x05\x00"), 'length exceeds buffer');
        self::assertRejects(static fn () => Asn1::parseShallow("\x30\x00\x00"), 'trailing data');
        self::assertRejects(static fn () => Asn1::parseShallow("\x30\x80\x00\x00"), 'indefinite');
    }

    public function testShallowEntryChildrenAreValidated(): void
    {
        // entry whose own content is malformed: children() must reject it
        $list = self::tlv(0x30, self::seq("\x05\x00") . self::tlv(0x30, "\x02\x05\x01"));
        $entries = iterator_to_array(Asn1::iterate(Asn1::parseShallow($list)), false);
        self::assertCount(2, $entries);
        self::assertCount(1, $entries[0]->children());
        self::assertRejects(static fn () => $entries[1]->children(), 'length exceeds buffer');
    }

    // ------------------------------------------------------------------ high tag numbers

    /**
     * @return iterable<string, array{0: string, 1: int, 2: int, 3: int}>
     */
    public static function highTags(): iterable
    {
        yield '[31] context primitive' => ["\x9F\x1F\x01X", Asn1::CLASS_CONTEXT, 31, 2];
        yield '[127] context primitive' => ["\x9F\x7F\x00", Asn1::CLASS_CONTEXT, 127, 2];
        yield '[128] application' => ["\x5F\x81\x00\x00", Asn1::CLASS_APPLICATION, 128, 3];
        yield '[201] private constructed' => ["\xFF\x81\x49\x02\x05\x00", Asn1::CLASS_PRIVATE, 201, 3];
        yield 'max 4 octets' => ["\x9F\xFF\xFF\xFF\x7F\x00", Asn1::CLASS_CONTEXT, 0x0FFFFFFF, 5];
    }

    #[DataProvider('highTags')]
    public function testHighTagNumbers(string $der, int $class, int $tag, int $idLen): void
    {
        $n = Asn1::parse($der);
        self::assertSame($class, $n->class);
        self::assertSame($tag, $n->tag);
        self::assertSame($idLen, $n->identifierLength());
        self::assertSame($idLen + 1, $n->contentOffset);
        self::assertSame($der, $n->raw());
    }

    public function testHighTagInsideSequence(): void
    {
        $der = self::seq("\x9F\x81\x00\x02hi", "\x05\x00");
        $c = Asn1::parse($der)->children();
        self::assertCount(2, $c);
        self::assertSame(128, $c[0]->tag);
        self::assertSame('hi', $c[0]->content());
        self::assertTrue($c[1]->isUniversal(Asn1::TAG_NULL));
    }

    /**
     * X.690 8.1.2.4.2 c): in the high-tag-number form the first subsequent octet must not have bits
     * 7..1 all zero (no leading 0x80 padding), and 8.1.2.4: numbers < 31 must use the low-tag form.
     * Both are invalid even in BER. Accepting them lets "3F 10" masquerade as a universal SEQUENCE,
     * i.e. a parser differential versus OpenSSL.
     */
    public function testNonCanonicalHighTagRejected(): void
    {
        self::assertRejects(static fn () => Asn1::parse("\x9F\x80\x81\x00\x00"), 'tag'); // leading 0x80
        self::assertRejects(static fn () => Asn1::parse("\x3F\x10\x00"), 'tag'); // SEQUENCE in high-tag form
    }

    // ------------------------------------------------------------------ OIDs

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function oids(): iterable
    {
        yield 'sha256' => ['608648016503040201', '2.16.840.1.101.3.4.2.1'];
        yield 'rsaEncryption' => ['2a864886f70d010101', '1.2.840.113549.1.1.1'];
        yield 'authEnvelopedData' => ['2a864886f70d0109100117', '1.2.840.113549.1.9.16.1.23'];
        yield 'first arc 0' => ['27', '0.39'];
        yield 'zero first byte then arc' => ['0027', '0.0.39'];
        yield 'first arc 1' => ['2827', '1.0.39'];
        yield 'first byte 0' => ['00', '0.0'];
        yield 'first arc 2 large second' => ['8837', '2.999'];
        yield 'zero arc' => ['2a0000', '1.2.0.0'];
        yield 'arc 128' => ['2a8100', '1.2.128'];
        yield 'arc 2^32' => ['2a9080808000', '1.2.4294967296'];
        yield 'arc PHP_INT_MAX' => ['2aFFFFFFFFFFFFFFFF7F', '1.2.' . PHP_INT_MAX];
    }

    #[DataProvider('oids')]
    public function testOidDecoding(string $hex, string $expected): void
    {
        self::assertSame($expected, Asn1::oid(self::oidNode($hex)));
    }

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function badOids(): iterable
    {
        yield 'non-minimal arc (leading 0x80)' => ['2a8001', 'non-minimal OID'];
        yield 'non-minimal first arc' => ['802a', 'non-minimal OID'];
        yield 'non-minimal mid arc' => ['2a01808101', 'non-minimal OID'];
        yield 'truncated (last octet has continuation bit)' => ['2a81', 'truncated OID'];
        yield 'truncated single' => ['81', 'truncated OID'];
        yield 'arc overflows 63 bits' => ['2a81808080808080808000', 'OID arc too large'];
        yield 'arc 10 octets' => ['2aFFFFFFFFFFFFFFFFFF7F', 'OID arc too large'];
        yield 'too long' => [str_repeat('2a', 129), 'bad OID length'];
    }

    #[DataProvider('badOids')]
    public function testOidRejectsMalformed(string $hex, string $message): void
    {
        self::assertRejects(static fn () => Asn1::oid(self::oidNode($hex)), $message);
    }

    public function testOidRejectsWrongNode(): void
    {
        self::assertRejects(static fn () => Asn1::oid(Asn1::parse("\x06\x00")), 'bad OID length');
        self::assertRejects(static fn () => Asn1::oid(Asn1::parse("\x04\x01\x2a")), 'OID expected');
        self::assertRejects(static fn () => Asn1::oid(Asn1::parse("\x86\x01\x2a")), 'OID expected'); // [6] implicit
        self::assertRejects(static fn () => Asn1::oid(Asn1::parse("\x26\x03\x04\x01\x2a")), 'OID expected'); // constructed
        $max = '2a' . str_repeat('01', 127); // 128 octets OK
        self::assertSame('1.2' . str_repeat('.1', 127), Asn1::oid(self::oidNode($max)));
    }

    // ------------------------------------------------------------------ INTEGER

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function integerHexCases(): iterable
    {
        yield 'zero' => ['00', '0'];
        yield 'one' => ['01', '01'];
        yield 'positive with sign padding' => ['0080', '80'];
        yield 'nibble' => ['0F', '0F'];
        yield 'three nibbles' => ['0123', '0123'];
        yield 'multi leading zeros stripped' => ['00000ABC', '0ABC'];
        yield 'long serial' => ['7C4E554FE353C733812361C0D619CC2ABA7AF27B', '7C4E554FE353C733812361C0D619CC2ABA7AF27B'];
        yield 'empty content' => ['', '0'];
    }

    #[DataProvider('integerHexCases')]
    public function testIntegerHex(string $contentHex, string $expected): void
    {
        $c = (string) hex2bin($contentHex);
        self::assertSame($expected, Asn1::integerHex(Asn1::parse("\x02" . chr(strlen($c)) . $c)));
    }

    public function testIntegerHexRejectsNonInteger(): void
    {
        self::assertRejects(static fn () => Asn1::integerHex(Asn1::parse("\x04\x01\x01")), 'INTEGER expected');
        self::assertRejects(static fn () => Asn1::integerHex(Asn1::parse("\x22\x03\x04\x01\x01")), 'INTEGER expected');
    }

    /**
     * @return iterable<string, array{0: string, 1: int}>
     */
    public static function smallIntegers(): iterable
    {
        yield '0' => ['00', 0];
        yield '127' => ['7F', 127];
        yield '128' => ['0080', 128];
        yield '-1' => ['FF', -1];
        yield '-128' => ['80', -128];
        yield '-129' => ['FF7F', -129];
        yield '7 octets max' => ['7FFFFFFFFFFFFF', 0x7FFFFFFFFFFFFF];
        yield '7 octets negative' => ['80000000000000', -0x80000000000000];
    }

    #[DataProvider('smallIntegers')]
    public function testSmallInteger(string $hex, int $expected): void
    {
        $c = (string) hex2bin($hex);
        self::assertSame($expected, Asn1::integer(Asn1::parse("\x02" . chr(strlen($c)) . $c)));
    }

    public function testSmallIntegerRejects(): void
    {
        self::assertRejects(static fn () => Asn1::integer(Asn1::parse("\x02\x00")), 'small INTEGER expected');
        self::assertRejects(static fn () => Asn1::integer(Asn1::parse("\x02\x08" . str_repeat("\x01", 8))), 'small INTEGER expected');
        self::assertRejects(static fn () => Asn1::integer(Asn1::parse("\x0A\x01\x01")), 'small INTEGER expected');
    }

    // ------------------------------------------------------------------ time

    /**
     * @return iterable<string, array{0: string, 1: int}>
     */
    public static function validTimes(): iterable
    {
        yield 'utc 2025' => ["\x17\x0D" . '250101000000Z', 1735689600];
        yield 'utc 49 -> 2049' => ["\x17\x0D" . '491231235959Z', 2524607999];
        yield 'utc 50 -> 1950' => ["\x17\x0D" . '500101000000Z', -631152000];
        yield 'utc 70 epoch' => ["\x17\x0D" . '700101000000Z', 0];
        yield 'utc leap day' => ["\x17\x0D" . '240229120000Z', 1709208000];
        yield 'gen 2025' => ["\x18\x0F" . '20250101000000Z', 1735689600];
        yield 'gen 2050' => ["\x18\x0F" . '20500101000000Z', 2524608000];
        yield 'gen 9999' => ["\x18\x0F" . '99991231235959Z', 253402300799];
        yield 'gen fraction' => ["\x18\x13" . '20250101000000.123Z', 1735689600];
    }

    #[DataProvider('validTimes')]
    public function testValidTimes(string $der, int $expected): void
    {
        self::assertSame($expected, Asn1::time(Asn1::parse($der)));
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function syntacticallyInvalidTimes(): iterable
    {
        yield 'utc no Z' => ["\x17\x0C" . '250101000000'];
        yield 'utc with offset' => ["\x17\x11" . '250101000000+0100'];
        yield 'utc without seconds' => ["\x17\x0B" . '2501010000Z'];
        yield 'utc letters' => ["\x17\x0D" . '25O101000000Z'];
        yield 'utc 4-digit year' => ["\x17\x0F" . '20250101000000Z'];
        yield 'gen as utc length' => ["\x18\x0D" . '250101000000Z'];
        yield 'gen local time' => ["\x18\x0E" . '20250101000000'];
        yield 'gen empty fraction' => ["\x18\x10" . '20250101000000.Z'];
        yield 'wrong tag (printable)' => ["\x13\x0D" . '250101000000Z'];
        yield 'empty' => ["\x17\x00"];
        yield 'unicode digits' => ["\x17\x0E" . "\xD9\xA2" . '50101000000Z'];
    }

    #[DataProvider('syntacticallyInvalidTimes')]
    public function testRejectsSyntacticallyInvalidTimes(string $der): void
    {
        self::assertRejects(static fn () => Asn1::time(Asn1::parse($der)), 'bad time');
    }

    /**
     * Out-of-range field values are silently normalised by gmmktime() instead of being rejected
     * (month 13 -> January next year, Feb 30 -> March 2, hour 25 ...), a trailing newline is accepted
     * by the "$" anchor, and GeneralizedTime years 0000-0100 are remapped by gmmktime() (0050 -> 2050).
     *
     * @return iterable<string, array{0: string}>
     */
    public static function semanticallyInvalidTimes(): iterable
    {
        yield 'utc month 13' => ["\x17\x0D" . '251301000000Z'];
        yield 'utc month 00' => ["\x17\x0D" . '250001000000Z'];
        yield 'utc day 32' => ["\x17\x0D" . '250132000000Z'];
        yield 'utc feb 30' => ["\x17\x0D" . '250230000000Z'];
        yield 'utc hour 25' => ["\x17\x0D" . '250101250000Z'];
        yield 'utc minute 60' => ["\x17\x0D" . '250101006000Z'];
        yield 'utc second 61' => ["\x17\x0D" . '250101000061Z'];
        yield 'utc trailing newline' => ["\x17\x0E" . "250101000000Z\n"];
        yield 'gen month 99' => ["\x18\x0F" . '20259901000000Z'];
        yield 'gen trailing newline' => ["\x18\x10" . "20250101000000Z\n"];
        yield 'gen year 0050 remapped to 2050' => ["\x18\x0F" . '00500101000000Z'];
    }

    #[DataProvider('semanticallyInvalidTimes')]
    public function testRejectsSemanticallyInvalidTimes(string $der): void
    {
        self::assertRejects(static fn () => Asn1::time(Asn1::parse($der)), 'time');
    }

    // ------------------------------------------------------------------ strings

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function validStrings(): iterable
    {
        yield 'ia5' => ["\x16\x12" . 'alice@example.test', 'alice@example.test'];
        yield 'printable' => ["\x13\x02" . 'PL', 'PL'];
        yield 'utf8 polish' => ["\x0C\x0A" . 'Zażółć', 'Zażółć'];
        yield 'utf8 empty' => ["\x0C\x00", ''];
        yield 't61 latin1' => ["\x14\x03" . "Z\xF3\xE9", 'Zóé'];
        yield 'bmp' => ["\x1E\x08" . "\x00Z\x00a\x01\x7C\x00\xF3", 'Zażó'];
        yield 'bmp surrogate pair' => ["\x1E\x04" . "\xD8\x3D\xDE\x00", "\u{1F600}"];
    }

    #[DataProvider('validStrings')]
    public function testValidStrings(string $der, string $expected): void
    {
        self::assertSame($expected, Asn1::string(Asn1::parse($der)));
    }

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function invalidStrings(): iterable
    {
        yield 'ia5 8-bit' => ["\x16\x03" . "a\xC3\xB3", 'non-ASCII'];
        yield 'ia5 NUL' => ["\x16\x03" . "a\x00b", 'non-ASCII'];
        yield 'ia5 newline (header injection)' => ["\x16\x0E" . "a@b.test\nBcc:x", 'non-ASCII'];
        yield 'printable 8-bit' => ["\x13\x02" . "P\xFF", 'non-ASCII'];
        yield 'utf8 invalid' => ["\x0C\x02" . "\xC3\x28", 'invalid UTF-8'];
        yield 'utf8 overlong' => ["\x0C\x02" . "\xC0\xAF", 'invalid UTF-8'];
        yield 'utf8 surrogate' => ["\x0C\x03" . "\xED\xA0\x80", 'invalid UTF-8'];
        yield 'octet string' => ["\x04\x01a", 'unsupported string type'];
        yield 'universal string' => ["\x1C\x04\x00\x00\x00a", 'unsupported string type'];
    }

    #[DataProvider('invalidStrings')]
    public function testInvalidStrings(string $der, string $message): void
    {
        self::assertRejects(static fn () => Asn1::string(Asn1::parse($der)), $message);
    }

    public function testBmpOddLengthDoesNotWarn(): void
    {
        // odd-length UTF-16: must not produce a PHP warning; result is valid UTF-8
        $s = Asn1::string(Asn1::parse("\x1E\x03\x00A\x00"));
        self::assertTrue(preg_match('//u', $s) === 1);
        self::assertStringStartsWith('A', $s);
    }

    // ------------------------------------------------------------------ BIT STRING

    /**
     * @return iterable<string, array{0: string, 1: string, 2: int}>
     */
    public static function validBitStrings(): iterable
    {
        yield 'empty' => ["\x03\x01\x00", '', 0];
        yield 'key usage digitalSignature' => ["\x03\x02\x07\x80", "\x80", 7];
        yield 'key usage 2 bytes' => ["\x03\x03\x07\x80\x80", "\x80\x80", 7];
        yield 'no unused' => ["\x03\x03\x00\xAB\xCD", "\xAB\xCD", 0];
    }

    #[DataProvider('validBitStrings')]
    public function testBitString(string $der, string $bytes, int $unused): void
    {
        self::assertSame([$bytes, $unused], Asn1::bitString(Asn1::parse($der)));
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function invalidBitStrings(): iterable
    {
        yield 'no content' => ["\x03\x00"];
        yield 'unused 8' => ["\x03\x02\x08\x00"];
        yield 'unused 255' => ["\x03\x02\xFF\x00"];
        yield 'unused bits without data' => ["\x03\x01\x03"];
        yield 'octet string' => ["\x04\x02\x00\x80"];
    }

    #[DataProvider('invalidBitStrings')]
    public function testInvalidBitString(string $der): void
    {
        self::assertRejects(static fn () => Asn1::bitString(Asn1::parse($der)), 'BIT STRING');
    }

    // ------------------------------------------------------------------ parseContent

    public function testParseContent(): void
    {
        $inner = self::seq("\x05\x00");
        $n = Asn1::parse(self::tlv(0x04, $inner));
        self::assertSame($inner, Asn1::parseContent($n)->raw());
        self::assertRejects(static fn () => Asn1::parseContent(Asn1::parse("\x04\x03\x05\x00\x00")), 'trailing data');
    }

    // ------------------------------------------------------------------ replaceAt

    /**
     * @return iterable<string, array{0: int, 1: int}>
     */
    public static function replaceBoundaries(): iterable
    {
        // [original leaf content length, new leaf content length]
        yield '120 -> 130 (crosses 127/128)' => [120, 130];
        yield '130 -> 120 (shrinks below 128)' => [130, 120];
        yield '123 -> 124 (inner 127 -> 128)' => [123, 124];
        yield '250 -> 260 (crosses 255/256)' => [250, 260];
        yield '260 -> 250' => [260, 250];
        yield '65530 -> 65540 (crosses 65535/65536)' => [65530, 65540];
        yield 'same size' => [10, 10];
        yield 'to empty' => [10, 0];
    }

    #[DataProvider('replaceBoundaries')]
    public function testReplaceAtReencodesAllAncestorLengths(int $oldLen, int $newLen): void
    {
        $leafOld = self::tlv(0x04, str_repeat('o', $oldLen));
        $leafNew = self::tlv(0x04, str_repeat('n', $newLen));
        $sibA = self::tlv(0x02, "\x01");
        $sibB = self::tlv(0x0C, 'tail');
        $build = static fn (string $leaf): string => self::seq(
            $sibA,
            "\xA0" . self::len(strlen(self::seq($leaf, $sibB))) . self::seq($leaf, $sibB),
            $sibB,
        );

        $root = Asn1::parse($build($leafOld));
        $out = Asn1::replaceAt($root, [1, 0, 0], $leafNew);
        self::assertSame(bin2hex($build($leafNew)), bin2hex($out));

        // result is valid DER and structurally intact
        $p = Asn1::parse($out);
        self::assertSame(str_repeat('n', $newLen), $p->child(1)->child(0)->child(0)->content());
        self::assertSame('tail', $p->child(1)->child(0)->child(1)->content());
        self::assertSame('tail', $p->child(2)->content());
        self::assertSame(1, Asn1::integer($p->child(0)));
    }

    public function testReplaceAtPreservesHighTagIdentifier(): void
    {
        $build = static fn (string $inner): string => "\x7F\x81\x00" . self::len(strlen($inner)) . $inner;
        $root = Asn1::parse($build("\x05\x00\x04\x01a"));
        $out = Asn1::replaceAt($root, [1], self::tlv(0x04, str_repeat('b', 200)));
        self::assertSame($build("\x05\x00" . self::tlv(0x04, str_repeat('b', 200))), $out);
        self::assertSame(128, Asn1::parse($out)->tag);
    }

    public function testReplaceAtBadPath(): void
    {
        $root = Asn1::parse(self::seq("\x05\x00"));
        self::assertRejects(static fn () => Asn1::replaceAt($root, [1], "\x05\x00"), 'bad path');
        self::assertRejects(static fn () => Asn1::replaceAt($root, [0, 0], "\x05\x00"), 'primitive');
    }

    public function testReplaceAtInRealCertificateRoundTrip(): void
    {
        $der = self::certDer('bob');
        $root = Asn1::parse($der);
        // replacing the serial number with itself is a no-op
        $serial = $root->child(0)->child(1);
        self::assertSame($der, Asn1::replaceAt($root, [0, 1], $serial->raw()));
        // a longer serial changes tbsCertificate and certificate lengths consistently
        $newSerial = self::tlv(0x02, "\x01" . str_repeat("\x00", 200));
        $out = Asn1::replaceAt($root, [0, 1], $newSerial);
        $tbsParts = array_map(static fn (Asn1Node $n): string => $n->raw(), $root->child(0)->children());
        $tbsParts[1] = $newSerial;
        $expected = self::seq(self::seq(...$tbsParts), $root->child(1)->raw(), $root->child(2)->raw());
        self::assertSame(bin2hex($expected), bin2hex($out));
        self::assertSame('01' . str_repeat('00', 200), Asn1::integerHex(Asn1::parse($out)->child(0)->child(1)));
    }

    // ------------------------------------------------------------------ fuzzing

    /**
     * Generate a deterministic set of mutated buffers from $seed.
     *
     * @return \Generator<int, string>
     */
    private static function mutations(string $seed, int $count, int $rngSeed): \Generator
    {
        mt_srand($rngSeed);
        $len = strlen($seed);
        for ($i = 0; $i < $count; $i++) {
            $buf = $seed;
            switch ($i % 6) {
                case 0: // truncation
                    $buf = substr($seed, 0, mt_rand(0, $len - 1));
                    break;
                case 1: // bit flips
                    $flips = mt_rand(1, 8);
                    for ($f = 0; $f < $flips; $f++) {
                        $p = mt_rand(0, $len - 1);
                        $buf[$p] = chr(ord($buf[$p]) ^ (1 << mt_rand(0, 7)));
                    }
                    break;
                case 2: // random byte overwrite in the header area (lengths/tags)
                    for ($f = 0; $f < 3; $f++) {
                        $p = mt_rand(0, min($len - 1, 64));
                        $buf[$p] = chr(mt_rand(0, 255));
                    }
                    break;
                case 3: // splice: insert or delete a random run
                    $p = mt_rand(0, $len - 1);
                    if (mt_rand(0, 1) === 0) {
                        $buf = substr($seed, 0, $p) . self::rnd(mt_rand(1, 8)) . substr($seed, $p);
                    } else {
                        $buf = substr($seed, 0, $p) . substr($seed, $p + mt_rand(1, 8));
                    }
                    break;
                case 4: // interesting length bytes
                    $p = mt_rand(0, $len - 1);
                    $vals = [0x00, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0xFF];
                    $buf[$p] = chr($vals[mt_rand(0, count($vals) - 1)]);
                    break;
                default: // pure random
                    $buf = self::rnd(mt_rand(0, 300));
                    break;
            }
            yield $buf;
        }
    }

    /**
     * Exercise every public decoding function on $node recursively (bounded).
     */
    private static function walk(Asn1Node $node, int $depth, int &$budget): void
    {
        if (--$budget < 0 || $depth > 40) {
            return;
        }
        foreach ([
            static fn () => Asn1::oid($node),
            static fn () => Asn1::integerHex($node),
            static fn () => Asn1::integer($node),
            static fn () => Asn1::time($node),
            static fn () => Asn1::string($node),
            static fn () => Asn1::bitString($node),
            static fn () => $node->content(),
            static fn () => $node->raw(),
            static fn () => $node->identifierLength(),
        ] as $fn) {
            try {
                $fn();
            } catch (ValidationException) {
            }
        }
        if ($node->constructed) {
            foreach ($node->children() as $c) {
                self::walk($c, $depth + 1, $budget);
            }
        }
    }

    private static function fuzzOne(string $buf): void
    {
        foreach ([[false, false], [true, false], [false, true], [true, true]] as [$trailing, $ber]) {
            try {
                $n = Asn1::parse($buf, $trailing, $ber);
                $budget = 400;
                self::walk($n, 0, $budget);
                if (!$n->indefinite) {
                    $path = $n->constructed && $n->children() !== [] ? [0] : [];
                    Asn1::replaceAt($n, $path, "\x05\x00");
                }
            } catch (ValidationException) {
            }
        }
        try {
            $n = Asn1::parseShallow($buf);
            if ($n->constructed) {
                $i = 0;
                foreach (Asn1::iterate($n, 1000) as $c) {
                    if ($c->constructed) {
                        $c->children();
                    }
                    if (++$i > 50) {
                        break;
                    }
                }
            }
        } catch (ValidationException) {
        }
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function fuzzSeeds(): iterable
    {
        yield 'certificate alice' => ['cert:alice'];
        yield 'certificate carol (EC)' => ['cert:carol'];
        yield 'crl' => ['file:int.crl'];
        yield 'cms signed (BER/indef)' => ['cms:signed'];
    }

    #[DataProvider('fuzzSeeds')]
    public function testFuzzOnlyValidationException(string $seedSpec): void
    {
        [$kind, $name] = explode(':', $seedSpec, 2);
        $seed = match ($kind) {
            'cert' => self::certDer($name),
            'file' => self::crlDer(TestPki::read($name)),
            default => self::berSignedData(),
        };
        self::assertGreaterThan(100, strlen($seed));

        set_error_handler(static function (int $no, string $str, string $file = '', int $line = 0): bool {
            throw new \ErrorException($str, 0, $no, $file, $line);
        });
        $t = microtime(true);
        $n = 0;
        try {
            foreach (self::mutations($seed, 3000, crc32($seedSpec)) as $buf) {
                try {
                    self::fuzzOne($buf);
                } catch (\Throwable $e) {
                    self::fail(sprintf('%s thrown for input %s: %s', get_class($e), bin2hex(substr($buf, 0, 200)), $e->getMessage()));
                }
                $n++;
            }
        } finally {
            restore_error_handler();
        }
        self::assertSame(3000, $n);
        self::assertLessThan(45.0, microtime(true) - $t, 'fuzz run too slow (possible hang)');
    }

    /** Deterministic pseudo-random bytes (mt_rand is seeded per run). */
    private static function rnd(int $n): string
    {
        $s = '';
        for ($i = 0; $i < $n; $i++) {
            $s .= chr(mt_rand(0, 255));
        }
        return $s;
    }

    private static function crlDer(string $data): string
    {
        if (str_contains($data, '-----BEGIN')) {
            $b64 = preg_replace('/-----[^-]+-----|\s+/', '', $data);
            return (string) base64_decode((string) $b64, true);
        }
        return $data;
    }

    /**
     * Indefinite-length SignedData produced by the openssl CLI.
     */
    private static function berSignedData(): string
    {
        $dir = TestPki::tempDir();
        try {
            file_put_contents($dir . '/m.txt', "Content-Type: text/plain\r\n\r\nfuzz\r\n");
            $cmd = sprintf(
                '/usr/bin/openssl cms -sign -binary -stream -indef -nodetach -in %s -signer %s -inkey %s -outform DER -out %s 2>&1',
                escapeshellarg($dir . '/m.txt'),
                escapeshellarg(TestPki::path('alice.crt')),
                escapeshellarg(TestPki::path('alice.key')),
                escapeshellarg($dir . '/s.der'),
            );
            exec($cmd, $out, $rc);
            self::assertSame(0, $rc, implode("\n", $out));
            $der = (string) file_get_contents($dir . '/s.der');
            self::assertSame(CmsInspector::OID_SIGNED_DATA, CmsInspector::contentType($der));
            return $der;
        } finally {
            array_map('unlink', glob($dir . '/*') ?: []);
            rmdir($dir);
        }
    }
}
