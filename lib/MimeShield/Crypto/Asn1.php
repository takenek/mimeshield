<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Crypto;

use MimeShield\Exception\ValidationException;

/**
 * Minimal, hardened DER reader.
 *
 * Used ONLY to read structures PHP's OpenSSL extension does not expose (SAN rfc822Name values,
 * KeyUsage/EKU bits, CMS digest/cipher OIDs, RecipientInfo identifiers, signingTime). It never
 * makes trust decisions on its own - all cryptographic checks are done by OpenSSL.
 *
 * Hardening: strict DER length rules (no indefinite length, minimal length encoding), every length
 * checked against the buffer, bounded recursion depth and bounded number of nodes per parse.
 */
final class Asn1
{
    public const CLASS_UNIVERSAL = 0;
    public const CLASS_APPLICATION = 1;
    public const CLASS_CONTEXT = 2;
    public const CLASS_PRIVATE = 3;

    public const TAG_BOOLEAN = 0x01;
    public const TAG_INTEGER = 0x02;
    public const TAG_BIT_STRING = 0x03;
    public const TAG_OCTET_STRING = 0x04;
    public const TAG_NULL = 0x05;
    public const TAG_OID = 0x06;
    public const TAG_UTF8 = 0x0C;
    public const TAG_SEQUENCE = 0x10;
    public const TAG_SET = 0x11;
    public const TAG_PRINTABLE = 0x13;
    public const TAG_T61 = 0x14;
    public const TAG_IA5 = 0x16;
    public const TAG_UTCTIME = 0x17;
    public const TAG_GENTIME = 0x18;
    public const TAG_BMP = 0x1E;

    private const MAX_DEPTH = 32;
    private const MAX_NODES = 20000;

    private int $nodes = 0;

    private bool $eager = true;

    private function __construct(private readonly string $data, private readonly bool $ber = false)
    {
    }

    /**
     * Parse one TLV at offset 0 of $der. The element must span the whole buffer unless $allowTrailing.
     *
     * With $ber the indefinite length form is accepted (CMS produced by some clients is BER encoded);
     * BER mode is only used for read-only inspection, never for certificates.
     */
    public static function parse(string $der, bool $allowTrailing = false, bool $ber = false): Asn1Node
    {
        $p = new self($der, $ber);
        $node = $p->readNode(0, strlen($der), 0);
        if (!$allowTrailing && $node->end() !== strlen($der)) {
            throw new ValidationException('malformed', 'ASN.1: trailing data');
        }
        return $node;
    }

    /**
     * Children of a constructed node.
     *
     * @return list<Asn1Node>
     */
    public static function children(Asn1Node $node): array
    {
        if (!$node->constructed) {
            throw new ValidationException('malformed', 'ASN.1: primitive node has no children');
        }
        $p = new self($node->buffer, $node->ber);
        $out = [];
        $pos = $node->contentOffset;
        $end = $node->contentOffset + $node->length;
        while ($pos < $end) {
            $child = $p->readNode($pos, $end, 0);
            $out[] = $child;
            $pos = $child->end();
            if (count($out) > self::MAX_NODES) {
                throw new ValidationException('malformed', 'ASN.1: too many elements');
            }
        }
        return $out;
    }

    /**
     * Shallow parse of a (possibly huge) DER element: the top element and its direct children are
     * length-checked but not recursively validated; each yielded child must be parsed further with
     * children(), which validates that (small) subtree. Used for long lists such as CRL entries.
     */
    public static function parseShallow(string $der): Asn1Node
    {
        $p = new self($der);
        $p->eager = false;
        $node = $p->readNode(0, strlen($der), 0);
        if ($node->end() !== strlen($der)) {
            throw new ValidationException('malformed', 'ASN.1: trailing data');
        }
        return $node;
    }

    /**
     * Iterate direct children of a constructed node without the global node limit.
     *
     * @return \Generator<int, Asn1Node>
     */
    public static function iterate(Asn1Node $node, int $max = 5000000): \Generator
    {
        if (!$node->constructed) {
            throw new ValidationException('malformed', 'ASN.1: primitive node has no children');
        }
        $pos = $node->contentOffset;
        $end = $node->contentOffset + $node->length;
        $n = 0;
        while ($pos < $end) {
            $p = new self($node->buffer);
            $p->eager = false;
            $child = $p->readNode($pos, $end, 0);
            yield $child;
            $pos = $child->end();
            if (++$n > $max) {
                throw new ValidationException('malformed', 'ASN.1: too many elements');
            }
        }
    }

    /**
     * Parse the content of an OCTET STRING / explicit wrapper as DER.
     */
    public static function parseContent(Asn1Node $node): Asn1Node
    {
        return self::parse($node->content());
    }

    /**
     * Decode an OBJECT IDENTIFIER node to dotted notation.
     */
    public static function oid(Asn1Node $node): string
    {
        if ($node->class !== self::CLASS_UNIVERSAL || $node->tag !== self::TAG_OID || $node->constructed) {
            throw new ValidationException('malformed', 'ASN.1: OID expected');
        }
        $bytes = $node->content();
        $len = strlen($bytes);
        if ($len === 0 || $len > 128) {
            throw new ValidationException('malformed', 'ASN.1: bad OID length');
        }
        $parts = [];
        $value = 0;
        $first = true;
        for ($i = 0; $i < $len; $i++) {
            $b = ord($bytes[$i]);
            if ($value === 0 && $b === 0x80) {
                throw new ValidationException('malformed', 'ASN.1: non-minimal OID');
            }
            if ($value > (PHP_INT_MAX >> 7)) {
                throw new ValidationException('malformed', 'ASN.1: OID arc too large');
            }
            $value = ($value << 7) | ($b & 0x7F);
            if (($b & 0x80) === 0) {
                if ($first) {
                    if ($value < 40) {
                        $parts[] = 0;
                        $parts[] = $value;
                    } elseif ($value < 80) {
                        $parts[] = 1;
                        $parts[] = $value - 40;
                    } else {
                        $parts[] = 2;
                        $parts[] = $value - 80;
                    }
                    $first = false;
                } else {
                    $parts[] = $value;
                }
                $value = 0;
            } elseif ($i === $len - 1) {
                throw new ValidationException('malformed', 'ASN.1: truncated OID');
            }
        }
        return implode('.', $parts);
    }

    /**
     * INTEGER as uppercase hex (unsigned magnitude, leading zero octets stripped).
     */
    public static function integerHex(Asn1Node $node): string
    {
        if ($node->tag !== self::TAG_INTEGER || $node->constructed) {
            throw new ValidationException('malformed', 'ASN.1: INTEGER expected');
        }
        $hex = strtoupper(bin2hex($node->content()));
        $hex = ltrim($hex, '0');
        return $hex === '' ? '0' : (strlen($hex) % 2 ? '0' . $hex : $hex);
    }

    /**
     * Small INTEGER as PHP int.
     */
    public static function integer(Asn1Node $node): int
    {
        $c = $node->content();
        if ($node->tag !== self::TAG_INTEGER || $c === '' || strlen($c) > 7) {
            throw new ValidationException('malformed', 'ASN.1: small INTEGER expected');
        }
        $v = 0;
        foreach (str_split($c) as $ch) {
            $v = ($v << 8) | ord($ch);
        }
        if (ord($c[0]) & 0x80) {
            $v -= 1 << (8 * strlen($c));
        }
        return $v;
    }

    /**
     * UTCTime / GeneralizedTime to unix timestamp.
     */
    public static function time(Asn1Node $node): int
    {
        $s = $node->content();
        if ($node->tag === self::TAG_UTCTIME && preg_match('/^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/D', $s, $m)) {
            $year = (int) $m[1];
            $year += $year < 50 ? 2000 : 1900;
        } elseif ($node->tag === self::TAG_GENTIME && preg_match('/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/D', $s, $m)) {
            $year = (int) $m[1];
        } else {
            throw new ValidationException('malformed', 'ASN.1: bad time');
        }
        [$mon, $day, $hour, $min, $sec] = [(int) $m[2], (int) $m[3], (int) $m[4], (int) $m[5], (int) $m[6]];
        if ($year < 1000 || !checkdate($mon, $day, $year) || $hour > 23 || $min > 59 || $sec > 59) {
            throw new ValidationException('malformed', 'ASN.1: time out of range');
        }
        $dt = \DateTimeImmutable::createFromFormat('!Y-m-d H:i:s', sprintf('%04d-%02d-%02d %02d:%02d:%02d', $year, $mon, $day, $hour, $min, $sec), new \DateTimeZone('UTC'));
        if ($dt === false) {
            throw new ValidationException('malformed', 'ASN.1: bad time value');
        }
        return $dt->getTimestamp();
    }

    /**
     * String types (IA5, Printable, UTF8, T61-as-latin1, BMP) to UTF-8.
     */
    public static function string(Asn1Node $node): string
    {
        $c = $node->content();
        switch ($node->tag) {
            case self::TAG_IA5:
            case self::TAG_PRINTABLE:
                if (preg_match('/[^\x20-\x7E]/', $c)) {
                    throw new ValidationException('malformed', 'ASN.1: non-ASCII in ASCII string');
                }
                return $c;
            case self::TAG_UTF8:
                if (!preg_match('//u', $c)) {
                    throw new ValidationException('malformed', 'ASN.1: invalid UTF-8');
                }
                return $c;
            case self::TAG_T61:
                return mb_convert_encoding($c, 'UTF-8', 'ISO-8859-1');
            case self::TAG_BMP:
                return mb_convert_encoding($c, 'UTF-8', 'UTF-16BE');
        }
        throw new ValidationException('malformed', 'ASN.1: unsupported string type');
    }

    /**
     * BIT STRING content as raw bytes + unused bit count.
     *
     * @return array{0: string, 1: int}
     */
    public static function bitString(Asn1Node $node): array
    {
        $c = $node->content();
        if ($node->tag !== self::TAG_BIT_STRING || $c === '') {
            throw new ValidationException('malformed', 'ASN.1: BIT STRING expected');
        }
        $unused = ord($c[0]);
        if ($unused > 7 || (strlen($c) === 1 && $unused !== 0)) {
            throw new ValidationException('malformed', 'ASN.1: bad BIT STRING');
        }
        return [substr($c, 1), $unused];
    }

    /**
     * Encode a DER length.
     */
    public static function encodeLength(int $len): string
    {
        if ($len < 0x80) {
            return chr($len);
        }
        $bytes = '';
        while ($len > 0) {
            $bytes = chr($len & 0xFF) . $bytes;
            $len >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    /**
     * Encode a TLV from identifier octets and content.
     */
    public static function encode(string $identifier, string $content): string
    {
        return $identifier . self::encodeLength(strlen($content)) . $content;
    }

    /**
     * Return the DER of $root with the descendant at $path (child indices) replaced by $newTlv.
     * All ancestors are re-encoded with correct definite lengths. DER (definite length) input only.
     *
     * @param list<int> $path
     */
    public static function replaceAt(Asn1Node $root, array $path, string $newTlv): string
    {
        if ($path === []) {
            return $newTlv;
        }
        // indefinite-length (BER) ancestors are re-encoded with definite lengths (still valid BER,
        // accepted by OpenSSL); untouched siblings are copied verbatim
        $idx = array_shift($path);
        $children = $root->children();
        if (!isset($children[$idx])) {
            throw new ValidationException('malformed', 'ASN.1: bad path');
        }
        $content = '';
        foreach ($children as $i => $c) {
            $content .= $i === $idx ? self::replaceAt($c, $path, $newTlv) : $c->raw();
        }
        $identifier = substr($root->buffer, $root->offset, $root->identifierLength());
        return self::encode($identifier, $content);
    }

    private function readNode(int $pos, int $limit, int $depth): Asn1Node
    {
        if ($depth > self::MAX_DEPTH) {
            throw new ValidationException('malformed', 'ASN.1: nesting too deep');
        }
        if (++$this->nodes > self::MAX_NODES) {
            throw new ValidationException('malformed', 'ASN.1: too many nodes');
        }
        if ($pos + 2 > $limit) {
            throw new ValidationException('malformed', 'ASN.1: truncated header');
        }
        $start = $pos;
        $b = ord($this->data[$pos++]);
        $class = $b >> 6;
        $constructed = ($b & 0x20) !== 0;
        $tag = $b & 0x1F;
        if ($tag === 0x1F) {
            // high tag number form
            $tag = 0;
            $n = 0;
            do {
                if ($pos >= $limit || ++$n > 4) {
                    throw new ValidationException('malformed', 'ASN.1: bad tag');
                }
                $t = ord($this->data[$pos++]);
                if ($n === 1 && $t === 0x80) {
                    throw new ValidationException('malformed', 'ASN.1: non-minimal tag'); // X.690 8.1.2.4.2 c)
                }
                $tag = ($tag << 7) | ($t & 0x7F);
            } while ($t & 0x80);
            if ($tag < 31) {
                throw new ValidationException('malformed', 'ASN.1: high-tag form for a low tag number');
            }
        }
        if ($pos >= $limit) {
            throw new ValidationException('malformed', 'ASN.1: truncated length');
        }
        $l = ord($this->data[$pos++]);
        if ($l === 0x80) {
            if (!$this->ber || !$constructed) {
                throw new ValidationException('malformed', 'ASN.1: indefinite length not allowed in DER');
            }
            // BER indefinite length: children until end-of-contents (00 00)
            $p = $pos;
            while (true) {
                if ($p + 2 > $limit) {
                    throw new ValidationException('malformed', 'ASN.1: missing end-of-contents');
                }
                if ($this->data[$p] === "\x00" && $this->data[$p + 1] === "\x00") {
                    break;
                }
                $child = $this->readNode($p, $limit, $depth + 1);
                $p = $child->end();
            }
            return new Asn1Node($this->data, $class, $constructed, $tag, $start, $pos, $p - $pos, true, true);
        }
        if ($l & 0x80) {
            $num = $l & 0x7F;
            if ($num > 4 || $pos + $num > $limit) {
                throw new ValidationException('malformed', 'ASN.1: bad length');
            }
            $len = 0;
            for ($i = 0; $i < $num; $i++) {
                $len = ($len << 8) | ord($this->data[$pos++]);
            }
            if ($len < 0x80 || ($num > 1 && $len < (1 << (8 * ($num - 1))))) {
                throw new ValidationException('malformed', 'ASN.1: non-minimal length');
            }
        } else {
            $len = $l;
        }
        if ($len > $limit - $pos) {
            throw new ValidationException('malformed', 'ASN.1: length exceeds buffer');
        }

        $node = new Asn1Node($this->data, $class, $constructed, $tag, $start, $pos, $len, false, $this->ber);

        // validate constructed children eagerly (bounded) so malformed input fails early
        if ($this->eager && $constructed && $depth < self::MAX_DEPTH) {
            $p = $pos;
            $end = $pos + $len;
            while ($p < $end) {
                $child = $this->readNode($p, $end, $depth + 1);
                $p = $child->end();
            }
        }

        return $node;
    }
}
