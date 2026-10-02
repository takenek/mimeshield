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
 * One parsed DER element (value object, references the original buffer).
 */
final class Asn1Node
{
    public function __construct(
        public readonly string $buffer,
        public readonly int $class,
        public readonly bool $constructed,
        public readonly int $tag,
        public readonly int $offset,
        public readonly int $contentOffset,
        public readonly int $length,
        public readonly bool $indefinite = false,
        public readonly bool $ber = false,
    ) {
    }

    /**
     * Offset just past this element (including a BER end-of-contents marker).
     */
    public function end(): int
    {
        return $this->contentOffset + $this->length + ($this->indefinite ? 2 : 0);
    }

    /**
     * Number of identifier octets.
     */
    public function identifierLength(): int
    {
        $n = 1;
        if ((ord($this->buffer[$this->offset]) & 0x1F) === 0x1F) {
            while (ord($this->buffer[$this->offset + $n]) & 0x80) {
                $n++;
            }
            $n++;
        }
        return $n;
    }

    /**
     * Content octets. For BER constructed strings (OCTET STRING split into chunks) the chunks are
     * concatenated.
     */
    public function content(): string
    {
        if ($this->constructed && $this->class === Asn1::CLASS_UNIVERSAL && $this->tag === Asn1::TAG_OCTET_STRING && $this->ber) {
            $out = '';
            foreach ($this->children() as $c) {
                $out .= $c->content();
            }
            return $out;
        }
        return substr($this->buffer, $this->contentOffset, $this->length);
    }

    /**
     * Full TLV encoding.
     */
    public function raw(): string
    {
        return substr($this->buffer, $this->offset, $this->end() - $this->offset);
    }

    public function is(int $class, int $tag): bool
    {
        return $this->class === $class && $this->tag === $tag;
    }

    public function isUniversal(int $tag): bool
    {
        return $this->class === Asn1::CLASS_UNIVERSAL && $this->tag === $tag;
    }

    public function isContext(int $tag): bool
    {
        return $this->class === Asn1::CLASS_CONTEXT && $this->tag === $tag;
    }

    /**
     * @return list<Asn1Node>
     */
    public function children(): array
    {
        return Asn1::children($this);
    }

    /**
     * Child at index (constructed nodes), throws when missing.
     */
    public function child(int $index): self
    {
        $c = $this->children();
        if (!isset($c[$index])) {
            throw new ValidationException('malformed', 'ASN.1: missing element ' . $index);
        }
        return $c[$index];
    }

    /**
     * Assert universal tag and return $this (fluent validation).
     */
    public function expect(int $tag, bool $constructed): self
    {
        if ($this->class !== Asn1::CLASS_UNIVERSAL || $this->tag !== $tag || $this->constructed !== $constructed) {
            throw new ValidationException('malformed', sprintf('ASN.1: expected tag %d, got class %d tag %d', $tag, $this->class, $this->tag));
        }
        return $this;
    }
}
