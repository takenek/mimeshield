<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Cert;

use MimeShield\Crypto\Asn1;
use MimeShield\Crypto\Asn1Node;
use MimeShield\Exception\ValidationException;

/**
 * Pre-flight check of password-based KDF cost parameters in PKCS#12 files and PKCS#8
 * EncryptedPrivateKeyInfo, BEFORE they are handed to OpenSSL.
 *
 * OpenSSL performs the full key derivation with whatever iteration count the file declares (also
 * for the PKCS#12 MAC, i.e. before the password is known to be wrong). A tiny upload with an
 * iteration count of 2^31 would keep a PHP worker busy for minutes (CPU DoS by any logged-in user).
 * Legitimate files use 1 000 - 600 000 iterations.
 */
final class KdfInspector
{
    public const MAX_ITERATIONS = 2000000;
    public const MAX_TOTAL_ITERATIONS = 6000000;

    private const OID_PBKDF2 = '1.2.840.113549.1.5.12';
    private const OID_PBES2 = '1.2.840.113549.1.5.13';
    private const OID_SCRYPT = '1.3.6.1.4.1.11591.4.11';
    private const PKCS12_PBE_PREFIX = '1.2.840.113549.1.12.1.';   // pbeWithSHAAnd... (iterations in params)
    private const PKCS5_PBES1 = ['1.2.840.113549.1.5.3', '1.2.840.113549.1.5.6', '1.2.840.113549.1.5.10', '1.2.840.113549.1.5.11'];

    private int $total = 0;

    private int $nodes = 0;

    /**
     * Check a DER PKCS#12 (PFX) or PKCS#8 structure. Throws ValidationException when a cost
     * parameter is excessive or the structure cannot be inspected.
     */
    public static function check(string $der, string $errorLabel): void
    {
        $self = new self();
        try {
            $root = Asn1::parse($der, true, true);
            $self->walk($root, 0, $errorLabel);
        } catch (ValidationException $e) {
            if ($e->getUserLabel() === $errorLabel && str_starts_with($e->getMessage(), 'KDF')) {
                throw $e;
            }
            throw new ValidationException($errorLabel, 'structure not inspectable: ' . $e->getMessage());
        }
    }

    /**
     * DER bodies of encrypted PEM private keys ("ENCRYPTED PRIVATE KEY", PKCS#8) in $pem.
     *
     * @return list<string>
     */
    public static function encryptedPkcs8Blocks(string $pem): array
    {
        preg_match_all('/-----BEGIN ENCRYPTED PRIVATE KEY-----\s*([A-Za-z0-9+\/=\s]+?)\s*-----END ENCRYPTED PRIVATE KEY-----/', $pem, $m);
        $out = [];
        foreach ($m[1] as $b64) {
            $der = base64_decode((string) preg_replace('/\s+/', '', $b64), true);
            if ($der !== false && $der !== '') {
                $out[] = $der;
            }
        }
        return $out;
    }

    private function walk(Asn1Node $node, int $depth, string $label): void
    {
        if ($depth > 24 || ++$this->nodes > 20000) {
            throw new ValidationException($label, 'KDF: structure too complex');
        }

        if ($node->isUniversal(Asn1::TAG_SEQUENCE) && $node->constructed) {
            $children = $node->children();
            if (isset($children[0]) && $children[0]->isUniversal(Asn1::TAG_OID)) {
                $this->algorithm(Asn1::oid($children[0]), $children[1] ?? null, $label);
            }
            // PFX MacData ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING, iterations INTEGER }
            if (count($children) === 3 && $children[0]->isUniversal(Asn1::TAG_SEQUENCE)
                && $children[1]->isUniversal(Asn1::TAG_OCTET_STRING) && $children[2]->isUniversal(Asn1::TAG_INTEGER)) {
                $this->iterations($children[2], $label);
            }
        }

        if ($node->constructed) {
            foreach ($node->children() as $c) {
                $this->walk($c, $depth + 1, $label);
            }
        } elseif ($node->isUniversal(Asn1::TAG_OCTET_STRING)) {
            // authSafe / SafeContents / bag values are DER inside OCTET STRINGs
            $content = $node->content();
            if ($content !== '' && ($content[0] === "\x30" || $content[0] === "\xA0")) {
                try {
                    $inner = Asn1::parse($content, false, true);
                } catch (ValidationException) {
                    return; // opaque data (e.g. encrypted bytes)
                }
                $this->walk($inner, $depth + 1, $label);
            }
        }
    }

    private function algorithm(string $oid, ?Asn1Node $params, string $label): void
    {
        if ($params === null || !$params->constructed) {
            return;
        }
        $p = $params->children();
        if ($oid === self::OID_PBKDF2 || str_starts_with($oid, self::PKCS12_PBE_PREFIX) || in_array($oid, self::PKCS5_PBES1, true)) {
            // PBKDF2-params / PKCS12PBEParams / PBEParameter: SEQUENCE { salt, iterationCount, ... }
            if (isset($p[1]) && $p[1]->isUniversal(Asn1::TAG_INTEGER)) {
                $this->iterations($p[1], $label);
            }
        } elseif ($oid === self::OID_SCRYPT) {
            // scrypt-params: SEQUENCE { salt, costParameter N, blockSize r, parallelizationParameter p, keyLength? }
            $n = isset($p[1]) ? self::bigInt($p[1]) : PHP_INT_MAX;
            $r = isset($p[2]) ? self::bigInt($p[2]) : PHP_INT_MAX;
            $par = isset($p[3]) ? self::bigInt($p[3]) : PHP_INT_MAX;
            if ($n > (1 << 20) || $r > 32 || $par > 4) {
                throw new ValidationException($label, 'KDF: scrypt parameters too expensive');
            }
        } elseif ($oid === self::OID_PBES2) {
            // the nested keyDerivationFunc AlgorithmIdentifier is reached by the recursive walk
            return;
        }
    }

    private function iterations(Asn1Node $int, string $label): void
    {
        $n = self::bigInt($int);
        if ($n < 1 || $n > self::MAX_ITERATIONS) {
            throw new ValidationException($label, 'KDF: iteration count out of range');
        }
        $this->total += $n;
        if ($this->total > self::MAX_TOTAL_ITERATIONS) {
            throw new ValidationException($label, 'KDF: total iteration count too high');
        }
    }

    /**
     * Non-negative INTEGER, saturating at PHP_INT_MAX (never overflows).
     */
    private static function bigInt(Asn1Node $node): int
    {
        if (!$node->isUniversal(Asn1::TAG_INTEGER)) {
            return PHP_INT_MAX;
        }
        $c = ltrim($node->content(), "\x00");
        if ($c === '' ) {
            return 0;
        }
        if (strlen($c) > 7 || (ord($node->content()[0]) & 0x80)) {
            return PHP_INT_MAX;
        }
        $v = 0;
        foreach (str_split($c) as $ch) {
            $v = ($v << 8) | ord($ch);
        }
        return $v;
    }
}
