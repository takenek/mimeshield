<?php

declare(strict_types=1);

/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Original author: Marek Królikowski (TaKeN)
 * Original project: https://github.com/takenek/mimeshield
 * SPDX-License-Identifier: GPL-3.0-or-later
 * See LICENSE and COPYRIGHT for the license and GPL section 7 attribution terms.
 *
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
 *
 * Parameters inside ENCRYPTED SafeContents (PKCS#12 EncryptedData, e.g. a shrouded key bag hidden
 * in an encrypted layer) are not visible without the password. When the password is given, every
 * encrypted layer is decrypted here (after its own cost was checked) and inspected as well, so the
 * whole operation stays within one budget before OpenSSL runs any of it (audit MS-05). A layer the
 * password does not decrypt is reported as a wrong password; a layer using a cipher this PHP/OpenSSL
 * cannot run is reported as legacy (the opt-in CLI converter runs in a separate, time-limited process).
 *
 * The PFX is inspected along its schema (RFC 7292: authSafe -> ContentInfo -> SafeContents -> bags,
 * MacData), always on the content of OCTET STRINGs with BER segments joined - exactly what OpenSSL
 * reads. Anything the schema requires to be DER that does not parse, and any content type OpenSSL
 * would process that this class cannot inspect, rejects the import (fail closed, audit F-03).
 *
 * Besides the declared iterations (MAX_TOTAL_ITERATIONS), the key derivation this class runs itself
 * in PHP is bounded by the real work: iterations x hash blocks x password encodings (audit F-08).
 */
final class KdfInspector
{
    public const MAX_ITERATIONS = 2000000;
    public const MAX_TOTAL_ITERATIONS = 6000000;

    private const OID_PBKDF2 = '1.2.840.113549.1.5.12';
    private const OID_PBES2 = '1.2.840.113549.1.5.13';
    private const OID_SCRYPT = '1.3.6.1.4.1.11591.4.11';
    private const PKCS12_PBE_PREFIX = '1.2.840.113549.1.12.1.';   // pbeWithSHAAnd... (iterations in params)
    private const PKCS5_PBES1 = [
        '1.2.840.113549.1.5.1', '1.2.840.113549.1.5.3', '1.2.840.113549.1.5.4',
        '1.2.840.113549.1.5.6', '1.2.840.113549.1.5.10', '1.2.840.113549.1.5.11',
    ];

    /** PBKDF2 keyLength above any supported cipher key or HMAC output is never derived */
    private const MAX_PBKDF2_KEY_LENGTH = 64;

    private const OID_DATA = '1.2.840.113549.1.7.1';
    private const OID_ENCRYPTED_DATA = '1.2.840.113549.1.7.6';
    private const OID_SHROUDED_KEY_BAG = '1.2.840.113549.1.12.10.1.2';
    private const OID_SAFE_CONTENTS_BAG = '1.2.840.113549.1.12.10.1.6';

    /**
     * Hash compression rounds the PKCS#12 PBE key derivation of this class may run in PHP per
     * inspection (iterations x output blocks x password encodings; about one second of CPU).
     */
    public const MAX_PHP_KDF_WORK = 12000000;

    /** PBES2 encryption schemes (OID => [OpenSSL cipher, key bytes, iv bytes]) */
    private const PBES2_CIPHERS = [
        '2.16.840.1.101.3.4.1.2' => ['aes-128-cbc', 16, 16],
        '2.16.840.1.101.3.4.1.22' => ['aes-192-cbc', 24, 16],
        '2.16.840.1.101.3.4.1.42' => ['aes-256-cbc', 32, 16],
        '1.2.840.113549.3.7' => ['des-ede3-cbc', 24, 8],
    ];

    /** PBKDF2 PRFs (OID => hash); hmacWithSHA1 is the default */
    private const PBKDF2_PRFS = [
        '1.2.840.113549.2.7' => 'sha1',
        '1.2.840.113549.2.8' => 'sha224',
        '1.2.840.113549.2.9' => 'sha256',
        '1.2.840.113549.2.10' => 'sha384',
        '1.2.840.113549.2.11' => 'sha512',
    ];

    /** PKCS#12 password based encryption (RFC 7292 appendix C): OID => [cipher, key bytes, iv bytes] */
    private const PKCS12_PBE = [
        '1.2.840.113549.1.12.1.1' => ['rc4', 16, 0],
        '1.2.840.113549.1.12.1.2' => ['rc4-40', 5, 0],
        '1.2.840.113549.1.12.1.3' => ['des-ede3-cbc', 24, 8],
        '1.2.840.113549.1.12.1.4' => ['des-ede-cbc', 16, 8],
        '1.2.840.113549.1.12.1.5' => ['rc2-cbc', 16, 8],
        '1.2.840.113549.1.12.1.6' => ['rc2-40-cbc', 5, 8],
    ];

    private const MAX_ENCRYPTED_LAYERS = 8;

    private int $total = 0;

    private int $nodes = 0;

    private int $layers = 0;

    private int $work = 0;

    /** @var array<string, bool> */
    private static array $cipherAvailable = [];

    private function __construct(#[\SensitiveParameter] private readonly ?string $password = null)
    {
    }

    /**
     * Check a DER PKCS#12 (PFX) or PKCS#8 structure. Throws ValidationException when a cost
     * parameter is excessive or the structure cannot be inspected.
     *
     * With $password, encrypted PKCS#12 SafeContents are decrypted and inspected too ('badpassword'
     * when the password does not decrypt them, 'p12legacy' for a cipher that is not available).
     */
    public static function check(string $der, string $errorLabel, #[\SensitiveParameter] ?string $password = null): void
    {
        $self = new self($password);
        try {
            $root = Asn1::parse($der, true, true);
            $c = $root->isUniversal(Asn1::TAG_SEQUENCE) && $root->constructed ? $root->children() : [];
            if (count($c) >= 2 && count($c) <= 3 && $c[0]->isUniversal(Asn1::TAG_INTEGER) && $c[1]->isUniversal(Asn1::TAG_SEQUENCE)) {
                $self->pfx($c, $errorLabel);
            } elseif (count($c) === 2 && $c[0]->isUniversal(Asn1::TAG_SEQUENCE) && $c[1]->isUniversal(Asn1::TAG_OCTET_STRING)) {
                // PKCS#8 EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm, encryptedData }
                $self->encryptionAlgorithm($c[0], $errorLabel, 'malformed');
            } else {
                throw new ValidationException('malformed', 'neither PFX nor EncryptedPrivateKeyInfo');
            }
        } catch (ValidationException $e) {
            if ($e->getUserLabel() === $errorLabel && str_starts_with($e->getMessage(), 'KDF')) {
                throw $e;
            }
            if (in_array($e->getUserLabel(), ['badpassword', 'p12legacy'], true)) {
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

    /**
     * PFX ::= SEQUENCE { version INTEGER, authSafe ContentInfo, macData MacData OPTIONAL }
     *
     * @param list<Asn1Node> $c
     */
    private function pfx(array $c, string $label): void
    {
        // authSafe: ContentInfo of type data whose OCTET STRING is the AuthenticatedSafe (the
        // public-key integrity mode with signedData is not supported by openssl_pkcs12_read either)
        [$type, $content] = $this->contentInfo($c[1], $label);
        if ($type !== self::OID_DATA) {
            throw new ValidationException('malformed', 'PFX authSafe is not data');
        }
        foreach ($this->derOctets($content, $label)->children() as $ci) {
            $this->authSafeEntry($ci, $label);
        }
        if (isset($c[2])) {
            // MacData ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING, iterations INTEGER DEFAULT 1 }
            $m = $c[2]->isUniversal(Asn1::TAG_SEQUENCE) && $c[2]->constructed ? $c[2]->children() : [];
            if (count($m) < 2 || !$m[0]->isUniversal(Asn1::TAG_SEQUENCE) || !$m[0]->constructed) {
                throw new ValidationException('malformed', 'bad MacData');
            }
            // DigestInfo.digestAlgorithm (PBMAC1 carries PBKDF2 parameters, RFC 9579)
            $this->algorithmIdentifier($m[0]->child(0), 0, $label);
            if (isset($m[2])) {
                if (!$m[2]->isUniversal(Asn1::TAG_INTEGER)) {
                    throw new ValidationException($label, 'KDF: MAC iteration count is not an INTEGER');
                }
                $this->iterations($m[2], $label);
            }
        }
    }

    /**
     * One ContentInfo of the AuthenticatedSafe: data (plain SafeContents) or encryptedData; any other
     * type cannot be inspected and is refused.
     */
    private function authSafeEntry(Asn1Node $ci, string $label): void
    {
        [$type, $content] = $this->contentInfo($ci, $label);
        if ($type === self::OID_DATA) {
            $this->safeContents($this->derOctets($content, $label), 0, $label);
            return;
        }
        if ($type !== self::OID_ENCRYPTED_DATA) {
            throw new ValidationException('malformed', 'unsupported PKCS#12 content type ' . $type);
        }
        // EncryptedData ::= SEQUENCE { version, EncryptedContentInfo ::= SEQUENCE { contentType,
        // contentEncryptionAlgorithm, encryptedContent [0] IMPLICIT OCTET STRING OPTIONAL } }
        $ed = $content->isUniversal(Asn1::TAG_SEQUENCE) && $content->constructed ? $content->children() : [];
        $eci = isset($ed[1]) && $ed[1]->isUniversal(Asn1::TAG_SEQUENCE) && $ed[1]->constructed ? $ed[1]->children() : [];
        if (count($eci) < 2 || !$eci[1]->isUniversal(Asn1::TAG_SEQUENCE) || !$eci[1]->constructed) {
            throw new ValidationException('malformed', 'bad EncryptedData');
        }
        $this->encryptionAlgorithm($eci[1], $label, 'p12legacy');   // its own cost is counted first
        if ($this->password !== null && isset($eci[2]) && $eci[2]->isContext(0)) {
            $plain = $this->decryptLayer($eci[1], self::octets($eci[2]), $label);
            if ($plain !== null) {
                // a new structure: shared node / layer / iteration budget
                $this->safeContents(Asn1::parse($plain, false, true), 0, $label);
            }
        }
    }

    /**
     * SafeContents ::= SEQUENCE OF SafeBag { bagId, bagValue [0] EXPLICIT, bagAttributes SET OPTIONAL }
     */
    private function safeContents(Asn1Node $node, int $depth, string $label): void
    {
        if ($depth > 8 || !$node->isUniversal(Asn1::TAG_SEQUENCE) || !$node->constructed) {
            throw new ValidationException('malformed', 'bad SafeContents');
        }
        foreach ($node->children() as $bag) {
            $this->count($label);
            $b = $bag->isUniversal(Asn1::TAG_SEQUENCE) && $bag->constructed ? $bag->children() : [];
            if (count($b) < 2 || !$b[0]->isUniversal(Asn1::TAG_OID) || !$b[1]->isContext(0) || !$b[1]->constructed) {
                throw new ValidationException('malformed', 'bad SafeBag');
            }
            $oid = Asn1::oid($b[0]);
            $value = $b[1]->child(0);
            if ($oid === self::OID_SHROUDED_KEY_BAG) {
                // EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm, encryptedData }
                if (!$value->isUniversal(Asn1::TAG_SEQUENCE) || !$value->constructed) {
                    throw new ValidationException('malformed', 'bad shrouded key bag');
                }
                $this->encryptionAlgorithm($value->child(0), $label, 'p12legacy');
            } elseif ($oid === self::OID_SAFE_CONTENTS_BAG) {
                $this->safeContents($value, $depth + 1, $label);
            }
            // keyBag, certBag, crlBag, secretBag and unknown bags run no key derivation
        }
    }

    /**
     * ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
     *
     * @return array{0: string, 1: Asn1Node}
     */
    private function contentInfo(Asn1Node $node, string $label): array
    {
        $this->count($label);
        $c = $node->isUniversal(Asn1::TAG_SEQUENCE) && $node->constructed ? $node->children() : [];
        if (count($c) !== 2 || !$c[0]->isUniversal(Asn1::TAG_OID) || !$c[1]->isContext(0) || !$c[1]->constructed) {
            throw new ValidationException('malformed', 'bad ContentInfo');
        }
        return [Asn1::oid($c[0]), $c[1]->child(0)];
    }

    /**
     * DER inside an OCTET STRING (primitive, or BER constructed: the segments are joined first).
     * Content that does not parse is refused, never skipped.
     */
    private function derOctets(Asn1Node $node, string $label): Asn1Node
    {
        $this->count($label);
        if (!$node->isUniversal(Asn1::TAG_OCTET_STRING)) {
            throw new ValidationException('malformed', 'OCTET STRING expected');
        }
        $inner = Asn1::parse($node->content(), false, true);
        if (!$inner->isUniversal(Asn1::TAG_SEQUENCE) || !$inner->constructed) {
            throw new ValidationException('malformed', 'SEQUENCE expected inside OCTET STRING');
        }
        return $inner;
    }

    /**
     * Password based encryption AlgorithmIdentifier of a key or SafeContents: only schemes whose cost
     * parameters this class understands are accepted; anything else would run a key derivation that
     * was never inspected (fail closed, F-03). $unsupported is the label for an unknown scheme.
     */
    private function encryptionAlgorithm(Asn1Node $node, string $label, string $unsupported): void
    {
        $c = $node->isUniversal(Asn1::TAG_SEQUENCE) && $node->constructed ? $node->children() : [];
        $oid = isset($c[0]) && $c[0]->isUniversal(Asn1::TAG_OID) ? Asn1::oid($c[0]) : '';
        $known = isset(self::PKCS12_PBE[$oid]) || in_array($oid, self::PKCS5_PBES1, true);
        if ($oid === self::OID_PBES2) {
            // PBES2-params ::= SEQUENCE { keyDerivationFunc AlgorithmIdentifier, encryptionScheme }
            $params = isset($c[1]) && $c[1]->isUniversal(Asn1::TAG_SEQUENCE) && $c[1]->constructed ? $c[1]->children() : [];
            $kdf = isset($params[0]) && $params[0]->constructed ? $params[0]->children() : [];
            $kdfOid = isset($kdf[0]) && $kdf[0]->isUniversal(Asn1::TAG_OID) ? Asn1::oid($kdf[0]) : '';
            $known = $kdfOid === self::OID_PBKDF2 || $kdfOid === self::OID_SCRYPT;
        }
        if (!$known) {
            throw new ValidationException($unsupported, 'unsupported key encryption algorithm ' . ($oid !== '' ? $oid : '(none)'));
        }
        $this->algorithmIdentifier($node, 0, $label);
    }

    /**
     * Cost parameters anywhere inside an AlgorithmIdentifier (PBES2 -> PBKDF2, PBMAC1 -> PBKDF2,
     * PKCS#12 PBE, PBES1, scrypt).
     */
    private function algorithmIdentifier(Asn1Node $node, int $depth, string $label): void
    {
        $this->count($label);
        if ($depth > 6 || !$node->constructed) {
            return;
        }
        $children = $node->children();
        if ($node->isUniversal(Asn1::TAG_SEQUENCE) && isset($children[0]) && $children[0]->isUniversal(Asn1::TAG_OID)) {
            $this->algorithm(Asn1::oid($children[0]), $children[1] ?? null, $label);
        }
        foreach ($children as $c) {
            $this->algorithmIdentifier($c, $depth + 1, $label);
        }
    }

    private function count(string $label): void
    {
        if (++$this->nodes > 20000) {
            throw new ValidationException($label, 'KDF: structure too complex');
        }
    }

    /**
     * Decrypt one encrypted PKCS#12 layer with the user's password.
     *
     * null: the layer uses a known cipher that this PHP/OpenSSL cannot run (e.g. RC2 without the
     * legacy provider) - openssl_pkcs12_read() cannot decrypt it either, so nothing inside it is ever
     * executed in this process (the result stays "legacy" / "wrong password" as before).
     */
    private function decryptLayer(Asn1Node $alg, string $ciphertext, string $label): ?string
    {
        if (++$this->layers > self::MAX_ENCRYPTED_LAYERS) {
            throw new ValidationException($label, 'KDF: too many encrypted layers');
        }
        $a = $alg->children();
        $oid = $a[0]->isUniversal(Asn1::TAG_OID) ? Asn1::oid($a[0]) : '';
        $params = isset($a[1]) && $a[1]->constructed ? $a[1]->children() : [];

        if ($oid === self::OID_PBES2) {
            // PBES2-params ::= SEQUENCE { keyDerivationFunc (PBKDF2), encryptionScheme }
            $kdf = isset($params[0]) && $params[0]->constructed ? $params[0]->children() : [];
            $enc = isset($params[1]) && $params[1]->constructed ? $params[1]->children() : [];
            if (!isset($kdf[0], $kdf[1], $enc[0], $enc[1]) || Asn1::oid($kdf[0]) !== self::OID_PBKDF2) {
                throw new ValidationException('p12legacy', 'encrypted PKCS#12 layer: unsupported PBES2 key derivation');
            }
            $scheme = self::PBES2_CIPHERS[Asn1::oid($enc[0])] ?? null;
            $kp = $kdf[1]->children();
            $prf = 'sha1';
            foreach (array_slice($kp, 2) as $opt) {
                if ($opt->isUniversal(Asn1::TAG_SEQUENCE) && $opt->constructed) {
                    $prf = self::PBKDF2_PRFS[Asn1::oid($opt->child(0))] ?? '';
                }
            }
            if ($scheme === null || $prf === '' || !isset($kp[0], $kp[1]) || !$kp[0]->isUniversal(Asn1::TAG_OCTET_STRING)
                || !$enc[1]->isUniversal(Asn1::TAG_OCTET_STRING)) {
                throw new ValidationException('p12legacy', 'encrypted PKCS#12 layer: unsupported PBES2 parameters');
            }
            $iter = self::layerIterations($kp[1], $label);
            [$cipher, $keyLen, $ivLen] = $scheme;
            if (!self::cipherAvailable($cipher, $keyLen, $ivLen)) {
                return null;
            }
            $hashLen = ['sha1' => 20, 'sha224' => 28, 'sha256' => 32, 'sha384' => 48, 'sha512' => 64][$prf];
            $this->work += $iter * (int) ceil($keyLen / $hashLen);
            if ($this->work > self::MAX_PHP_KDF_WORK) {
                throw new ValidationException($label, 'KDF: key derivation work budget exceeded');
            }
            $key = openssl_pbkdf2((string) $this->password, $kp[0]->content(), $keyLen, $iter, $prf);
            $plain = is_string($key) ? openssl_decrypt($ciphertext, $cipher, $key, OPENSSL_RAW_DATA, $enc[1]->content()) : false;
            if (is_string($plain) && self::isDer($plain)) {
                return $plain;
            }
            throw new ValidationException('badpassword', 'encrypted PKCS#12 layer cannot be decrypted with the password');
        }

        if (isset(self::PKCS12_PBE[$oid])) {
            [$cipher, $keyLen, $ivLen] = self::PKCS12_PBE[$oid];
            if (!isset($params[0], $params[1]) || !$params[0]->isUniversal(Asn1::TAG_OCTET_STRING)) {
                throw new ValidationException('p12legacy', 'encrypted PKCS#12 layer: bad PBE parameters');
            }
            $iter = self::layerIterations($params[1], $label);
            if (!self::cipherAvailable($cipher, $keyLen, $ivLen)) {
                return null;
            }
            $salt = $params[0]->content();
            $passwords = self::bmpPasswords((string) $this->password);
            // real work of the PHP derivation below: every output block repeats all iterations, and
            // every password encoding repeats everything (F-08)
            $blocks = (int) ceil($keyLen / 20) + ($ivLen > 0 ? (int) ceil($ivLen / 20) : 0);
            $this->work += $iter * $blocks * count($passwords);
            if ($this->work > self::MAX_PHP_KDF_WORK) {
                throw new ValidationException($label, 'KDF: key derivation work budget exceeded');
            }
            foreach ($passwords as $pw) {
                $key = self::pkcs12Kdf($pw, $salt, 1, $iter, $keyLen);
                $iv = $ivLen > 0 ? self::pkcs12Kdf($pw, $salt, 2, $iter, $ivLen) : '';
                $plain = openssl_decrypt($ciphertext, $cipher, $key, OPENSSL_RAW_DATA, $iv);
                if (is_string($plain) && self::isDer($plain)) {
                    return $plain;
                }
            }
            throw new ValidationException('badpassword', 'encrypted PKCS#12 layer cannot be decrypted with the password');
        }

        throw new ValidationException('p12legacy', 'encrypted PKCS#12 layer: unsupported algorithm ' . $oid);
    }

    /**
     * Password encodings OpenSSL may have used for PKCS#12 PBE (BMPString of the UTF-8 password and
     * the legacy byte-wise conversion; for an empty password also the "no password" form).
     *
     * @return list<string>
     */
    private static function bmpPasswords(#[\SensitiveParameter] string $password): array
    {
        $out = [];
        if (mb_check_encoding($password, 'UTF-8')) {
            $out[] = mb_convert_encoding($password, 'UTF-16BE', 'UTF-8') . "\x00\x00";
        }
        $ascii = '';
        foreach (str_split($password) as $ch) {
            $ascii .= "\x00" . $ch;
        }
        $out[] = $ascii . "\x00\x00";
        if ($password === '') {
            $out[] = '';
        }
        return array_values(array_unique($out));
    }

    /**
     * PKCS#12 key derivation with SHA-1 (RFC 7292 appendix B.2).
     */
    private static function pkcs12Kdf(#[\SensitiveParameter] string $password, string $salt, int $id, int $iterations, int $n): string
    {
        $u = 20;
        $v = 64;
        $d = str_repeat(chr($id), $v);
        $s = $salt === '' ? '' : substr(str_repeat($salt, intdiv($v * (int) ceil(strlen($salt) / $v), strlen($salt)) + 1), 0, $v * (int) ceil(strlen($salt) / $v));
        $p = $password === '' ? '' : substr(str_repeat($password, intdiv($v * (int) ceil(strlen($password) / $v), strlen($password)) + 1), 0, $v * (int) ceil(strlen($password) / $v));
        $i = $s . $p;
        $out = '';
        for ($block = 0, $c = (int) ceil($n / $u); $block < $c; $block++) {
            $a = hash('sha1', $d . $i, true);
            for ($k = 1; $k < $iterations; $k++) {
                $a = hash('sha1', $a, true);
            }
            $out .= $a;
            if ($block + 1 < $c) {
                // I_j = (I_j + B + 1) mod 2^(8v), B = A repeated to v bytes
                $b = substr(str_repeat($a, intdiv($v, $u) + 1), 0, $v);
                $next = '';
                foreach (str_split($i, $v) as $chunk) {
                    $carry = 1;
                    for ($x = $v - 1; $x >= 0; $x--) {
                        $sum = ord($chunk[$x]) + ord($b[$x]) + $carry;
                        $chunk[$x] = chr($sum & 0xFF);
                        $carry = $sum >> 8;
                    }
                    $next .= $chunk;
                }
                $i = $next;
            }
        }
        return substr($out, 0, $n);
    }

    private static function cipherAvailable(string $cipher, int $keyLen, int $ivLen): bool
    {
        return self::$cipherAvailable[$cipher] ??= @openssl_encrypt('probe', $cipher, str_repeat("\x01", $keyLen), OPENSSL_RAW_DATA, str_repeat("\x02", $ivLen)) !== false;
    }

    private static function isDer(string $data): bool
    {
        if ($data === '' || $data[0] !== "\x30") {
            return false;
        }
        try {
            Asn1::parse($data, false, true);
            return true;
        } catch (ValidationException) {
            return false;
        }
    }

    /**
     * Content of a (possibly constructed, BER) [0] IMPLICIT OCTET STRING.
     */
    private static function octets(Asn1Node $node): string
    {
        if (!$node->constructed) {
            return $node->content();
        }
        $out = '';
        foreach ($node->children() as $c) {
            if (!$c->isUniversal(Asn1::TAG_OCTET_STRING)) {
                throw new ValidationException('malformed', 'bad encrypted content segment');
            }
            $out .= $c->content();
        }
        return $out;
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
            // PBKDF2-params keyLength INTEGER OPTIONAL: native code derives that many bytes
            if ($oid === self::OID_PBKDF2 && isset($p[2]) && $p[2]->isUniversal(Asn1::TAG_INTEGER)
                && self::bigInt($p[2]) > self::MAX_PBKDF2_KEY_LENGTH) {
                throw new ValidationException($label, 'KDF: key length out of range');
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

    /**
     * Iteration count of an encrypted layer, checked again right before this class runs the KDF
     * itself: algorithm() only counts INTEGER values, so anything else (or an out-of-range value)
     * must never reach the key derivation loop.
     */
    private static function layerIterations(Asn1Node $node, string $label): int
    {
        $n = self::bigInt($node);
        if (!$node->isUniversal(Asn1::TAG_INTEGER) || $n < 1 || $n > self::MAX_ITERATIONS) {
            throw new ValidationException($label, 'KDF: iteration count out of range');
        }
        return $n;
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
        if ($c === '') {
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
