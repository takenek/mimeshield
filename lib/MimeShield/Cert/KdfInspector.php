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
 *
 * Parameters inside ENCRYPTED SafeContents (PKCS#12 EncryptedData, e.g. a shrouded key bag hidden
 * in an encrypted layer) are not visible without the password. When the password is given, every
 * encrypted layer is decrypted here (after its own cost was checked) and inspected as well, so the
 * whole operation stays within one budget before OpenSSL runs any of it (audit MS-05). A layer the
 * password does not decrypt is reported as a wrong password; a layer using a cipher this PHP/OpenSSL
 * cannot run is reported as legacy (the opt-in CLI converter runs in a separate, time-limited process).
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

    private const OID_DATA = '1.2.840.113549.1.7.1';

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
            $self->walk($root, 0, $errorLabel);
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
            $children = $node->children();
            foreach ($children as $c) {
                $this->walk($c, $depth + 1, $label);
            }
            // EncryptedContentInfo ::= SEQUENCE { contentType data, contentEncryptionAlgorithm,
            // encryptedContent [0] IMPLICIT OCTET STRING } - its own cost was counted just above
            if ($this->password !== null && $node->isUniversal(Asn1::TAG_SEQUENCE) && count($children) === 3
                && $children[0]->isUniversal(Asn1::TAG_OID) && Asn1::oid($children[0]) === self::OID_DATA
                && $children[1]->isUniversal(Asn1::TAG_SEQUENCE) && $children[1]->constructed && $children[2]->isContext(0)) {
                $plain = $this->decryptLayer($children[1], self::octets($children[2]), $label);
                if ($plain !== null) {
                    // a new structure: own depth, shared node / layer / iteration budget
                    $this->walk(Asn1::parse($plain, false, true), 0, $label);
                }
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
            foreach (self::bmpPasswords((string) $this->password) as $pw) {
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
