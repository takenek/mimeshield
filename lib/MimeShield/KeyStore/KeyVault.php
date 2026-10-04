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

namespace MimeShield\KeyStore;

use MimeShield\Exception\CryptoException;
use MimeShield\Log;

/**
 * Authenticated encryption of private keys at rest.
 *
 * Blob format v2 (stored base64 encoded in the database; v1 blobs remain readable):
 *
 *   magic "MSK" | version 0x02 | alg (1 byte) | kidLen (1 byte) | kid | nonce | ciphertext||tag
 *
 *   alg 0x01 = XChaCha20-Poly1305 (libsodium), 24-byte nonce, 16-byte tag  (default)
 *   alg 0x02 = AES-256-GCM (OpenSSL),           12-byte nonce, 16-byte tag  (fallback w/o sodium)
 *
 * - a fresh random nonce per encryption (192-bit for XChaCha, so random nonces are safe; 96-bit for
 *   GCM, where the number of encryptions per key stays far below the 2^32 random-nonce bound);
 * - the data key is derived from the master key with HKDF-SHA256 (domain separation, the master key
 *   is never used directly as a cipher key);
 * - associated data binds the ciphertext to its header and to its context (user id + certificate
 *   fingerprint), so a blob copied to another user's or another certificate's row fails to decrypt;
 * - any authentication failure is fatal - there is no unauthenticated fallback.
 */
final class KeyVault
{
    public const FORMAT_VERSION = 2;
    public const ALG_XCHACHA20POLY1305 = 1;
    public const ALG_AES256GCM = 2;

    private const MAGIC = 'MSK';
    private const HKDF_INFO = 'mimeshield private key wrapping v1';

    public function __construct(private readonly MasterKeyProvider $keys, private readonly ?int $forceAlg = null)
    {
    }

    public static function preferredAlgorithm(): int
    {
        return function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')
            ? self::ALG_XCHACHA20POLY1305
            : self::ALG_AES256GCM;
    }

    /**
     * Encrypt $plaintext for $context. Returns base64 blob.
     */
    public function encrypt(#[\SensitiveParameter] string $plaintext, string $context): string
    {
        $alg = $this->forceAlg ?? self::preferredAlgorithm();
        $kid = $this->keys->activeKid();
        $key = $this->deriveKey($kid, $alg);
        $header = self::MAGIC . chr(self::FORMAT_VERSION) . chr($alg) . chr(strlen($kid)) . $kid;
        $aad = $this->aad($header, $context);

        try {
            if ($alg === self::ALG_XCHACHA20POLY1305) {
                if (!function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')) {
                    throw new CryptoException('keystoreunavailable', 'libsodium not available');
                }
                $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
                $ct = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plaintext, $aad, $nonce, $key);
            } elseif ($alg === self::ALG_AES256GCM) {
                $nonce = random_bytes(12);
                $tag = '';
                $ct = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad, 16);
                if ($ct === false || strlen($tag) !== 16) {
                    throw new CryptoException('keystoreunavailable', 'AES-GCM encryption failed');
                }
                $ct .= $tag;
            } else {
                throw new CryptoException('keystoreunavailable', 'unsupported key wrapping algorithm');
            }
        } finally {
            self::wipe($key);
        }

        return base64_encode($header . $nonce . $ct);
    }

    /**
     * Decrypt a blob for $context. Throws on any integrity failure.
     */
    public function decrypt(string $blob, string $context): string
    {
        $raw = base64_decode($blob, true);
        if ($raw === false || strlen($raw) < 7 || substr($raw, 0, 3) !== self::MAGIC) {
            throw new CryptoException('keystorecorrupt', 'key blob: bad magic');
        }
        $version = ord($raw[3]);
        if ($version !== self::FORMAT_VERSION && $version !== 1) {
            throw new CryptoException('keystorecorrupt', 'key blob: unsupported format version ' . $version);
        }
        $alg = ord($raw[4]);
        $kidLen = ord($raw[5]);
        if ($kidLen < 1 || $kidLen > 16 || strlen($raw) < 6 + $kidLen) {
            throw new CryptoException('keystorecorrupt', 'key blob: bad key id');
        }
        $kid = substr($raw, 6, $kidLen);
        if (!preg_match('/^[a-z0-9]{1,16}$/D', $kid)) {
            throw new CryptoException('keystorecorrupt', 'key blob: bad key id');
        }
        $header = substr($raw, 0, 6 + $kidLen);
        $rest = substr($raw, 6 + $kidLen);
        $aad = $this->aad($header, $context);
        if (!in_array($kid, $this->keys->kids(), true)) {
            // a tampered/copied blob or a master key removed too early during rotation
            Log::error('keystore', 'private key blob references an unknown master key id', ['kid' => $kid]);
            throw new CryptoException('keystorecorrupt', 'key blob: unknown master key id');
        }
        $key = $this->deriveKey($kid, $alg, $version);

        try {
            if ($alg === self::ALG_XCHACHA20POLY1305) {
                if (!function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_decrypt')) {
                    throw new CryptoException('keystoreunavailable', 'libsodium not available');
                }
                $nl = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
                if (strlen($rest) < $nl + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES) {
                    throw new CryptoException('keystorecorrupt', 'key blob: truncated');
                }
                $pt = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(substr($rest, $nl), $aad, substr($rest, 0, $nl), $key);
            } elseif ($alg === self::ALG_AES256GCM) {
                if (strlen($rest) < 12 + 16) {
                    throw new CryptoException('keystorecorrupt', 'key blob: truncated');
                }
                $nonce = substr($rest, 0, 12);
                $tag = substr($rest, -16);
                $ct = substr($rest, 12, -16);
                // tag length is fixed to 16: openssl_decrypt accepts truncated tags otherwise
                $pt = strlen($tag) === 16 ? openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, $aad) : false;
            } else {
                throw new CryptoException('keystorecorrupt', 'key blob: unsupported algorithm');
            }
        } finally {
            self::wipe($key);
        }

        if (!is_string($pt)) {
            Log::error('keystore', 'private key blob failed authentication (tampered, wrong master key or wrong row)', ['kid' => $kid]);
            throw new CryptoException('keystorecorrupt', 'key blob authentication failed');
        }

        return $pt;
    }

    /**
     * Key id of a blob without decrypting it.
     */
    public static function blobKid(string $blob): ?string
    {
        $raw = base64_decode($blob, true);
        if ($raw === false || strlen($raw) < 7 || substr($raw, 0, 3) !== self::MAGIC) {
            return null;
        }
        $len = ord($raw[5]);
        $kid = substr($raw, 6, $len);
        return preg_match('/^[a-z0-9]{1,16}$/D', $kid) ? $kid : null;
    }

    public static function blobVersion(string $blob): ?int
    {
        $raw = base64_decode($blob, true);
        return ($raw === false || strlen($raw) < 4 || substr($raw, 0, 3) !== self::MAGIC) ? null : ord($raw[3]);
    }

    /**
     * Re-wrap a blob with the active master key (rotation). Returns the input if already current.
     */
    public function rewrap(string $blob, string $context): string
    {
        if (self::blobKid($blob) === $this->keys->activeKid() && self::blobVersion($blob) === self::FORMAT_VERSION) {
            return $blob;
        }
        $pt = $this->decrypt($blob, $context);
        try {
            return $this->encrypt($pt, $context);
        } finally {
            self::wipe($pt);
        }
    }

    /**
     * Best-effort wipe of a secret string held in a variable.
     *
     * @param-out string $secret
     */
    public static function wipe(#[\SensitiveParameter] string &$secret): void
    {
        if (function_exists('sodium_memzero')) {
            sodium_memzero($secret);
            $secret = '';
            return;
        }
        $secret = str_repeat("\0", strlen($secret));
        $secret = '';
    }

    /**
     * Data key per master key AND algorithm (domain separation: XChaCha20-Poly1305 and AES-GCM never
     * share a key).
     */
    private function deriveKey(string $kid, int $alg, int $version = self::FORMAT_VERSION): string
    {
        // v1 (first builds): one data key for both algorithms; v2: per-algorithm key
        $info = $version === 1 ? self::HKDF_INFO : self::HKDF_INFO . '|alg:' . $alg;
        return hash_hkdf('sha256', $this->keys->key($kid), 32, $info, 'kid:' . $kid);
    }

    private function aad(string $header, string $context): string
    {
        return $header . '|' . $context;
    }
}
