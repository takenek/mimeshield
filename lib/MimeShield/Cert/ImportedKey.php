<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Cert;

use MimeShield\KeyStore\KeyVault;

/**
 * Result of a key import (transient: holds the plaintext private key in memory).
 */
final class ImportedKey
{
    /**
     * @param list<Certificate> $chain Intermediate/root certificates shipped with the key
     */
    public function __construct(
        public readonly Certificate $certificate,
        private string $privateKeyPem,
        public readonly array $chain,
    ) {
    }

    public function privateKeyPem(): string
    {
        return $this->privateKeyPem;
    }

    /**
     * Wipe the plaintext key from this object.
     */
    public function wipe(): void
    {
        KeyVault::wipe($this->privateKeyPem);
    }

    public function __destruct()
    {
        $this->wipe();
    }
}
