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
        #[\SensitiveParameter]
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
