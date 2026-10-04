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

namespace MimeShield\Storage;

use MimeShield\Cert\Certificate;
use MimeShield\Exception\ValidationException;

/**
 * A stored own certificate + (encrypted) private key of the current user.
 */
final class KeyRecord
{
    private ?Certificate $cert = null;

    /**
     * @param array<string, ?string> $row
     */
    public function __construct(private readonly array $row)
    {
    }

    public function id(): int
    {
        return (int) $this->row['key_id'];
    }

    public function userId(): int
    {
        return (int) $this->row['user_id'];
    }

    public function fingerprint(): string
    {
        return (string) $this->row['fingerprint'];
    }

    /**
     * Certificate of the record. It must match the record fingerprint, which is bound to the
     * encrypted private key (AEAD context): a certificate swapped in the database is rejected (MS-09).
     */
    public function certificate(): Certificate
    {
        if ($this->cert === null) {
            $c = Certificate::fromString((string) $this->row['cert_pem']);
            if (!hash_equals($this->fingerprint(), $c->fingerprint)) {
                throw new ValidationException('keyinvalid', 'certificate does not match the key record');
            }
            $this->cert = $c;
        }
        return $this->cert;
    }

    /**
     * Intermediate certificates stored with the key (PEM list, untrusted).
     *
     * @return list<string>
     */
    public function chainPems(): array
    {
        return Certificate::splitPemBundle((string) ($this->row['chain_pem'] ?? ''), 16);
    }

    /**
     * Chain certificates suitable for embedding in signatures (CA, not self-signed roots).
     *
     * @return list<string>
     */
    public function embeddableChain(): array
    {
        $out = [];
        foreach ($this->chainPems() as $pem) {
            try {
                $c = Certificate::fromString($pem);
            } catch (ValidationException) {
                continue;
            }
            if ($c->isCa && !$c->isSelfIssued()) {
                $out[] = $c->pem;
            }
        }
        return $out;
    }

    public function blob(): string
    {
        return (string) $this->row['key_blob'];
    }

    public function kid(): string
    {
        return (string) $this->row['key_kid'];
    }

    public function created(): string
    {
        return (string) $this->row['created'];
    }

    /**
     * AEAD context binding the key blob to this user and certificate.
     */
    public static function context(int $userId, string $fingerprint): string
    {
        return 'user:' . $userId . '|fp:' . $fingerprint;
    }

    public function blobContext(): string
    {
        return self::context($this->userId(), $this->fingerprint());
    }
}
