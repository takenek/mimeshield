<?php

declare(strict_types=1);

/**
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

    public function certificate(): Certificate
    {
        return $this->cert ??= Certificate::fromString((string) $this->row['cert_pem']);
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
