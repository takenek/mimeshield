<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Storage;

use MimeShield\Cert\Certificate;

/**
 * A stored correspondent certificate.
 */
final class CertRecord
{
    private ?Certificate $cert = null;

    /**
     * @param array<string, ?string> $row
     * @param list<string>           $preferredFor
     */
    public function __construct(private readonly array $row, public readonly array $preferredFor = [])
    {
    }

    public function id(): int
    {
        return (int) $this->row['cert_id'];
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
     * @return list<string>
     */
    public function emails(): array
    {
        $e = trim((string) $this->row['emails']);
        return $e === '' ? [] : explode("\n", $e);
    }

    /**
     * @return list<string>
     */
    public function chainPems(): array
    {
        return Certificate::splitPemBundle((string) ($this->row['chain_pem'] ?? ''), 16);
    }

    public function source(): string
    {
        return (string) $this->row['source'];
    }

    public function trust(): string
    {
        return (string) $this->row['trust'];
    }

    public function created(): string
    {
        return (string) $this->row['created'];
    }
}
