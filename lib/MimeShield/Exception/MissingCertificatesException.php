<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Exception;

/**
 * Encryption requested but some recipients have no usable certificate. Sending is blocked; the UI
 * shows exactly which recipients are affected (no silent downgrade to plaintext).
 */
final class MissingCertificatesException extends MimeShieldException
{
    /**
     * @param array<string, string> $recipients address => status (missing|expired|invalid|untrusted)
     */
    public function __construct(private readonly array $recipients)
    {
        parent::__construct('encryptmissingcerts', 'recipients without usable certificate: ' . count($recipients),
            ['emails' => implode(', ', array_keys($recipients))]);
    }

    /**
     * @return array<string, string>
     */
    public function recipients(): array
    {
        return $this->recipients;
    }
}
