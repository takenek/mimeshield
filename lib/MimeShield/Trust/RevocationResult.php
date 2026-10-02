<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Trust;

/**
 * Revocation status of a certificate.
 */
final class RevocationResult
{
    public const NOT_CHECKED = 'not_checked';
    public const GOOD = 'good';
    public const REVOKED = 'revoked';
    public const UNKNOWN = 'unknown';

    public function __construct(
        public readonly string $status,
        public readonly string $reason = '',
        public readonly ?int $revokedAt = null,
        public readonly ?int $nextUpdate = null,
    ) {
    }
}
