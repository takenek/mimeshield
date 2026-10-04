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
