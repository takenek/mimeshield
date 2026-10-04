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

use MimeShield\Cert\Certificate;

/**
 * Result of certificate chain validation.
 */
final class ChainResult
{
    public const TRUSTED = 'trusted';
    public const UNTRUSTED_ROOT = 'untrusted_root';
    public const INCOMPLETE = 'incomplete';
    public const EXPIRED = 'expired';
    public const NOT_YET_VALID = 'not_yet_valid';
    public const BAD_PURPOSE = 'bad_purpose';
    public const NO_TRUST_STORE = 'no_trust_store';

    /**
     * @param list<string>      $path  Subjects from the leaf up to the anchor (untrusted data)
     * @param list<Certificate> $certs The path itself (leaf first) when it ends in an anchor of the
     *                                 configured trust store, otherwise empty. Revocation checking and
     *                                 the choice of CRL issuers use exactly this path (audit F-04/F-05).
     */
    public function __construct(
        public readonly string $status,
        public readonly array $path,
        public readonly bool $leafExpired = false,
        public readonly array $certs = [],
    ) {
    }

    public function isTrusted(): bool
    {
        return $this->status === self::TRUSTED;
    }

    /**
     * Issuer of $cert on the anchored path (null when $cert is not on it or is the anchor).
     */
    public function issuerOf(Certificate $cert): ?Certificate
    {
        foreach ($this->certs as $i => $c) {
            if ($c->fingerprint === $cert->fingerprint) {
                return $this->certs[$i + 1] ?? null;
            }
        }
        return null;
    }
}
