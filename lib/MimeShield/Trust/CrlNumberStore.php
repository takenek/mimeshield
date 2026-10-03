<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Trust;

/**
 * Highest cRLNumber seen per CRL issuer and scope (audit I-02).
 *
 * Numbers are non-negative integers as normalised upper-case hex (Asn1::integerHex). Implementations
 * may throw; RevocationChecker treats any failure as "no information" and keeps checking.
 */
interface CrlNumberStore
{
    public function get(string $key): ?string;

    public function put(string $key, string $number): void;
}
