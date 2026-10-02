<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield;

/**
 * Sliding-window request limit kept in the user's session (audit MS-11).
 *
 * Bounds how often one session can trigger expensive cryptographic work (recipient chain
 * validation / CRL fetches, PKCS#12 key derivation). It does not replace limits at the edge
 * (reverse proxy, WAF): a new session starts with an empty window.
 */
final class RateLimiter
{
    /**
     * Record a request in $bucket and tell whether it is within $max requests per $window seconds.
     * A refused request is not recorded.
     *
     * @param array<array-key, mixed> $store e.g. $_SESSION
     */
    public static function allow(array &$store, string $bucket, int $max, int $window, ?int $now = null): bool
    {
        $now ??= time();
        $hits = array_values(array_filter(
            is_array($store[$bucket] ?? null) ? $store[$bucket] : [],
            static fn ($t) => is_int($t) && $t > $now - $window && $t <= $now
        ));
        if (count($hits) >= $max) {
            $store[$bucket] = $hits;
            return false;
        }
        $hits[] = $now;
        $store[$bucket] = $hits;
        return true;
    }
}
