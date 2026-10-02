<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\RateLimiter;
use PHPUnit\Framework\TestCase;

/**
 * Audit MS-11: per-session limit of expensive actions.
 */
final class RateLimiterTest extends TestCase
{
    public function testAllowsUpToTheLimitWithinTheWindow(): void
    {
        $store = [];
        for ($i = 0; $i < 3; $i++) {
            self::assertTrue(RateLimiter::allow($store, 'b', 3, 60, 1000 + $i));
        }
        self::assertFalse(RateLimiter::allow($store, 'b', 3, 60, 1010));
        self::assertCount(3, $store['b'], 'a refused request is not recorded');
    }

    public function testWindowSlides(): void
    {
        $store = [];
        self::assertTrue(RateLimiter::allow($store, 'b', 1, 60, 1000));
        self::assertFalse(RateLimiter::allow($store, 'b', 1, 60, 1059));
        self::assertTrue(RateLimiter::allow($store, 'b', 1, 60, 1060));
    }

    public function testBucketsAreIndependentAndGarbageIsIgnored(): void
    {
        $store = ['a' => 'not an array', 'b' => ['x', null, 5000]];
        self::assertTrue(RateLimiter::allow($store, 'a', 1, 60, 1000));
        // entries in the future (clock change) or of the wrong type never count
        self::assertTrue(RateLimiter::allow($store, 'b', 1, 60, 1000));
        self::assertFalse(RateLimiter::allow($store, 'a', 1, 60, 1001));
    }
}
