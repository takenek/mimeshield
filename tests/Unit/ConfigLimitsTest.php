<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Tests\Unit;

use MimeShield\Config;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Audit V-06: the S/MIME size limits are bounded by a fraction of PHP's memory_limit, so a message
 * close to the configured limit yields the "message too large" label instead of a fatal error.
 */
final class ConfigLimitsTest extends TestCase
{
    /**
     * @return iterable<string, array{0: string, 1: ?int}>
     */
    public static function memoryValues(): iterable
    {
        yield 'bytes' => ['134217728', 134217728];
        yield 'megabytes' => ['128M', 134217728];
        yield 'lower case' => ['128m', 134217728];
        yield 'kilobytes' => ['512K', 524288];
        yield 'gigabytes' => ['1G', 1073741824];
        yield 'spaces' => [' 256M ', 268435456];
        yield 'unlimited' => ['-1', null];
        yield 'empty' => ['', null];
        yield 'zero' => ['0', null];
        yield 'garbage' => ['lots', null];
        yield 'fraction' => ['1.5G', null];
    }

    #[DataProvider('memoryValues')]
    public function testMemoryLimitParsing(string $ini, ?int $bytes): void
    {
        self::assertSame($bytes, Config::memoryLimitBytes($ini));
    }

    public function testBoundedByMemory(): void
    {
        // 128 MB / 6 caps the 50 MB default message limit at ~21 MB
        self::assertSame(22369621, Config::boundedByMemory(52428800, 134217728, Config::MESSAGE_MEMORY_DIVISOR, 65536));
        // 512 MB leaves the configured limit alone
        self::assertSame(52428800, Config::boundedByMemory(52428800, 536870912, Config::MESSAGE_MEMORY_DIVISOR, 65536));
        // envelopes: 128 MB / 2
        self::assertSame(67108864, Config::boundedByMemory(268435456, 134217728, Config::ENVELOPE_MEMORY_DIVISOR, 1048576));
        // never below the minimum, unchanged without a memory limit
        self::assertSame(65536, Config::boundedByMemory(52428800, 65536, Config::MESSAGE_MEMORY_DIVISOR, 65536));
        self::assertSame(52428800, Config::boundedByMemory(52428800, null, Config::MESSAGE_MEMORY_DIVISOR, 65536));
    }

    public function testEffectiveLimitsFollowTheRunningMemoryLimit(): void
    {
        $cfg = new Config(new \rcube_config());
        $memory = Config::memoryLimitBytes((string) ini_get('memory_limit'));
        self::assertSame(Config::boundedByMemory(52428800, $memory, Config::MESSAGE_MEMORY_DIVISOR, 65536), $cfg->maxMessageSize());
        self::assertSame(Config::boundedByMemory(268435456, $memory, Config::ENVELOPE_MEMORY_DIVISOR, 1048576), $cfg->maxTotalEnvelopeBytes());
        self::assertLessThanOrEqual(52428800, $cfg->maxMessageSize());
        self::assertGreaterThanOrEqual(65536, $cfg->maxMessageSize());
    }
}
