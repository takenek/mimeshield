<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Trust\AddressMatcher;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AddressMatcherTest extends TestCase
{
    /**
     * @return iterable<string, array{0: string, 1: ?string}>
     */
    public static function normalizeCases(): iterable
    {
        yield 'plain' => ['alice@example.test', 'alice@example.test'];
        yield 'case folded' => ['Alice@Example.TEST', 'alice@example.test'];
        yield 'trimmed' => ['  bob@example.test ', 'bob@example.test'];
        yield 'idn domain' => ['jan@żółw.pl', 'jan@xn--w-uga1v8h.pl'];
        yield 'display name rejected' => ['Alice <alice@example.test>', null];
        yield 'comma injection rejected' => ['victim@example.test, email:attacker@evil.test', null];
        yield 'no at' => ['alice', null];
        yield 'empty local' => ['@example.test', null];
        yield 'space' => ['al ice@example.test', null];
        yield 'quoted local rejected' => ['"a b"@example.test', null];
        yield 'ip literal rejected' => ['a@[127.0.0.1]', null];
        yield 'single label domain rejected' => ['a@localhost', null];
        yield 'too long' => [str_repeat('a', 65) . '@example.test', null];
        yield 'newline' => ["a@example.test\nBcc: x@y.z", null];
    }

    #[DataProvider('normalizeCases')]
    public function testNormalize(string $in, ?string $expected): void
    {
        self::assertSame($expected, AddressMatcher::normalize($in));
    }

    public function testEqualsIsCaseInsensitive(): void
    {
        self::assertTrue(AddressMatcher::equals('ALICE@example.TEST', 'alice@EXAMPLE.test'));
        self::assertFalse(AddressMatcher::equals('alice@example.test', 'alice@example.test.evil'));
        self::assertFalse(AddressMatcher::equals('', ''));
    }

    public function testParseListFallback(): void
    {
        $list = AddressMatcher::parseList('Alice <alice@example.test>, bob@example.test; "x" <BOB@example.test>, undisclosed-recipients:;');
        self::assertSame(['alice@example.test', 'bob@example.test'], $list);
    }
}
