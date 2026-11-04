<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Tests\Unit;

use MimeShield\Exception\ValidationException;
use MimeShield\Mime\IncomingProcessor;
use PHPUnit\Framework\TestCase;

/**
 * Audit V-05: the structure budget of an injected entity (nesting depth of forwarded messages, retained
 * nested bodies, number of entities) is enforced before the platform MIME parser allocates the tree.
 */
final class MimeBudgetTest extends TestCase
{
    private const MAX = 1048576;

    private static function message(string $body, string $ctype = 'text/plain'): string
    {
        return "Content-Type: {$ctype}\r\nMIME-Version: 1.0\r\n\r\n" . $body;
    }

    private static function nested(string $inner, int $layers): string
    {
        for ($i = 0; $i < $layers; $i++) {
            $inner = "Content-Type: message/rfc822\r\n\r\n" . $inner;
        }
        return $inner;
    }

    public function testFlatAndModeratelyNestedEntitiesPass(): void
    {
        IncomingProcessor::assertMimeBudget(self::message("hello\r\n"), self::MAX);
        IncomingProcessor::assertMimeBudget(self::nested(self::message("hello\r\n"), 8), self::MAX);   // depth 8 is allowed
        $this->addToAssertionCount(1);
    }

    public function testDigestWithManySiblingForwardsPasses(): void
    {
        // 40 forwarded messages side by side: siblings retain their own bodies only (800 KB in total)
        $b = 'digest-boundary';
        $body = '';
        for ($i = 0; $i < 40; $i++) {
            $body .= "--{$b}\r\nContent-Type: message/rfc822\r\n\r\n" . self::message(str_repeat('x', 20000) . "\r\n") . "\r\n";
        }
        IncomingProcessor::assertMimeBudget("Content-Type: multipart/digest; boundary=\"{$b}\"\r\n\r\n" . $body . "--{$b}--\r\n", 500000);
        $this->addToAssertionCount(1);
    }

    public function testNestingTooDeepIsRefused(): void
    {
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('nested messages 9 deep');
        IncomingProcessor::assertMimeBudget(self::nested(self::message("hello\r\n"), 9), self::MAX);
    }

    public function testRetainedNestedBodiesAboveTheBudgetAreRefused(): void
    {
        // 6 layers around a 300 KB body: about 1.8 MB retained by the parser for a 300 KB entity
        $entity = self::nested(self::message(str_repeat('x', 300000) . "\r\n"), 6);
        try {
            IncomingProcessor::assertMimeBudget($entity, 400000);
            self::fail('expected refusal');
        } catch (ValidationException $e) {
            self::assertSame('messagetoolarge', $e->getUserLabel());
            self::assertStringContainsString('nested message bodies', $e->getMessage());
        }
        // the same entity within a larger limit passes
        IncomingProcessor::assertMimeBudget($entity, 2 * self::MAX);
    }

    public function testTooManyEntitiesAreRefused(): void
    {
        $body = '';
        for ($i = 0; $i < 501; $i++) {
            $body .= "--b\r\nContent-Type: text/plain\r\n\r\nx\r\n";
        }
        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('entities');
        IncomingProcessor::assertMimeBudget("Content-Type: multipart/mixed; boundary=b\r\n\r\n" . $body . "--b--\r\n", self::MAX);
    }

    public function testSpanEndsAtTheDelimiterOfAnEnclosingMultipart(): void
    {
        // a small forwarded message followed by a large attachment in the same multipart: the retained
        // body of the forward ends at the next delimiter, the attachment does not count against it
        $b = 'outer';
        $entity = "Content-Type: multipart/mixed;\r\n boundary=\"{$b}\"\r\n\r\n"
            . "--{$b}\r\nContent-Type: message/rfc822\r\n\r\n" . self::message("short\r\n") . "\r\n"
            . "--{$b}\r\nContent-Type: application/octet-stream\r\n\r\n" . str_repeat('A', 900000) . "\r\n"
            . "--{$b}--\r\n";
        IncomingProcessor::assertMimeBudget($entity, 300000);
        $this->addToAssertionCount(1);
    }

    public function testBoundaryDeclaredInsideTheForwardDoesNotEndIt(): void
    {
        // the forwarded message is itself a multipart: its own delimiters never end its span
        $inner = "Content-Type: multipart/mixed; boundary=\"in\"\r\n\r\n--in\r\nContent-Type: text/plain\r\n\r\n" . str_repeat('y', 200000) . "\r\n--in--\r\n";
        $entity = self::nested($inner, 5);
        try {
            IncomingProcessor::assertMimeBudget($entity, 200000);
            self::fail('expected refusal: 5 x 200 KB retained');
        } catch (ValidationException $e) {
            self::assertStringContainsString('nested message bodies', $e->getMessage());
        }
    }
}
