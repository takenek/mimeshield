<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Mime;

/**
 * Predicts where Net_SMTP (1.12.x, string path) splits the DATA payload into 512000-byte chunks.
 *
 * Net_SMTP::data() dot-stuffs every chunk on its own (preg_replace('/^\./m', '..')). A chunk that
 * starts in the MIDDLE of a line with "." therefore gets an extra dot that the receiving MTA keeps,
 * which silently corrupts clear-signed content. The plugin shifts such borders by padding the
 * multipart/signed preamble (outside the signed bytes).
 */
final class DotGuard
{
    public const CHUNK = 512000;

    /**
     * Offsets of chunk starts that would be corrupted.
     *
     * @return list<int>
     */
    public static function riskyOffsets(string $data): array
    {
        $size = strlen($data);
        $risky = [];
        for ($offset = 0; $offset < $size;) {
            $end = $offset + self::CHUNK;
            if ($end >= $size) {
                break;
            }
            while ($end < $size && $data[$end] === "\n") {
                $end++;
            }
            if ($end < $size && $data[$end] === '.' && $data[$end - 1] !== "\n") {
                $risky[] = $end;
            }
            $offset = $end;
        }
        return $risky;
    }

    /**
     * Pad until no chunk border is risky. $data returns the current DATA payload, $pad shifts it by
     * one byte. Returns false when the payload is still unsafe after $attempts paddings: the caller
     * must then refuse to send (fail closed, audit F-11) instead of letting the transport change the
     * signed bytes.
     *
     * @param callable(): string $data
     * @param callable(): void   $pad
     */
    public static function makeSafe(callable $data, callable $pad, int $attempts = 8): bool
    {
        for ($i = 0; ; $i++) {
            if (self::riskyOffsets($data()) === []) {
                return true;
            }
            if ($i >= $attempts) {
                return false;
            }
            $pad();
        }
    }
}
