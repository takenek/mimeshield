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
}
