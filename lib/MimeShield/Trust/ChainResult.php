<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Trust;

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
     * @param list<string> $path Subjects from the leaf up to the anchor (untrusted data)
     */
    public function __construct(
        public readonly string $status,
        public readonly array $path,
        public readonly bool $leafExpired = false,
    ) {
    }

    public function isTrusted(): bool
    {
        return $this->status === self::TRUSTED;
    }
}
