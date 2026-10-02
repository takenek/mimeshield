<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Mime;

use MimeShield\Trust\VerificationResult;

/**
 * S/MIME processing state of one MIME part (per request, in memory only).
 */
final class PartStatus
{
    /** Decryption: null = not encrypted, true = decrypted, string = error label */
    public bool|string|null $decryption = null;

    /** Content encryption algorithm (e.g. aes-256-cbc) */
    public string $cipher = '';

    /** Unauthenticated encryption (CBC) without an inner valid signature: EFAIL-relevant */
    public bool $unauthenticated = false;

    public ?VerificationResult $signature = null;

    /** Signature could not be checked: error label */
    public ?string $signatureError = null;

    /** Only a sub-part of the message is protected */
    public bool $partial = false;

    /** Encrypted part that was deliberately not decrypted (nested / forwarded) */
    public bool $notDecrypted = false;

    /** Displayed already in the UI */
    public bool $shown = false;

    public function __construct(public readonly string $partId)
    {
    }

    public function isEncrypted(): bool
    {
        return $this->decryption !== null || $this->notDecrypted;
    }

    public function isSigned(): bool
    {
        return $this->signature !== null || $this->signatureError !== null;
    }
}
