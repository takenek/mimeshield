<?php

declare(strict_types=1);

/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Original author: Marek Królikowski (TaKeN)
 * Original project: https://github.com/takenek/mimeshield
 * SPDX-License-Identifier: GPL-3.0-or-later
 * See LICENSE and COPYRIGHT for the license and GPL section 7 attribution terms.
 *
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Crypto;

/**
 * Result of the purely cryptographic part of signature verification.
 */
final class SignatureCheck
{
    public const FAIL_NONE = '';
    public const FAIL_MODIFIED = 'modified';
    public const FAIL_UNSUPPORTED = 'unsupported';
    public const FAIL_NO_SIGNER = 'nosigner';
    public const FAIL_MALFORMED = 'malformed';

    /**
     * @param list<string> $signerPems   Signer certificate(s)
     * @param list<string> $embeddedPems All certificates embedded in the CMS
     * @param null|array{detached: bool, digests: list<string>, signers: list<array{digest: string, signature: string, signingTime: ?int, sid: array<string, string>}>, certificates: int} $info
     */
    public function __construct(
        public readonly bool $valid,
        public readonly string $failure,
        public readonly array $signerPems,
        public readonly array $embeddedPems,
        public readonly ?array $info,
        public readonly ?string $content,
        public readonly bool $canonicalized,
    ) {
    }

    public function digest(): string
    {
        return $this->info['signers'][0]['digest'] ?? ($this->info['digests'][0] ?? 'unknown');
    }

    public function signatureAlgorithm(): string
    {
        return $this->info['signers'][0]['signature'] ?? 'unknown';
    }

    public function signingTime(): ?int
    {
        return $this->info['signers'][0]['signingTime'] ?? null;
    }

    public function signerCount(): int
    {
        return $this->info !== null ? count($this->info['signers']) : count($this->signerPems);
    }
}
