<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Trust;

use MimeShield\Cert\Certificate;
use MimeShield\Crypto\SignatureCheck;

/**
 * Full result of verifying one S/MIME signature.
 *
 * The four questions are kept strictly separate and are never collapsed into "valid":
 *   1. cryptographic signature verification   ($cryptoValid / $failure)
 *   2. certificate chain validation            ($chain)
 *   3. identity matching (From/Sender vs cert)  ($identity)
 *   4. revocation checking                     ($revocation)
 * plus certificate time validity, key usage / EKU and algorithm policy.
 */
final class VerificationResult
{
    public const LEVEL_OK = 'ok';
    public const LEVEL_WARNING = 'warning';
    public const LEVEL_ERROR = 'error';

    public const IDENTITY_MATCH = 'match';
    public const IDENTITY_SENDER = 'sender';
    public const IDENTITY_MISMATCH = 'mismatch';
    public const IDENTITY_NOEMAIL = 'noemail';
    public const IDENTITY_NOFROM = 'nofrom';

    public const TIME_VALID = 'valid';
    public const TIME_EXPIRED = 'expired';
    public const TIME_NOTYET = 'notyet';

    /**
     * @param list<string> $fromAddresses normalised From addresses
     */
    public function __construct(
        public readonly SignatureCheck $check,
        public readonly ?Certificate $signer,
        public readonly ?ChainResult $chain,
        public readonly string $identity,
        public readonly string $certTime,
        public readonly bool $purposeOk,
        public readonly RevocationResult $revocation,
        public readonly bool $weakDigest,
        public readonly bool $forbiddenDigest,
        public readonly bool $smallKey,
        public readonly array $fromAddresses,
        public readonly bool $partial = false,
        public readonly bool $legacyEmail = false,
    ) {
    }

    public function cryptoValid(): bool
    {
        return $this->check->valid && !$this->forbiddenDigest;
    }

    public function level(): string
    {
        if (!$this->cryptoValid()
            || $this->signer === null
            || $this->identity === self::IDENTITY_MISMATCH
            || $this->revocation->status === RevocationResult::REVOKED
            || !$this->purposeOk) {
            return self::LEVEL_ERROR;
        }
        if ($this->chain !== null && $this->chain->isTrusted()
            && $this->certTime === self::TIME_VALID
            && $this->identity === self::IDENTITY_MATCH
            && in_array($this->revocation->status, [RevocationResult::GOOD, RevocationResult::NOT_CHECKED], true)
            && !$this->weakDigest && !$this->smallKey && !$this->partial) {
            return self::LEVEL_OK;
        }
        return self::LEVEL_WARNING;
    }

    /**
     * Status lines for the UI: [label (plugin domain), vars, severity]. Vars contain untrusted data and
     * are escaped by the UI layer.
     *
     * @return list<array{0: string, 1: array<string, string>, 2: string}>
     */
    public function lines(): array
    {
        $out = [];
        $signer = $this->signer;

        if (!$this->check->valid) {
            $label = match ($this->check->failure) {
                SignatureCheck::FAIL_MODIFIED => 'sig_modified',
                SignatureCheck::FAIL_UNSUPPORTED => 'sig_unsupported',
                SignatureCheck::FAIL_NO_SIGNER => 'sig_nosigner',
                default => 'sig_malformed',
            };
            $out[] = [$label, [], self::LEVEL_ERROR];
        } elseif ($this->forbiddenDigest) {
            $out[] = ['sig_forbiddendigest', ['digest' => $this->check->digest()], self::LEVEL_ERROR];
        } else {
            $out[] = ['sig_cryptovalid', [], self::LEVEL_OK];
        }

        if ($signer !== null) {
            if (!$this->purposeOk) {
                $out[] = ['cert_badpurpose', [], self::LEVEL_ERROR];
            }

            $status = $this->chain->status ?? ChainResult::NO_TRUST_STORE;
            $out[] = match ($status) {
                ChainResult::TRUSTED => ['chain_trusted', ['issuer' => $signer->issuerDisplayName()], self::LEVEL_OK],
                ChainResult::UNTRUSTED_ROOT => ['chain_untrusted', ['issuer' => $signer->issuerDisplayName()], self::LEVEL_WARNING],
                ChainResult::INCOMPLETE => ['chain_incomplete', ['issuer' => $signer->issuerDisplayName()], self::LEVEL_WARNING],
                ChainResult::EXPIRED => ['chain_expiredpath', [], self::LEVEL_WARNING],
                ChainResult::NOT_YET_VALID => ['chain_notyetpath', [], self::LEVEL_WARNING],
                ChainResult::BAD_PURPOSE => ['chain_badpurpose', [], self::LEVEL_WARNING],
                default => ['chain_notruststore', [], self::LEVEL_WARNING],
            };

            if ($this->certTime === self::TIME_EXPIRED) {
                $vars = ['date' => gmdate('Y-m-d', $signer->notAfter)];
                $st = $this->check->signingTime();
                if ($st !== null && $st >= $signer->notBefore && $st <= $signer->notAfter) {
                    $out[] = ['cert_expired_signedwhilevalid', $vars + ['signed' => gmdate('Y-m-d H:i', $st) . ' UTC'], self::LEVEL_WARNING];
                } else {
                    $out[] = ['cert_expired', $vars, self::LEVEL_WARNING];
                }
            } elseif ($this->certTime === self::TIME_NOTYET) {
                $out[] = ['cert_notyetvalid', ['date' => gmdate('Y-m-d', $signer->notBefore)], self::LEVEL_WARNING];
            }

            $emails = implode(', ', $signer->emails());
            $out[] = match ($this->identity) {
                self::IDENTITY_MATCH => ['identity_match', ['email' => $emails], self::LEVEL_OK],
                self::IDENTITY_SENDER => ['identity_senderonly', ['email' => $emails], self::LEVEL_WARNING],
                self::IDENTITY_MISMATCH => ['identity_mismatch', ['email' => $emails, 'from' => implode(', ', $this->fromAddresses)], self::LEVEL_ERROR],
                self::IDENTITY_NOEMAIL => ['identity_noemail', [], self::LEVEL_WARNING],
                default => ['identity_nofrom', [], self::LEVEL_WARNING],
            };
            if ($this->legacyEmail) {
                $out[] = ['identity_legacyemail', [], self::LEVEL_WARNING];
            }

            $out[] = match ($this->revocation->status) {
                RevocationResult::GOOD => ['revocation_good', [], self::LEVEL_OK],
                RevocationResult::REVOKED => ['revocation_revoked', ['date' => $this->revocation->revokedAt ? gmdate('Y-m-d', $this->revocation->revokedAt) : '?', 'reason' => $this->revocation->reason], self::LEVEL_ERROR],
                RevocationResult::UNKNOWN => ['revocation_unknown', [], self::LEVEL_WARNING],
                default => ['revocation_notchecked', [], self::LEVEL_WARNING],
            };
        }

        if ($this->weakDigest) {
            $out[] = $this->check->info === null
                ? ['sig_digestunverified', [], self::LEVEL_WARNING]
                : ['sig_weakdigest', ['digest' => strtoupper($this->check->digest())], self::LEVEL_WARNING];
        }
        if ($this->smallKey && $signer !== null) {
            $out[] = ['cert_smallkey', ['bits' => (string) $signer->keyBits], self::LEVEL_WARNING];
        }
        if ($this->partial) {
            $out[] = ['sig_partial', [], self::LEVEL_WARNING];
        }
        if ($this->check->canonicalized) {
            $out[] = ['sig_canonicalized', [], self::LEVEL_OK];
        }

        return $out;
    }

    /**
     * Headline label for the status bar.
     */
    public function headline(): string
    {
        if (!$this->check->valid || $this->forbiddenDigest) {
            return 'status_sig_invalid';
        }
        if ($this->identity === self::IDENTITY_MISMATCH) {
            return 'status_sig_mismatch';
        }
        if ($this->revocation->status === RevocationResult::REVOKED) {
            return 'status_sig_revoked';
        }
        if (!$this->purposeOk || $this->signer === null) {
            return 'status_sig_badcert';
        }
        if ($this->level() === self::LEVEL_OK) {
            return 'status_sig_ok';
        }
        if ($this->certTime === self::TIME_EXPIRED || ($this->chain !== null && $this->chain->status === ChainResult::EXPIRED)) {
            return 'status_sig_expired';
        }
        if ($this->certTime === self::TIME_NOTYET || ($this->chain !== null && $this->chain->status === ChainResult::NOT_YET_VALID)) {
            return 'status_sig_notyet';
        }
        if ($this->chain === null || !$this->chain->isTrusted()) {
            return 'status_sig_untrusted';
        }
        return 'status_sig_warning';
    }
}
