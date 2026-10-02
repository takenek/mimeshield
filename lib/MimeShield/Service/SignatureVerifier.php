<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Service;

use MimeShield\Cert\Certificate;
use MimeShield\Crypto\SignatureCheck;
use MimeShield\Exception\ValidationException;
use MimeShield\Trust\AddressMatcher;
use MimeShield\Trust\ChainResult;
use MimeShield\Trust\ChainValidator;
use MimeShield\Trust\RevocationChecker;
use MimeShield\Trust\RevocationResult;
use MimeShield\Trust\TrustStore;
use MimeShield\Trust\VerificationResult;

/**
 * Turns a cryptographic SignatureCheck into a complete VerificationResult (chain, identity,
 * time, purpose, revocation, algorithm policy).
 */
final class SignatureVerifier
{
    /**
     * @param list<string> $allowedDigests Digests accepted without warning (e.g. sha256, sha384, sha512)
     * @param list<string> $legacyDigests  Digests accepted WITH a warning (e.g. sha1)
     */
    public function __construct(
        private readonly ChainValidator $chains,
        private readonly TrustStore $store,
        private readonly RevocationChecker $revocation,
        private readonly array $allowedDigests = ['sha256', 'sha384', 'sha512'],
        private readonly array $legacyDigests = ['sha1', 'sha224'],
        private readonly bool $subjectEmailFallback = true,
        private readonly int $minRsaBits = 2048,
    ) {
    }

    /**
     * @param list<string> $fromAddresses   normalised From addresses
     * @param list<string> $senderAddresses normalised Sender addresses
     */
    public function evaluate(SignatureCheck $check, array $fromAddresses, array $senderAddresses, bool $partial = false, ?int $now = null): VerificationResult
    {
        $now ??= time();
        $signer = null;
        if (isset($check->signerPems[0])) {
            try {
                $signer = Certificate::fromString($check->signerPems[0]);
            } catch (ValidationException) {
                $signer = null;
            }
        }

        $digest = strtolower($check->digest());
        $forbidden = !in_array($digest, $this->allowedDigests, true) && !in_array($digest, $this->legacyDigests, true);
        $weak = in_array($digest, $this->legacyDigests, true);
        if ($check->info === null) {
            // structure could not be inspected (e.g. exotic BER): no algorithm policy decision possible
            $forbidden = false;
            $weak = false;
        }

        if ($signer === null) {
            return new VerificationResult($check, null, null, VerificationResult::IDENTITY_NOFROM, VerificationResult::TIME_VALID, false,
                new RevocationResult(RevocationResult::NOT_CHECKED), $weak, $forbidden, false, $fromAddresses, $partial);
        }

        $time = $signer->isExpired($now) ? VerificationResult::TIME_EXPIRED
            : ($signer->isNotYetValid($now) ? VerificationResult::TIME_NOTYET : VerificationResult::TIME_VALID);

        // RFC 8550 4.4.2 / 4.4.4: KU must allow digitalSignature or nonRepudiation, EKU emailProtection/any
        $purposeOk = $signer->hasKeyUsage(Certificate::KU_DIGITAL_SIGNATURE | Certificate::KU_NON_REPUDIATION)
            && $signer->allowsEmailProtection() && !$signer->isCa;

        $chain = $this->chains->validate($signer, $check->embeddedPems, ChainValidator::PURPOSE_SIGN, $now);

        $emails = $signer->emails($this->subjectEmailFallback);
        if ($emails === []) {
            $identity = VerificationResult::IDENTITY_NOEMAIL;
        } elseif ($fromAddresses === []) {
            $identity = VerificationResult::IDENTITY_NOFROM;
        } else {
            $allFromMatch = true;
            foreach ($fromAddresses as $f) {
                if (!AddressMatcher::matchesAny($f, $emails)) {
                    $allFromMatch = false;
                    break;
                }
            }
            if ($allFromMatch) {
                $identity = VerificationResult::IDENTITY_MATCH;
            } else {
                $senderMatch = false;
                foreach ($senderAddresses as $s) {
                    if (AddressMatcher::matchesAny($s, $emails)) {
                        $senderMatch = true;
                    }
                }
                $identity = $senderMatch ? VerificationResult::IDENTITY_SENDER : VerificationResult::IDENTITY_MISMATCH;
            }
        }

        // revocation: only for chains anchored in the configured trust store (RFC 8550 section 6)
        $rev = new RevocationResult(RevocationResult::NOT_CHECKED, $this->revocation->isEnabled() ? 'untrusted' : 'disabled');
        if ($this->revocation->isEnabled() && in_array($chain->status, [ChainResult::TRUSTED, ChainResult::EXPIRED], true)) {
            $issuer = $this->findIssuer($signer, $check->embeddedPems);
            $rev = $this->revocation->check($signer, $issuer, $now);
        }

        $small = $signer->keyType === 'RSA' && $signer->keyBits > 0 && $signer->keyBits < $this->minRsaBits;

        return new VerificationResult($check, $signer, $chain, $identity, $time, $purposeOk, $rev, $weak, $forbidden, $small,
            $fromAddresses, $partial, $signer->usesLegacySubjectEmail() && $this->subjectEmailFallback);
    }

    /**
     * Issuer certificate of $cert among embedded, configured intermediate and anchor certificates.
     *
     * @param list<string> $embedded
     */
    public function findIssuer(Certificate $cert, array $embedded): ?Certificate
    {
        $candidates = [];
        foreach ($embedded as $pem) {
            try {
                $candidates[] = Certificate::fromString($pem);
            } catch (ValidationException) {
            }
        }
        foreach (array_merge($candidates, $this->store->intermediates(), $this->store->anchors()) as $c) {
            if ($c->fingerprint !== $cert->fingerprint && $cert->isIssuedBy($c)) {
                return $c;
            }
        }
        return null;
    }
}
