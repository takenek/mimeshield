<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Trust;

use MimeShield\Cert\Certificate;
use MimeShield\Crypto\OpenSsl;
use MimeShield\Crypto\SecureTemp;
use MimeShield\Exception\ValidationException;
use MimeShield\Log;

/**
 * Certificate chain validation.
 *
 * The decision "trusted" is made by OpenSSL (openssl_x509_checkpurpose against a store holding ONLY
 * the configured anchors - never OpenSSL's default CA directory - at the current time, with the
 * S/MIME purpose). A second path builder (issuer name + signature checks) explains WHY a check
 * failed (expired / not yet valid certificate in the path, unknown root, incomplete chain, wrong
 * purpose) and provides the path the other decisions are bound to. It never upgrades a failed
 * OpenSSL decision to "trusted"; it can only downgrade it: the path must end in an anchor of the
 * configured trust store for every key type and purpose (audit F-02), its certificates must be
 * within their validity period, and for EC recipients (checked with the "any" purpose) every CA on
 * it must allow e-mail protection. Revocation checking uses the same path (ChainResult::$certs).
 */
final class ChainValidator
{
    public const PURPOSE_SIGN = 'sign';
    public const PURPOSE_ENCRYPT = 'encrypt';

    private const MAX_DEPTH = 8;

    /** Candidate issuer comparisons per path search (bounds work on attacker-supplied pools) */
    private const PATH_BUDGET = 256;

    public function __construct(private readonly TrustStore $store, private readonly string $tempBaseDir)
    {
    }

    /**
     * @param list<string> $untrustedPems Extra (untrusted) certificates for path building
     */
    public function validate(Certificate $leaf, array $untrustedPems, string $purpose, ?int $now = null): ChainResult
    {
        $now ??= time();
        $pool = $this->buildPool($leaf, $untrustedPems);

        if (!$this->store->hasAnchors()) {
            return new ChainResult(ChainResult::NO_TRUST_STORE, []);
        }

        // one path for every decision: OpenSSL verifies exactly the path that ends in a configured
        // anchor (only its intermediates are offered as untrusted certificates); without such a path
        // nothing is trusted, whatever else a verification store might contain (audit F-02/F-05)
        $path = $this->buildPath($leaf, $pool);
        $anchoredCerts = $path['anchored'] ? $path['certs'] : [];
        $trusted = $path['anchored'] && $this->opensslCheck($leaf, array_slice($path['certs'], 1, -1), $purpose);

        if ($trusted) {
            foreach ($path['certs'] as $c) {
                // the anchored path must be valid now as well (OpenSSL may have used another one)
                if ($c->isExpired($now)) {
                    return new ChainResult(ChainResult::EXPIRED, $path['subjects'], false, $anchoredCerts);
                }
                if ($c->isNotYetValid($now)) {
                    return new ChainResult(ChainResult::NOT_YET_VALID, $path['subjects'], false, $anchoredCerts);
                }
            }
        }
        if ($trusted && $this->usesAnyPurpose($leaf, $purpose) && !self::caPathAllowsEmailProtection($path)) {
            // the "any" purpose does not check the CA certificates: a CA restricted by its EKU to other
            // uses (e.g. TLS server authentication) must not issue trusted e-mail recipients (audit MS-03)
            Log::info('chain', 'EC recipient path contains a CA not allowed for e-mail protection', ['fingerprint' => $leaf->fingerprint]);
            return new ChainResult(ChainResult::BAD_PURPOSE, $path['subjects'], false, $anchoredCerts);
        }
        if ($trusted) {
            return new ChainResult(ChainResult::TRUSTED, $path['subjects'], false, $anchoredCerts);
        }

        // diagnostics
        if ($path['anchored'] && !$path['anchorIsRoot']) {
            // the reached anchor is an intermediate CA: OpenSSL requires a chain up to a self-signed
            // root (no partial-chain trust) - the CA bundle must contain the root certificate
            return new ChainResult(ChainResult::INCOMPLETE, $path['subjects']);
        }
        if ($path['anchored']) {
            foreach ($path['certs'] as $c) {
                if ($c->isExpired($now)) {
                    return new ChainResult(ChainResult::EXPIRED, $path['subjects'], false, $anchoredCerts);
                }
                if ($c->isNotYetValid($now)) {
                    return new ChainResult(ChainResult::NOT_YET_VALID, $path['subjects'], false, $anchoredCerts);
                }
            }
            return new ChainResult(ChainResult::BAD_PURPOSE, $path['subjects'], false, $anchoredCerts);
        }

        if ($leaf->isExpired($now)) {
            // still report the most specific reason the user can act on
            return new ChainResult($path['selfSigned'] ? ChainResult::UNTRUSTED_ROOT : ChainResult::INCOMPLETE, $path['subjects'], true);
        }

        return new ChainResult($path['selfSigned'] ? ChainResult::UNTRUSTED_ROOT : ChainResult::INCOMPLETE, $path['subjects']);
    }

    /**
     * @param list<string> $untrustedPems
     *
     * @return list<Certificate>
     */
    private function buildPool(Certificate $leaf, array $untrustedPems): array
    {
        // administrator-configured intermediates first: path building prefers them over copies
        // shipped with a message (audit F-05)
        $pool = [];
        $seen = [$leaf->fingerprint => true];
        foreach ($this->store->intermediates() as $c) {
            if (!isset($seen[$c->fingerprint])) {
                $seen[$c->fingerprint] = true;
                $pool[] = $c;
            }
        }
        $extra = 0;
        foreach ($untrustedPems as $pem) {
            try {
                $c = Certificate::fromString($pem);
            } catch (ValidationException) {
                continue;
            }
            if (!isset($seen[$c->fingerprint]) && $c->isCa) {
                $seen[$c->fingerprint] = true;
                $pool[] = $c;
                $extra++;
            }
            if ($extra >= 32) {
                break;
            }
        }
        return $pool;
    }

    /**
     * @param list<Certificate> $pool intermediates of the anchored path (leaf and anchor excluded)
     */
    private function opensslCheck(Certificate $leaf, array $pool, string $purpose): bool
    {
        // bundle files + an empty plugin directory: OpenSSL's default CA directory is never consulted
        $caInfo = $this->store->verifyLocations($this->tempBaseDir);
        if ($caInfo === null) {
            return false;
        }
        // OpenSSL's SMIME_ENCRYPT purpose rejects keyAgreement (EC) certificates; for EC recipients
        // the chain is checked with the "any" purpose, key usage/EKU of the leaf are enforced by
        // Certificate and the EKU of every CA on the path by validate() (caPathAllowsEmailProtection)
        $p = match (true) {
            $purpose === self::PURPOSE_SIGN => X509_PURPOSE_SMIME_SIGN,
            $this->usesAnyPurpose($leaf, $purpose) => X509_PURPOSE_ANY,
            default => X509_PURPOSE_SMIME_ENCRYPT,
        };

        $tmp = new SecureTemp($this->tempBaseDir);
        try {
            $untrusted = $pool !== [] ? $tmp->file(implode("\n", array_map(static fn (Certificate $c) => $c->pem, $pool))) : null;
            $pem = $leaf->pem;
            [$r] = OpenSsl::run(static fn () => openssl_x509_checkpurpose($pem, $p, $caInfo, $untrusted));
            return $r === true;
        } finally {
            $tmp->cleanup();
        }
    }

    private function usesAnyPurpose(Certificate $leaf, string $purpose): bool
    {
        return $purpose !== self::PURPOSE_SIGN && $leaf->keyType === 'EC';
    }

    /**
     * Every CA certificate on the path (intermediates and the reached anchor, as OpenSSL checks them
     * for the S/MIME purposes) allows e-mail protection. A path that does not reach an anchor is
     * rejected (fail closed: the purpose of the CAs OpenSSL used cannot be confirmed).
     *
     * @param array{certs: list<Certificate>, anchored: bool} $path
     */
    private static function caPathAllowsEmailProtection(array $path): bool
    {
        if (!$path['anchored']) {
            return false;
        }
        foreach (array_slice($path['certs'], 1) as $ca) {
            if (!$ca->allowsEmailProtection()) {
                return false;
            }
        }
        return true;
    }

    /**
     * Diagnostic path building (signature + name chaining only).
     *
     * @param list<Certificate> $pool
     *
     * @return array{certs: list<Certificate>, subjects: list<string>, anchored: bool, anchorIsRoot: bool, selfSigned: bool}
     */
    private function buildPath(Certificate $leaf, array $pool): array
    {
        // the SHORTEST path ending in a configured anchor, if there is one (iterative deepening,
        // bounded): a shadowing candidate (same name, other signature) never hides the real issuer,
        // and a re-signed copy of an issuer cannot insert itself into the path (audit F-05)
        $budget = self::PATH_BUDGET;
        $anchoredPath = null;
        for ($len = 1; $len <= self::MAX_DEPTH && $anchoredPath === null && $budget > 0; $len++) {
            $anchoredPath = $this->searchAnchored([$leaf], $pool, $budget, $len);
        }
        if ($anchoredPath !== null) {
            $anchor = $anchoredPath[count($anchoredPath) - 1];
            return [
                'certs' => $anchoredPath,
                'subjects' => array_map(static fn (Certificate $c) => $c->subject, $anchoredPath),
                'anchored' => true,
                'anchorIsRoot' => $anchor->isSelfIssued() && $anchor->isIssuedBy($anchor),
                'selfSigned' => false,
            ];
        }

        // diagnostics only: greedy path explaining why no anchor is reached
        $certs = [$leaf];
        $subjects = [$leaf->subject];
        $current = $leaf;
        $anchored = false;
        $anchorIsRoot = false;
        $selfSigned = false;

        for ($depth = 0; $depth < self::MAX_DEPTH; $depth++) {
            $anchor = $this->findIssuer($current, $this->store->anchors());
            if ($anchor !== null) {
                if ($anchor->fingerprint !== $current->fingerprint) {
                    $certs[] = $anchor;
                    $subjects[] = $anchor->subject;
                }
                $anchored = true;
                $anchorIsRoot = $anchor->isSelfIssued() && $anchor->isIssuedBy($anchor);
                break;
            }
            if ($current->isSelfIssued() && $current->isIssuedBy($current)) {
                $selfSigned = true;
                break;
            }
            $next = $this->findIssuer($current, $pool);
            if ($next === null || $next->fingerprint === $current->fingerprint) {
                break;
            }
            $certs[] = $next;
            $subjects[] = $next->subject;
            $current = $next;
        }

        return ['certs' => $certs, 'subjects' => $subjects, 'anchored' => $anchored, 'anchorIsRoot' => $anchorIsRoot, 'selfSigned' => $selfSigned];
    }

    /**
     * @param list<Certificate> $certs  path so far (leaf first)
     * @param list<Certificate> $pool
     * @param int               $maxLen maximum number of non-anchor certificates on the path
     *
     * @return null|list<Certificate>
     */
    private function searchAnchored(array $certs, array $pool, int &$budget, int $maxLen): ?array
    {
        $current = $certs[count($certs) - 1];
        $anchor = $this->findIssuer($current, $this->store->anchors());
        if ($anchor !== null) {
            if ($anchor->fingerprint !== $current->fingerprint) {
                $certs[] = $anchor;
            }
            return $certs;
        }
        if (count($certs) >= $maxLen) {
            return null;
        }
        $used = array_map(static fn (Certificate $c) => $c->fingerprint, $certs);
        foreach ($pool as $c) {
            if (--$budget < 0) {
                return null;
            }
            if (in_array($c->fingerprint, $used, true) || $c->subjectNameDer !== $current->issuerNameDer || !$current->isIssuedBy($c)) {
                continue;
            }
            $found = $this->searchAnchored([...$certs, $c], $pool, $budget, $maxLen);
            if ($found !== null) {
                return $found;
            }
        }
        return null;
    }

    /**
     * @param list<Certificate> $candidates
     */
    private function findIssuer(Certificate $cert, array $candidates): ?Certificate
    {
        foreach ($candidates as $c) {
            if ($c->subjectNameDer === $cert->issuerNameDer && $cert->isIssuedBy($c)) {
                return $c;
            }
        }
        return null;
    }
}
