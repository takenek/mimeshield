<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Service;

use MimeShield\Cert\Certificate;
use MimeShield\Cert\PublicCertImporter;
use MimeShield\Exception\ValidationException;
use MimeShield\Log;
use MimeShield\Storage\CertRecord;
use MimeShield\Storage\CertRepository;
use MimeShield\Trust\AddressMatcher;
use MimeShield\Trust\ChainValidator;
use MimeShield\Trust\RevocationChecker;
use MimeShield\Trust\RevocationResult;
use MimeShield\Trust\TrustStore;
use MimeShield\Trust\VerificationResult;

/**
 * Correspondent certificate store: import, collection from signed messages and recipient
 * resolution for encryption.
 */
final class CertificateService
{
    public const R_OK = 'ok';
    public const R_UNTRUSTED = 'untrusted';   // usable only when policy = warn
    public const R_MISSING = 'missing';
    public const R_EXPIRED = 'expired';
    public const R_INVALID = 'invalid';       // wrong usage / revoked / untrusted with policy block

    /** detail of an R_OK result whose revocation status could not be determined (CRL checking on) */
    public const D_REVOCATION_UNKNOWN = 'trusted-revocationunknown';

    public function __construct(
        private readonly CertRepository $repo,
        private readonly PublicCertImporter $importer,
        private readonly ChainValidator $chains,
        private readonly RevocationChecker $revocation,
        private readonly KeyService $keys,
        private readonly int $maxCerts,
        private readonly string $untrustedPolicy = 'block',
        private readonly bool $subjectEmailFallback = true,
        private readonly ?TrustStore $trust = null,
        private readonly string $revocationUnknownPolicy = 'warn',
        private readonly ?\Closure $identityEmails = null,
    ) {
    }

    public function repository(): CertRepository
    {
        return $this->repo;
    }

    /**
     * Import public certificate(s) from an uploaded file.
     *
     * When a certificate for one of the addresses already exists with a DIFFERENT fingerprint and
     * $confirmed is false, nothing is stored and 'confirm' lists the old certificates (fingerprint
     * change warning).
     *
     * @return array{imported: list<array{id: int, certificate: Certificate, trust: string}>, confirm: list<array{email: string, old: list<string>, new: string}>, skipped: list<string>, updated: list<array{id: int, trust: string}>}
     */
    public function importFile(string $data, bool $confirmed): array
    {
        $parsed = $this->importer->parse($data);
        if ($parsed['entities'] === []) {
            throw new ValidationException('certnoentity', 'only CA certificates in file');
        }
        $chainPems = array_map(static fn (Certificate $c) => $c->pem, $parsed['cas']);

        $confirm = [];
        foreach ($parsed['entities'] as $cert) {
            $confirm = array_merge($confirm, $this->fingerprintChanges($cert));
        }
        if ($confirm !== [] && !$confirmed) {
            return ['imported' => [], 'confirm' => $confirm, 'skipped' => [], 'updated' => []];
        }

        $imported = [];
        $skipped = [];
        $updated = [];
        foreach ($parsed['entities'] as $cert) {
            $existing = $this->repo->findByFingerprint($cert->fingerprint);
            if ($existing !== null) {
                // same certificate uploaded again together with its CA chain: store the chain and
                // re-evaluate the trust flag (e.g. an earlier chain-less import was 'untrusted')
                $merged = array_values(array_unique(array_merge($existing->chainPems(), $chainPems)));
                if ($chainPems !== [] && count($merged) > count($existing->chainPems())) {
                    $chain = $this->chains->validate($cert, $merged, $cert->canEncrypt() ? ChainValidator::PURPOSE_ENCRYPT : ChainValidator::PURPOSE_SIGN);
                    $trust = $chain->isTrusted() ? CertRepository::TRUST_VERIFIED : $existing->trust();
                    $this->repo->updateChain($existing->id(), $merged, $trust);
                    $updated[] = ['id' => $existing->id(), 'trust' => $trust];
                } else {
                    $skipped[] = $cert->fingerprint;
                }
                continue;
            }
            $emails = $cert->emails($this->subjectEmailFallback);
            if ($emails === []) {
                throw new ValidationException('certnoemail', 'certificate without e-mail address');
            }
            if (!$cert->canEncrypt() && !$cert->canSign()) {
                throw new ValidationException('certnotsmime', 'certificate not usable for S/MIME');
            }
            $id = $this->add($cert, $chainPems, CertRepository::SOURCE_IMPORT);
            $imported[] = ['id' => $id, 'certificate' => $cert, 'trust' => (string) $this->repo->get($id)?->trust()];
        }

        return ['imported' => $imported, 'confirm' => [], 'skipped' => $skipped, 'updated' => $updated];
    }

    /**
     * Save the signer certificate of a VERIFIED message. Requires a cryptographically valid
     * signature whose certificate matches the From address. The certificate is NOT trusted because
     * of this: its trust flag reflects chain validation only.
     *
     * @return array{id: int, trust: string, confirm: list<array{email: string, old: list<string>, new: string}>}
     */
    public function saveFromMessage(VerificationResult $result, bool $confirmed): array
    {
        $cert = $result->signer;
        if ($cert === null || !$result->cryptoValid() || $result->identity !== VerificationResult::IDENTITY_MATCH) {
            throw new ValidationException('savecertrefused', 'signature not valid or sender mismatch');
        }
        if ($cert->isExpired() || !$cert->canEncrypt()) {
            throw new ValidationException('certnotsmime', 'certificate expired or not usable for encryption');
        }
        $existing = $this->repo->findByFingerprint($cert->fingerprint);
        if ($existing !== null) {
            return ['id' => $existing->id(), 'trust' => $existing->trust(), 'confirm' => []];
        }
        $confirm = $this->fingerprintChanges($cert);
        if ($confirm !== [] && !$confirmed) {
            return ['id' => 0, 'trust' => '', 'confirm' => $confirm];
        }
        $chain = array_values(array_filter($result->check->embeddedPems, static function (string $pem) use ($cert) {
            try {
                $c = Certificate::fromString($pem);
            } catch (ValidationException) {
                return false;
            }
            return $c->isCa && $c->fingerprint !== $cert->fingerprint;
        }));
        $id = $this->add($cert, $chain, CertRepository::SOURCE_MESSAGE);
        return ['id' => $id, 'trust' => (string) $this->repo->get($id)?->trust(), 'confirm' => []];
    }

    /**
     * Resolve recipient certificates for encryption.
     *
     * @param list<string> $emails normalised addresses
     *
     * @return array<string, array{status: string, cert: ?Certificate, detail: string}>
     */
    public function resolveRecipients(array $emails): array
    {
        $out = [];
        foreach ($emails as $email) {
            $out[$email] = $this->resolveOne($email);
        }
        return $out;
    }

    /**
     * @return array{status: string, cert: ?Certificate, detail: string}
     */
    public function resolveOne(string $email): array
    {
        // own addresses (identities of the user): use own certificate; any other address is resolved
        // through the correspondent store with chain validation (audit MS-09)
        $own = $this->isOwnAddress($email) ? $this->keys->encryptionCertFor($email) : null;
        if ($own !== null) {
            return ['status' => self::R_OK, 'cert' => $own, 'detail' => 'own'];
        }

        $best = ['status' => self::R_MISSING, 'cert' => null, 'detail' => ''];
        foreach ($this->repo->findByEmail($email) as $rec) {
            $eval = $this->evaluate($rec, $email);
            if ($eval['status'] === self::R_OK) {
                return $eval;
            }
            // keep the most informative failure (untrusted > expired > invalid > missing)
            $rank = [self::R_UNTRUSTED => 3, self::R_EXPIRED => 2, self::R_INVALID => 1, self::R_MISSING => 0];
            if ($rank[$eval['status']] > $rank[$best['status']]) {
                $best = $eval;
            }
        }
        if ($best['status'] === self::R_UNTRUSTED && $this->untrustedPolicy !== 'warn') {
            $best['status'] = self::R_INVALID;
            $best['detail'] = 'untrusted';
        }
        return $best;
    }

    /**
     * @return array{status: string, cert: ?Certificate, detail: string}
     */
    private function evaluate(CertRecord $rec, string $email): array
    {
        try {
            $cert = $rec->certificate();
        } catch (ValidationException) {
            return ['status' => self::R_INVALID, 'cert' => null, 'detail' => 'unparsable'];
        }
        // re-check the binding from the certificate itself, never only from the index table
        if (!AddressMatcher::matchesAny($email, $cert->emails($this->subjectEmailFallback))) {
            return ['status' => self::R_INVALID, 'cert' => null, 'detail' => 'address'];
        }
        if ($cert->isExpired() || $cert->isNotYetValid()) {
            return ['status' => self::R_EXPIRED, 'cert' => $cert, 'detail' => $cert->isExpired() ? 'expired' : 'notyet'];
        }
        if (!$cert->canEncrypt()) {
            return ['status' => self::R_INVALID, 'cert' => $cert, 'detail' => 'usage'];
        }
        $chain = $this->chains->validate($cert, $rec->chainPems(), ChainValidator::PURPOSE_ENCRYPT);
        $revocationUnknown = false;
        if ($chain->isTrusted() && $this->revocation->isEnabled()) {
            // same issuer lookup as signature verification: stored chain + configured intermediates
            // + trust anchors (a certificate imported without its chain is still checked, audit MS-04)
            $issuer = $this->findIssuer($cert, $rec->chainPems());
            $rev = $this->revocation->check($cert, $issuer);
            if ($rev->status === RevocationResult::REVOKED) {
                return ['status' => self::R_INVALID, 'cert' => $cert, 'detail' => 'revoked'];
            }
            if ($rev->status === RevocationResult::UNKNOWN) {
                Log::info('certs', 'recipient revocation status unknown', ['fingerprint' => $cert->fingerprint, 'reason' => $rev->reason]);
                if ($this->revocationUnknownPolicy === 'block') {
                    return ['status' => self::R_INVALID, 'cert' => $cert, 'detail' => 'revocationunknown'];
                }
                $revocationUnknown = true;
            }
        }
        if (!$chain->isTrusted()) {
            return ['status' => self::R_UNTRUSTED, 'cert' => $cert, 'detail' => $chain->status];
        }
        return ['status' => self::R_OK, 'cert' => $cert, 'detail' => $revocationUnknown ? self::D_REVOCATION_UNKNOWN : 'trusted'];
    }

    private function isOwnAddress(string $email): bool
    {
        if ($this->identityEmails === null) {
            return true;
        }
        $mine = array_values(array_filter(array_map(
            static fn ($e) => AddressMatcher::normalize((string) $e),
            (array) ($this->identityEmails)()
        )));
        return AddressMatcher::matchesAny($email, $mine);
    }

    /**
     * @param list<string> $chainPems
     */
    private function findIssuer(Certificate $cert, array $chainPems): ?Certificate
    {
        if ($this->trust !== null) {
            return $this->trust->findIssuer($cert, $chainPems);
        }
        foreach ($chainPems as $pem) {
            try {
                $c = Certificate::fromString($pem);
            } catch (ValidationException) {
                continue;
            }
            if ($c->fingerprint !== $cert->fingerprint && $cert->isIssuedBy($c)) {
                return $c;
            }
        }
        return null;
    }

    /**
     * Existing certificates (other fingerprints) for the addresses of $cert.
     *
     * @return list<array{email: string, old: list<string>, new: string}>
     */
    public function fingerprintChanges(Certificate $cert): array
    {
        $out = [];
        foreach ($cert->emails($this->subjectEmailFallback) as $email) {
            $old = [];
            foreach ($this->repo->findByEmail($email) as $rec) {
                if ($rec->fingerprint() !== $cert->fingerprint) {
                    $old[] = $rec->fingerprint();
                }
            }
            if ($old !== []) {
                $out[] = ['email' => $email, 'old' => $old, 'new' => $cert->fingerprint];
            }
        }
        return $out;
    }

    /**
     * @param list<string> $chainPems
     */
    private function add(Certificate $cert, array $chainPems, string $source): int
    {
        if ($this->repo->count() >= $this->maxCerts) {
            throw new ValidationException('toomanycerts', 'certificate limit reached', ['max' => (string) $this->maxCerts]);
        }
        $chain = $this->chains->validate($cert, $chainPems, $cert->canEncrypt() ? ChainValidator::PURPOSE_ENCRYPT : ChainValidator::PURPOSE_SIGN);
        $trust = $chain->isTrusted() ? CertRepository::TRUST_VERIFIED
            : ($source === CertRepository::SOURCE_MESSAGE ? CertRepository::TRUST_OBSERVED : CertRepository::TRUST_UNTRUSTED);
        $emails = $cert->emails($this->subjectEmailFallback);
        $id = $this->repo->insert($cert, $emails, $chainPems, $source, $trust);
        // a newly added certificate becomes the preferred one for its addresses
        foreach ($emails as $email) {
            $this->repo->setPreferred($id, $email);
        }
        Log::info('certstore', 'certificate stored', ['fingerprint' => $cert->fingerprint, 'source' => $source, 'trust' => $trust]);
        return $id;
    }
}
