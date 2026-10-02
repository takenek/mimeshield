<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Service;

use MimeShield\Cert\Certificate;
use MimeShield\Cert\ImportedKey;
use MimeShield\Cert\KeyImporter;
use MimeShield\Cert\LegacyPkcs12Converter;
use MimeShield\Crypto\CmsInspector;
use MimeShield\Exception\MimeShieldException;
use MimeShield\Exception\ValidationException;
use MimeShield\KeyStore\KeyVault;
use MimeShield\Log;
use MimeShield\Storage\KeyRecord;
use MimeShield\Storage\KeyRepository;
use MimeShield\Trust\AddressMatcher;

/**
 * Own certificates and private keys of the logged-in user.
 */
final class KeyService
{
    public function __construct(
        private readonly KeyRepository $repo,
        private readonly KeyVault $vault,
        private readonly KeyImporter $importer,
        private readonly ?LegacyPkcs12Converter $legacy,
        private readonly int $maxKeys,
        private readonly bool $subjectEmailFallback = true,
    ) {
    }

    public function repository(): KeyRepository
    {
        return $this->repo;
    }

    /**
     * Import a PKCS#12 / PEM key. The password is wiped by the caller after this returns.
     *
     * @param list<array{identity_id: int|string, email: string}> $identities The user's identities
     *
     * @return array{id: int, certificate: Certificate, bound: list<int>, warnings: list<string>}
     */
    public function import(#[\SensitiveParameter] string $data, #[\SensitiveParameter] string $password, array $identities): array
    {
        if ($this->repo->count() >= $this->maxKeys) {
            throw new ValidationException('toomanykeys', 'key limit reached', ['max' => (string) $this->maxKeys]);
        }

        try {
            $imported = $this->importer->import($data, $password);
        } catch (ValidationException $e) {
            if ($e->getUserLabel() !== 'p12legacy' || $this->legacy === null) {
                throw $e;
            }
            // admin opted in: convert the legacy PKCS#12 with the openssl CLI (no shell, no disk)
            $pem = $this->legacy->toPem($data, $password);
            try {
                $imported = $this->importer->import($pem, '');
            } finally {
                KeyVault::wipe($pem);
            }
        }

        try {
            return $this->store($imported, $identities);
        } finally {
            $imported->wipe();
        }
    }

    /**
     * @param list<array{identity_id: int|string, email: string}> $identities
     *
     * @return array{id: int, certificate: Certificate, bound: list<int>, warnings: list<string>}
     */
    private function store(ImportedKey $imported, array $identities): array
    {
        $cert = $imported->certificate;
        if ($this->repo->findByFingerprint($cert->fingerprint) !== null) {
            throw new ValidationException('keyexists', 'certificate already imported');
        }

        $warnings = [];
        if (!$cert->canSign()) {
            $warnings[] = 'warn_cannotsign';
        }
        if (!$cert->canEncrypt()) {
            $warnings[] = 'warn_cannotencrypt';
        }
        if ($cert->isExpired()) {
            $warnings[] = 'warn_expired';
        } elseif ($cert->isNotYetValid()) {
            $warnings[] = 'warn_notyetvalid';
        }
        $emails = $cert->emails($this->subjectEmailFallback);
        if ($emails === []) {
            $warnings[] = 'warn_noemail';
        }

        $key = $imported->privateKeyPem();
        $blob = $this->vault->encrypt($key, KeyRecord::context($this->repo->userId(), $cert->fingerprint));
        $kid = KeyVault::blobKid($blob) ?? '';
        $id = $this->repo->insert($cert, $imported->chain, $blob, $kid, KeyVault::FORMAT_VERSION);
        Log::info('import', 'private key imported', ['fingerprint' => $cert->fingerprint, 'key_id' => $id]);

        // bind to matching identities: new key becomes the signing key when it is usable and
        // newer than the current one (rotation); old keys stay for decryption
        $bound = [];
        if ($cert->canSign() && $cert->isTimeValid()) {
            foreach ($identities as $ident) {
                if (!AddressMatcher::matchesAny((string) $ident['email'], $emails)) {
                    continue;
                }
                $iid = (int) $ident['identity_id'];
                $current = $this->repo->bindingFor($iid);
                $currentRec = $current !== null ? $this->repo->get($current) : null;
                if ($currentRec === null || !$this->isUsableForSigning($currentRec, (string) $ident['email'])
                    || $currentRec->certificate()->notAfter < $cert->notAfter) {
                    $this->repo->bind($iid, $id);
                    $bound[] = $iid;
                }
            }
        }

        return ['id' => $id, 'certificate' => $cert, 'bound' => $bound, 'warnings' => $warnings];
    }

    /**
     * Decrypt the private key of a record (caller wipes the result after use).
     */
    public function privateKey(KeyRecord $record): string
    {
        if ($record->userId() !== $this->repo->userId()) {
            throw new ValidationException('notfound', 'foreign key record');
        }
        return $this->vault->decrypt($record->blob(), $record->blobContext());
    }

    public function isUsableForSigning(KeyRecord $record, string $email): bool
    {
        try {
            $c = $record->certificate();
        } catch (ValidationException) {
            return false;
        }
        return $c->canSign() && $c->isTimeValid() && AddressMatcher::matchesAny($email, $c->emails($this->subjectEmailFallback));
    }

    /**
     * Signing key for an identity, or an exception explaining why there is none.
     *
     * @param array{identity_id: int|string, email: string} $identity
     */
    public function signerFor(array $identity): KeyRecord
    {
        $email = (string) $identity['email'];
        $bound = $this->repo->bindingFor((int) $identity['identity_id']);
        $record = $bound !== null ? $this->repo->get($bound) : null;

        if ($record === null) {
            throw new ValidationException('signnocert', 'no certificate bound to identity', ['email' => $email]);
        }
        $cert = $record->certificate();
        if (!AddressMatcher::matchesAny($email, $cert->emails($this->subjectEmailFallback))) {
            // never sign with a certificate issued for another address
            throw new ValidationException('signaddressmismatch', 'certificate does not cover identity address', ['email' => $email]);
        }
        if ($cert->isExpired()) {
            throw new ValidationException('signcertexpired', 'signing certificate expired', ['date' => gmdate('Y-m-d', $cert->notAfter)]);
        }
        if ($cert->isNotYetValid()) {
            throw new ValidationException('signcertnotyet', 'signing certificate not yet valid', ['date' => gmdate('Y-m-d', $cert->notBefore)]);
        }
        if (!$cert->canSign()) {
            throw new ValidationException('signcertusage', 'certificate not usable for signing');
        }
        return $record;
    }

    /** @var array<int, bool> key id => blob authenticated with the master key (per request) */
    private array $authentic = [];

    /**
     * Own certificate usable as encryption recipient for $email (encrypt-to-self / own addresses).
     *
     * Only records whose private key blob authenticates under the master key (AEAD over user id +
     * fingerprint) are used: a row inserted or modified directly in the database cannot redirect
     * encryption to a foreign certificate (audit MS-09).
     */
    public function encryptionCertFor(string $email, ?int $identityId = null): ?Certificate
    {
        $candidates = [];
        if ($identityId !== null && ($b = $this->repo->bindingFor($identityId)) !== null && ($r = $this->repo->get($b)) !== null) {
            $candidates[] = $r;
        }
        foreach ($this->repo->all() as $r) {
            $candidates[] = $r;
        }
        foreach ($candidates as $r) {
            try {
                $c = $r->certificate();
            } catch (ValidationException) {
                continue;
            }
            if ($c->canEncrypt() && $c->isTimeValid() && AddressMatcher::matchesAny($email, $c->emails($this->subjectEmailFallback))
                && $this->isAuthentic($r)) {
                return $c;
            }
        }
        return null;
    }

    /**
     * The record's key blob decrypts and authenticates for its user and fingerprint.
     */
    private function isAuthentic(KeyRecord $r): bool
    {
        if (!isset($this->authentic[$r->id()])) {
            try {
                $pem = $this->vault->decrypt($r->blob(), $r->blobContext());
                KeyVault::wipe($pem);
                $this->authentic[$r->id()] = true;
            } catch (MimeShieldException $e) {
                Log::error('keystore', 'own key record failed authentication - not used for encryption', ['key_id' => $r->id(), 'reason' => $e->getUserLabel()]);
                $this->authentic[$r->id()] = false;
            }
        }
        return $this->authentic[$r->id()];
    }

    /**
     * Own keys ordered by how likely they decrypt $der (RecipientInfo match first).
     *
     * @return list<KeyRecord>
     */
    public function decryptionCandidates(string $der, int $max = 25): array
    {
        $all = $this->repo->all();
        $ids = [];
        try {
            foreach (CmsInspector::envelopedData($der)['recipients'] as $ri) {
                $ids[] = $ri;
            }
        } catch (ValidationException) {
            $ids = [];
        }
        $matched = [];
        $rest = [];
        foreach ($all as $r) {
            try {
                $c = $r->certificate();
            } catch (ValidationException) {
                continue;
            }
            $hit = false;
            foreach ($ids as $ri) {
                if ((isset($ri['serial'], $ri['issuer']) && $ri['serial'] === $c->serialHex && $ri['issuer'] === $c->issuerNameDer)
                    || (isset($ri['ski']) && $c->subjectKeyId !== '' && $ri['ski'] === $c->subjectKeyId)) {
                    $hit = true;
                    break;
                }
            }
            if ($hit) {
                $matched[] = $r;
            } else {
                // identifiers may be computed differently by some clients: try the others afterwards
                $rest[] = $r;
            }
        }
        return array_slice(array_merge($matched, $rest), 0, $max);
    }

    public function delete(int $keyId): bool
    {
        $ok = $this->repo->delete($keyId);
        if ($ok) {
            Log::info('delete', 'private key deleted', ['key_id' => $keyId]);
        }
        return $ok;
    }
}
