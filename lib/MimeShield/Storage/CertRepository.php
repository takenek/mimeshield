<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Storage;

use MimeShield\Cert\Certificate;
use MimeShield\Exception\StorageException;

/**
 * Recipient (correspondent) certificate store of ONE user. Same user scoping rules as KeyRepository.
 */
final class CertRepository
{
    public const SOURCE_IMPORT = 'import';
    public const SOURCE_MESSAGE = 'message';

    public const TRUST_VERIFIED = 'verified';   // chain validated to a configured trust anchor when stored
    public const TRUST_UNTRUSTED = 'untrusted'; // chain did not validate when stored
    public const TRUST_OBSERVED = 'observed';   // collected from a message, not validated

    private const COLUMNS = '`cert_id`, `user_id`, `fingerprint`, `serial`, `subject`, `issuer`, `emails`, `not_before`, `not_after`, `cert_pem`, `chain_pem`, `source`, `trust`, `created`, `changed`';

    public function __construct(private readonly Database $db, private readonly int $userId)
    {
        if ($userId <= 0) {
            throw new StorageException('notloggedin', 'no user');
        }
    }

    /**
     * @return list<CertRecord>
     */
    public function all(int $limit = 1000): array
    {
        $rows = $this->db->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM ' . $this->db->table('mimeshield_certs')
            . ' WHERE `user_id` = ? ORDER BY `emails`, `not_after` DESC',
            $this->userId
        );
        $rows = array_slice($rows, 0, $limit);
        $pref = $this->preferredMap();
        return array_map(static fn (array $r) => new CertRecord($r, $pref[(int) $r['cert_id']] ?? []), $rows);
    }

    public function get(int $certId): ?CertRecord
    {
        $row = $this->db->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM ' . $this->db->table('mimeshield_certs') . ' WHERE `cert_id` = ? AND `user_id` = ?',
            $certId, $this->userId
        );
        return $row ? new CertRecord($row, $this->preferredMap()[$certId] ?? []) : null;
    }

    public function findByFingerprint(string $fingerprint): ?CertRecord
    {
        $row = $this->db->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM ' . $this->db->table('mimeshield_certs') . ' WHERE `fingerprint` = ? AND `user_id` = ?',
            strtolower($fingerprint), $this->userId
        );
        return $row ? new CertRecord($row, $this->preferredMap()[(int) $row['cert_id']] ?? []) : null;
    }

    /**
     * Certificates bound to a (normalised) e-mail address, preferred first, newest first.
     *
     * @return list<CertRecord>
     */
    public function findByEmail(string $email): array
    {
        $rows = $this->db->fetchAll(
            'SELECT c.`cert_id`, c.`user_id`, c.`fingerprint`, c.`serial`, c.`subject`, c.`issuer`, c.`emails`, c.`not_before`, c.`not_after`,'
            . ' c.`cert_pem`, c.`chain_pem`, c.`source`, c.`trust`, c.`created`, c.`changed`, e.`preferred`'
            . ' FROM ' . $this->db->table('mimeshield_cert_emails') . ' e'
            . ' JOIN ' . $this->db->table('mimeshield_certs') . ' c ON c.`cert_id` = e.`cert_id` AND c.`user_id` = e.`user_id`'
            . ' WHERE e.`user_id` = ? AND e.`email` = ?'
            . ' ORDER BY e.`preferred` DESC, c.`not_after` DESC',
            $this->userId, strtolower($email)
        );
        return array_map(static fn (array $r) => new CertRecord($r, !empty($r['preferred']) ? [strtolower($email)] : []), $rows);
    }

    public function count(): int
    {
        $row = $this->db->fetchOne('SELECT COUNT(*) AS cnt FROM ' . $this->db->table('mimeshield_certs') . ' WHERE `user_id` = ?', $this->userId);
        return (int) ($row['cnt'] ?? 0);
    }

    /**
     * Store a certificate. $emails must be the certificate's own (normalised) addresses.
     *
     * @param list<string> $emails
     * @param list<string> $chainPems
     */
    public function insert(Certificate $cert, array $emails, array $chainPems, string $source, string $trust): int
    {
        $now = Database::now();
        $this->db->query(
            'INSERT INTO ' . $this->db->table('mimeshield_certs')
            . ' (`user_id`, `fingerprint`, `serial`, `subject`, `issuer`, `emails`, `not_before`, `not_after`, `cert_pem`, `chain_pem`, `source`, `trust`, `created`, `changed`)'
            . ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            $this->userId,
            $cert->fingerprint,
            substr($cert->serialHex, 0, 128),
            mb_substr($cert->subject, 0, 2048),
            mb_substr($cert->issuer, 0, 2048),
            implode("\n", $emails),
            Database::datetime($cert->notBefore),
            Database::datetime($cert->notAfter),
            $cert->pem,
            implode('', $chainPems),
            $source,
            $trust,
            $now,
            $now
        );
        $id = $this->db->insertId('mimeshield_certs');
        foreach ($emails as $email) {
            $this->db->query(
                'INSERT INTO ' . $this->db->table('mimeshield_cert_emails') . ' (`user_id`, `cert_id`, `email`, `preferred`) VALUES (?, ?, ?, 0)',
                $this->userId, $id, strtolower($email)
            );
        }
        return $id;
    }

    public function updateTrust(int $certId, string $trust): void
    {
        $this->db->query(
            'UPDATE ' . $this->db->table('mimeshield_certs') . ' SET `trust` = ?, `changed` = ? WHERE `cert_id` = ? AND `user_id` = ?',
            $trust, Database::now(), $certId, $this->userId
        );
    }

    public function delete(int $certId): bool
    {
        $this->db->query('DELETE FROM ' . $this->db->table('mimeshield_cert_emails') . ' WHERE `cert_id` = ? AND `user_id` = ?', $certId, $this->userId);
        $res = $this->db->query('DELETE FROM ' . $this->db->table('mimeshield_certs') . ' WHERE `cert_id` = ? AND `user_id` = ?', $certId, $this->userId);
        return $this->db->affected($res) > 0;
    }

    /**
     * Make $certId the preferred certificate for $email (only one preferred per address).
     */
    public function setPreferred(int $certId, string $email): void
    {
        $email = strtolower($email);
        $row = $this->db->fetchOne(
            'SELECT `cert_id` FROM ' . $this->db->table('mimeshield_cert_emails') . ' WHERE `user_id` = ? AND `cert_id` = ? AND `email` = ?',
            $this->userId, $certId, $email
        );
        if (!$row) {
            throw new StorageException('notfound', 'certificate/address pair not owned by user');
        }
        $this->db->query('UPDATE ' . $this->db->table('mimeshield_cert_emails') . ' SET `preferred` = 0 WHERE `user_id` = ? AND `email` = ?', $this->userId, $email);
        $this->db->query('UPDATE ' . $this->db->table('mimeshield_cert_emails') . ' SET `preferred` = 1 WHERE `user_id` = ? AND `cert_id` = ? AND `email` = ?', $this->userId, $certId, $email);
    }

    /**
     * cert_id => list of addresses for which it is preferred
     *
     * @return array<int, list<string>>
     */
    private function preferredMap(): array
    {
        $rows = $this->db->fetchAll('SELECT `cert_id`, `email` FROM ' . $this->db->table('mimeshield_cert_emails') . ' WHERE `user_id` = ? AND `preferred` = 1', $this->userId);
        $out = [];
        foreach ($rows as $r) {
            $out[(int) $r['cert_id']][] = (string) $r['email'];
        }
        return $out;
    }
}
