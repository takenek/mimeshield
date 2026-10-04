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

namespace MimeShield\Storage;

use MimeShield\Cert\Certificate;
use MimeShield\Exception\StorageException;

/**
 * Own certificates/keys and identity bindings of ONE user.
 *
 * The user id is injected once (from the authenticated Roundcube session) and is part of EVERY
 * statement; ids coming from requests are only ever used together with it, so a foreign key_id
 * simply matches nothing (no IDOR).
 */
final class KeyRepository
{
    private const COLUMNS = '`key_id`, `user_id`, `fingerprint`, `serial`, `subject`, `issuer`, `emails`, `not_before`, `not_after`, `cert_pem`, `chain_pem`, `key_blob`, `key_kid`, `key_format`, `key_type`, `key_bits`, `created`, `changed`';

    public function __construct(private readonly Database $db, private readonly int $userId)
    {
        if ($userId <= 0) {
            throw new StorageException('notloggedin', 'no user');
        }
    }

    public function userId(): int
    {
        return $this->userId;
    }

    /**
     * @return list<KeyRecord>
     */
    public function all(): array
    {
        $rows = $this->db->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM ' . $this->db->table('mimeshield_keys')
            . ' WHERE `user_id` = ? ORDER BY `not_after` DESC, `key_id` DESC',
            $this->userId
        );
        return array_map(static fn (array $r) => new KeyRecord($r), $rows);
    }

    public function get(int $keyId): ?KeyRecord
    {
        $row = $this->db->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM ' . $this->db->table('mimeshield_keys')
            . ' WHERE `key_id` = ? AND `user_id` = ?',
            $keyId, $this->userId
        );
        return $row ? new KeyRecord($row) : null;
    }

    public function findByFingerprint(string $fingerprint): ?KeyRecord
    {
        $row = $this->db->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM ' . $this->db->table('mimeshield_keys')
            . ' WHERE `fingerprint` = ? AND `user_id` = ?',
            strtolower($fingerprint), $this->userId
        );
        return $row ? new KeyRecord($row) : null;
    }

    public function count(): int
    {
        $row = $this->db->fetchOne('SELECT COUNT(*) AS cnt FROM ' . $this->db->table('mimeshield_keys') . ' WHERE `user_id` = ?', $this->userId);
        return (int) ($row['cnt'] ?? 0);
    }

    /**
     * @param list<Certificate> $chain
     */
    public function insert(Certificate $cert, array $chain, string $blob, string $kid, int $format): int
    {
        $now = Database::now();
        $this->db->query(
            'INSERT INTO ' . $this->db->table('mimeshield_keys')
            . ' (`user_id`, `fingerprint`, `serial`, `subject`, `issuer`, `emails`, `not_before`, `not_after`, `cert_pem`, `chain_pem`, `key_blob`, `key_kid`, `key_format`, `key_type`, `key_bits`, `created`, `changed`)'
            . ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            $this->userId,
            $cert->fingerprint,
            substr($cert->serialHex, 0, 128),
            mb_substr($cert->subject, 0, 2048),
            mb_substr($cert->issuer, 0, 2048),
            implode("\n", $cert->emails()),
            Database::datetime($cert->notBefore),
            Database::datetime($cert->notAfter),
            $cert->pem,
            implode('', array_map(static fn (Certificate $c) => $c->pem, $chain)),
            $blob,
            $kid,
            $format,
            $cert->keyType,
            $cert->keyBits,
            $now,
            $now
        );
        return $this->db->insertId('mimeshield_keys');
    }

    public function delete(int $keyId): bool
    {
        // bindings go away through the FK cascade; delete them explicitly as well (sqlite without FK pragma)
        $this->db->query('DELETE FROM ' . $this->db->table('mimeshield_bindings') . ' WHERE `key_id` = ? AND `user_id` = ?', $keyId, $this->userId);
        $res = $this->db->query('DELETE FROM ' . $this->db->table('mimeshield_keys') . ' WHERE `key_id` = ? AND `user_id` = ?', $keyId, $this->userId);
        return $this->db->affected($res) > 0;
    }

    /**
     * identity_id => key_id
     *
     * @return array<int, int>
     */
    public function bindings(): array
    {
        $rows = $this->db->fetchAll('SELECT `identity_id`, `key_id` FROM ' . $this->db->table('mimeshield_bindings') . ' WHERE `user_id` = ?', $this->userId);
        $out = [];
        foreach ($rows as $r) {
            $out[(int) $r['identity_id']] = (int) $r['key_id'];
        }
        return $out;
    }

    public function bindingFor(int $identityId): ?int
    {
        $row = $this->db->fetchOne(
            'SELECT `key_id` FROM ' . $this->db->table('mimeshield_bindings') . ' WHERE `user_id` = ? AND `identity_id` = ?',
            $this->userId, $identityId
        );
        return $row ? (int) $row['key_id'] : null;
    }

    /**
     * Bind $keyId to $identityId. Ownership of BOTH must have been verified by the caller
     * (identity via rcube_user::get_identity, key via get()).
     */
    public function bind(int $identityId, int $keyId): void
    {
        if ($this->get($keyId) === null) {
            throw new StorageException('notfound', 'key not owned by user');
        }
        $this->unbind($identityId);
        $this->db->query(
            'INSERT INTO ' . $this->db->table('mimeshield_bindings') . ' (`user_id`, `identity_id`, `key_id`, `changed`) VALUES (?, ?, ?, ?)',
            $this->userId, $identityId, $keyId, Database::now()
        );
    }

    public function unbind(int $identityId): void
    {
        $this->db->query('DELETE FROM ' . $this->db->table('mimeshield_bindings') . ' WHERE `user_id` = ? AND `identity_id` = ?', $this->userId, $identityId);
    }
}
