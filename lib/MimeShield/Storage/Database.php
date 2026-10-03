<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Storage;

use MimeShield\Exception\StorageException;
use MimeShield\Log;

/**
 * Thin helper around Roundcube's rcube_db (parameterised queries, prefixed table names, errors).
 */
final class Database
{
    public const SCHEMA_VERSION = '2026100200';

    public function __construct(private readonly \rcube_db $db)
    {
    }

    public function raw(): \rcube_db
    {
        return $this->db;
    }

    /** Run a group of writes atomically; failure to begin must not execute any write. */
    public function transaction(callable $write): void
    {
        if (!$this->db->startTransaction()) {
            throw new StorageException('dberror', 'cannot start database transaction');
        }
        try {
            $write();
            if (!$this->db->endTransaction()) {
                throw new StorageException('dberror', 'cannot commit database transaction');
            }
        } catch (\Throwable $e) {
            try {
                $this->db->rollbackTransaction();
            } catch (\Throwable) {
                // Preserve the original failure. Never report a partially saved operation as success.
            }
            throw $e;
        }
    }

    /**
     * Prefixed, quoted table name ($config['db_prefix'] is applied by rcube_db).
     */
    public function table(string $name): string
    {
        return $this->db->table_name($name, true);
    }

    /**
     * Run a parameterised query; throws on error.
     *
     * @param mixed ...$params
     *
     * @return \PDOStatement
     */
    public function query(string $sql, ...$params): mixed
    {
        $res = $this->db->query($sql, ...$params);
        $err = $this->db->is_error($res);
        if ($res === false || $err) {
            Log::error('db', 'query failed', ['error' => (string) $err]);
            throw new StorageException('dberror', 'database error');
        }
        return $res;
    }

    /**
     * @param mixed ...$params
     *
     * @return list<array<string, ?string>>
     */
    public function fetchAll(string $sql, ...$params): array
    {
        $res = $this->query($sql, ...$params);
        $rows = [];
        while ($row = $this->db->fetch_assoc($res)) {
            $rows[] = $row;
        }
        return $rows;
    }

    /**
     * @param mixed ...$params
     *
     * @return null|array<string, ?string>
     */
    public function fetchOne(string $sql, ...$params): ?array
    {
        $res = $this->query($sql, ...$params);
        $row = $this->db->fetch_assoc($res);
        return is_array($row) ? $row : null;
    }

    public function insertId(string $table): int
    {
        // NOTE: unprefixed name - the pgsql driver builds "<prefix><table>_seq" itself
        $id = $this->db->insert_id($table);
        if (!$id) {
            throw new StorageException('dberror', 'no insert id');
        }
        return (int) $id;
    }

    public function affected(mixed $res): int
    {
        return (int) $this->db->affected_rows($res);
    }

    public static function now(): string
    {
        return gmdate('Y-m-d H:i:s');
    }

    public static function datetime(int $ts): string
    {
        // clamp to the range every supported database accepts
        $ts = max(-30610224000, min($ts, 253402300799)); // 1000-01-01 .. 9999-12-31
        return gmdate('Y-m-d H:i:s', $ts);
    }

    /**
     * Installed schema version ('' if the plugin schema is not installed).
     */
    public function schemaVersion(): string
    {
        $this->db->set_option('ignore_errors', true);
        try {
            $res = $this->db->query('SELECT `value` FROM ' . $this->table('system') . ' WHERE `name` = ?', 'mimeshield-version');
            $row = $res ? $this->db->fetch_assoc($res) : null;
        } finally {
            $this->db->set_option('ignore_errors', false);
        }
        return is_array($row) ? preg_replace('/[^0-9]/', '', (string) $row['value']) ?? '' : '';
    }

    public function isSchemaCurrent(): bool
    {
        return $this->schemaVersion() >= self::SCHEMA_VERSION;
    }
}
