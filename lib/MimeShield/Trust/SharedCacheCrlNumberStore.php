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

namespace MimeShield\Trust;

use MimeShield\Exception\StorageException;
use MimeShield\Storage\Database;

/**
 * CrlNumberStore in Roundcube's cache_shared table, so the highest cRLNumber is shared by all users
 * and all servers of an installation (audit I-02).
 *
 * The rows are written directly, not through rcube_cache (audit V-02, V-04): put() raises the stored
 * number inside a transaction that locks the row first (InnoDB / PostgreSQL row lock, SQLite database
 * write lock), never lowers it and never replaces a higher number another request wrote concurrently;
 * the value is JSON validated on read (no unserialize() of database content). A row read more than
 * REFRESH seconds after it was written gets its expiry renewed with a compare-and-swap on the
 * unchanged value, so a CRL that is used but rarely re-issued keeps its mark - the refresh can never
 * move the number. Rows the plugin cannot decode (e.g. the serialized format of earlier plugin
 * versions) count as "no number seen". Roundcube's cache garbage collection removes expired rows.
 */
final class SharedCacheCrlNumberStore implements CrlNumberStore
{
    public const PREFIX = 'mimeshield_crlnum';

    /** lifetime of a mark in seconds, renewed on use */
    public const TTL_SECONDS = 30 * 86400;

    private const REFRESH = 86400;

    public function __construct(private readonly Database $db)
    {
    }

    public function get(string $key): ?string
    {
        $table = $this->db->table('cache_shared');
        $dbKey = self::dbKey($key);
        $best = null;
        $stale = [];
        foreach ($this->db->fetchAll("SELECT `data` FROM {$table} WHERE `cache_key` = ?", $dbKey) as $row) {
            $raw = (string) ($row['data'] ?? '');
            $v = self::decode($raw);
            if ($v === null) {
                continue;
            }
            if ($best === null || RevocationChecker::compareNumbers($v['n'], $best) > 0) {
                $best = $v['n'];
            }
            if (time() - $v['t'] > self::REFRESH) {
                $stale[$raw] = $v['n'];
            }
        }
        foreach ($stale as $raw => $number) {
            // renew the expiry of an UNCHANGED row only (compare-and-swap on the stored value): a
            // higher number written by another request in the meantime is never overwritten (V-02)
            $this->db->query("UPDATE {$table} SET `expires` = ?, `data` = ? WHERE `cache_key` = ? AND `data` = ?",
                Database::datetime(time() + self::TTL_SECONDS), self::encode($number), $dbKey, $raw);
        }
        return $best;
    }

    public function put(string $key, string $number): void
    {
        $table = $this->db->table('cache_shared');
        $dbKey = self::dbKey($key);
        // reads inside the transaction must see the committed writes of other servers: writer connection
        $this->db->raw()->set_table_dsn('cache_shared', 'w');
        try {
            $this->raise($table, $dbKey, $number);
        } catch (StorageException) {
            // cache_key is the primary key in every Roundcube schema: of two concurrent FIRST writers
            // the second one fails on its INSERT, finds the winner's row on the retry, locks it and
            // raises it if its own number is the higher one (otherwise the retry is a no-op)
            $this->raise($table, $dbKey, $number);
        }
    }

    private function raise(string $table, string $dbKey, string $number): void
    {
        $this->db->transaction(function () use ($table, $dbKey, $number): void {
            // lock the existing row before reading: a no-op update is portable across the supported
            // drivers (the pattern of RateLimiter::allowForUser()); the SELECT then sees the committed
            // number of a concurrent writer that held the lock before us
            $this->db->query("UPDATE {$table} SET `cache_key` = `cache_key` WHERE `cache_key` = ?", $dbKey);
            $rows = $this->db->fetchAll("SELECT `data` FROM {$table} WHERE `cache_key` = ?", $dbKey);
            $current = null;
            foreach ($rows as $row) {
                $v = self::decode((string) ($row['data'] ?? ''));
                if ($v !== null && ($current === null || RevocationChecker::compareNumbers($v['n'], $current) > 0)) {
                    $current = $v['n'];
                }
            }
            if ($current !== null && RevocationChecker::compareNumbers($number, $current) <= 0) {
                return;   // never below (or equal to) the high-water mark already stored
            }
            $expires = Database::datetime(time() + self::TTL_SECONDS);
            if ($rows === []) {
                $this->db->query("INSERT INTO {$table} (`cache_key`, `expires`, `data`) VALUES (?, ?, ?)", $dbKey, $expires, self::encode($number));
            } else {
                $this->db->query("UPDATE {$table} SET `expires` = ?, `data` = ? WHERE `cache_key` = ?", $expires, self::encode($number), $dbKey);
            }
        });
    }

    private static function dbKey(string $key): string
    {
        return self::PREFIX . '.' . $key;
    }

    private static function encode(string $number): string
    {
        return json_encode(['n' => $number, 't' => time()], JSON_THROW_ON_ERROR);
    }

    /**
     * @return null|array{n: string, t: int}
     */
    private static function decode(string $raw): ?array
    {
        $v = json_decode($raw, true);
        if (!is_array($v) || !is_string($v['n'] ?? null) || preg_match('/^[0-9A-F]{1,128}$/D', $v['n']) !== 1 || !is_int($v['t'] ?? null)) {
            return null;
        }
        return ['n' => $v['n'], 't' => $v['t']];
    }
}
