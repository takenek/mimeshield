<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield;

use MimeShield\Exception\StorageException;
use MimeShield\Storage\Database;

/**
 * Sliding-window request limits (audit MS-11, F-08).
 *
 * Bounds how often a session - and, with allowForUser(), a user account across all its sessions
 * - can trigger expensive cryptographic work (recipient chain validation / CRL fetches, PKCS#12 key
 * derivation). It does not replace limits at the edge (reverse proxy, WAF, PHP-FPM
 * request_terminate_timeout).
 */
final class RateLimiter
{
    /**
     * Record a request in $bucket and tell whether it is within $max requests per $window seconds.
     * A refused request is not recorded. Shared stores retain future hits across clock rollback.
     *
     * @param array<array-key, mixed> $store e.g. $_SESSION
     */
    public static function allow(array &$store, string $bucket, int $max, int $window, ?int $now = null, bool $keepFuture = false): bool
    {
        $now ??= time();
        $hits = array_values(array_filter(
            is_array($store[$bucket] ?? null) ? $store[$bucket] : [],
            static fn ($t) => is_int($t) && $t > $now - $window && ($keepFuture || $t <= $now)
        ));
        if (count($hits) >= $max) {
            $store[$bucket] = $hits;
            return false;
        }
        $hits[] = $now;
        $store[$bucket] = $hits;
        return true;
    }

    /**
     * Atomically reserve an attempt in Roundcube's cache table before expensive work starts.
     * A no-op update locks the existing user row across database drivers, serialising concurrent
     * sessions without a schema change. The lock is released before any cryptography. Roundcube's
     * cache object cannot be used here: its writes are buffered and read-modify-write is not atomic.
     * Any storage failure refuses the operation instead of falling back to a session-only limit.
     */
    public static function allowForUser(Database $db, int $userId, string $bucket, int $max, int $window, ?int $now = null): bool
    {
        if ($userId <= 0 || $max <= 0 || $window <= 0 || !preg_match('/^[a-z0-9_]{1,48}$/D', $bucket)) {
            return false;
        }
        $allowed = false;
        try {
            // Reads must stay on the writer too, including installations with a read replica.
            $db->raw()->set_table_dsn('users', 'w');
            $db->raw()->set_table_dsn('cache', 'w');
            $db->transaction(static function () use ($db, $userId, $bucket, $max, $window, $now, &$allowed): void {
                $users = $db->table('users');
                $cache = $db->table('cache');
                $key = 'mimeshield_rl_atomic.' . $bucket;
                $db->query("UPDATE {$users} SET `user_id` = `user_id` WHERE `user_id` = ?", $userId);
                // Lock contention must not make this request's timestamp older than reservations
                // committed while it waited. Keep future hits too for cross-node clock skew.
                $now ??= time();
                if ($db->fetchOne("SELECT `user_id` FROM {$users} WHERE `user_id` = ?", $userId) === null) {
                    throw new StorageException('notloggedin', 'rate limit user does not exist');
                }
                $row = $db->fetchOne("SELECT `data` FROM {$cache} WHERE `user_id` = ? AND `cache_key` = ?", $userId, $key);
                $hits = $row === null ? [] : json_decode((string) $row['data'], true);
                if (!is_array($hits)) {
                    throw new StorageException('dberror', 'rate limit state is invalid');
                }
                $store = [$bucket => $hits];
                $allowed = self::allow($store, $bucket, $max, $window, $now, true);
                $expires = max([$now, ...$store[$bucket]]) + $window * 2;
                $db->query("DELETE FROM {$cache} WHERE `user_id` = ? AND `cache_key` = ?", $userId, $key);
                $db->query("INSERT INTO {$cache} (`user_id`, `cache_key`, `expires`, `data`) VALUES (?, ?, ?, ?)",
                    $userId, $key, Database::datetime($expires), json_encode($store[$bucket], JSON_THROW_ON_ERROR));
            });
        } catch (\Throwable $e) {
            Log::exception('ratelimit', $e);
            return false;
        }
        return $allowed;
    }
}
