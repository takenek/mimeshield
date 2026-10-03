<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Trust;

/**
 * CrlNumberStore in Roundcube's shared cache (table cache_shared with the db driver), so the highest
 * cRLNumber is shared by all users and all servers of an installation (audit I-02).
 *
 * rcube_cache caps every TTL at 30 days (rcube_cache::__construct), so the intended 90 days are not
 * possible; an entry read more than REFRESH seconds after it was written is written again, which
 * keeps the high-water mark of a CRL that is used but rarely re-issued alive. Best effort: two
 * servers storing concurrently may keep the lower of two new numbers - never one below the previous
 * high-water mark.
 */
final class SharedCacheCrlNumberStore implements CrlNumberStore
{
    public const PREFIX = 'mimeshield_crlnum';
    public const TTL = '30d';
    private const REFRESH = 86400;

    public function __construct(private readonly \rcube_cache $cache)
    {
    }

    public function get(string $key): ?string
    {
        $v = $this->cache->get($key);
        if (!is_array($v) || !is_string($v['n'] ?? null) || preg_match('/^[0-9A-F]{1,128}$/D', $v['n']) !== 1) {
            return null;
        }
        if (!is_int($v['t'] ?? null) || time() - $v['t'] > self::REFRESH) {
            $this->put($key, $v['n']);
        }
        return $v['n'];
    }

    public function put(string $key, string $number): void
    {
        $this->cache->set($key, ['n' => $number, 't' => time()]);
        // the non-indexed cache writes on close() only; write now so a later fatal error or another
        // server does not miss the new high-water mark
        $this->cache->close();
    }
}
