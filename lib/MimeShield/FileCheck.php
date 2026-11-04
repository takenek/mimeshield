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

namespace MimeShield;

/**
 * Ownership and permission check of the administrator files the plugin trusts: the master key file
 * and the CA bundle / intermediate files (audit V-10).
 *
 * Trust anchors decide which signatures are trusted and to whom mail may be encrypted; the master
 * key protects every stored private key. A file that other local users may write is therefore not
 * acceptable (world-writable trust files are ignored, group-writable ones reported). Ownership by a
 * user other than root or the PHP process user is reported once per process and in diag, but not
 * refused: the owner can read the file anyway, and legitimate layouts hand such files to a
 * management account. The directories above the file are checked with the rule of keygen (owner
 * root or the PHP user, not writable by group/others unless the sticky bit is set): a replaceable
 * directory entry is as good as a writable file.
 */
final class FileCheck
{
    /** @var array<string, true> paths already reported in this process */
    private static array $warned = [];

    /**
     * @return array{0: bool, 1: string} [acceptable, description without secrets]
     */
    public static function status(string $path): array
    {
        clearstatcache(true, $path);
        $real = realpath($path);
        if ($real === false || !is_file($real)) {
            return [false, 'not a readable file'];
        }
        $stat = @stat($real);
        if ($stat === false) {
            return [false, 'cannot be inspected (stat failed)'];
        }
        $mode = $stat['mode'] & 0o777;
        $owner = (int) $stat['uid'];
        $self = function_exists('posix_geteuid') ? posix_geteuid() : null;
        $desc = sprintf('mode 0%o, owner uid %d', $mode, $owner);
        if (($mode & 0o002) !== 0) {
            return [false, $desc . ' - WORLD-WRITABLE: any local user can replace its content'];
        }
        if (($mode & 0o020) !== 0) {
            return [false, $desc . ' - group-writable: every member of the group can replace its content'];
        }
        if ($owner !== 0 && $self !== null && $owner !== $self) {
            return [false, $desc . ' - owned by a user other than root or the PHP process user (uid ' . $self . ')'];
        }
        $parent = self::replaceableParent($real, $self);
        if ($parent !== null) {
            return [false, $desc . ' - ' . $parent];
        }
        return [true, $desc];
    }

    /**
     * The first directory above $real whose entry another user could replace (or null): writable by
     * group/others without the sticky bit, or owned by neither root nor the PHP process user.
     */
    private static function replaceableParent(string $real, ?int $self): ?string
    {
        $dir = dirname($real);
        for ($i = 0; $i < 64; $i++) {
            $stat = @stat($dir);
            if ($stat === false) {
                return null;
            }
            $mode = $stat['mode'] & 0o7777;
            $owner = (int) $stat['uid'];
            if (($mode & 0o022) !== 0 && ($mode & 0o1000) === 0) {
                return sprintf('parent directory %s is writable by group/others (mode 0%o) without the sticky bit: the file can be replaced', $dir, $mode & 0o777);
            }
            if ($owner !== 0 && $self !== null && $owner !== $self) {
                return sprintf('parent directory %s is owned by uid %d (neither root nor the PHP process user)', $dir, $owner);
            }
            $up = dirname($dir);
            if ($up === $dir) {
                return null;
            }
            $dir = $up;
        }
        return null;
    }

    public static function isWorldWritable(string $path): bool
    {
        clearstatcache(true, $path);
        $perms = @fileperms($path);
        return $perms !== false && ($perms & 0o002) !== 0;
    }

    /**
     * Log an unexpected ownership or permission once per process (the path is not a secret).
     */
    public static function warnOnce(string $operation, string $what, string $path): void
    {
        if (isset(self::$warned[$path])) {
            return;
        }
        [$ok, $text] = self::status($path);
        if (!$ok) {
            self::$warned[$path] = true;
            Log::warning($operation, $what . ' has unexpected ownership or permissions: ' . $text, ['file' => $path]);
        }
    }
}
