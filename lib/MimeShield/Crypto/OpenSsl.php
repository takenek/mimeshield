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

namespace MimeShield\Crypto;

use MimeShield\Exception\CryptoException;
use MimeShield\Log;

/**
 * Central wrapper for PHP OpenSSL calls.
 *
 * OpenSSL keeps a per-thread error queue that PHP exposes through openssl_error_string(). Errors are
 * NOT cleared by successful calls, so stale entries from earlier operations would be attributed to
 * the next call. Every call made through this class drains the queue before and after the call and
 * converts PHP warnings into collected strings (instead of output / Roundcube error log noise).
 */
final class OpenSsl
{
    /** Raw OpenSSL CMS flag CMS_NOSMIMECAP (0x200). PHP does not define a constant for it. */
    public const CMS_NOSMIMECAP = 0x200;

    /**
     * Drain the OpenSSL error queue.
     *
     * @return list<string>
     */
    public static function drainErrors(): array
    {
        $errors = [];
        $guard = 0;
        while (($msg = openssl_error_string()) !== false && $guard++ < 64) {
            $errors[] = $msg;
        }
        return $errors;
    }

    /**
     * Call an openssl_* function, capturing the OpenSSL error queue and PHP warnings.
     *
     * Arguments are passed by reference when the function expects references (e.g. output params).
     *
     * @param callable $fn
     * @param array<int, mixed> $args
     *
     * @return array{0: mixed, 1: list<string>}
     */
    public static function call(callable $fn, array &$args = []): array
    {
        self::drainErrors();
        $warnings = [];
        set_error_handler(static function (int $errno, string $errstr) use (&$warnings): bool {
            $warnings[] = $errstr;
            return true;
        });
        try {
            $result = $fn(...$args);
        } finally {
            restore_error_handler();
        }
        $errors = array_merge(self::drainErrors(), $warnings);

        return [$result, $errors];
    }

    /**
     * Run a callable (closure doing openssl work), capturing warnings and errors.
     *
     * @template T
     *
     * @param callable(): T $fn
     *
     * @return array{0: T, 1: list<string>}
     */
    public static function run(callable $fn): array
    {
        $args = [];
        return self::call($fn, $args);
    }

    /**
     * Log OpenSSL errors (redacted) and throw a user-safe exception.
     *
     * @param list<string>         $errors
     * @param array<string, mixed> $context
     */
    public static function fail(string $operation, string $userLabel, array $errors, array $context = []): never
    {
        Log::error($operation, 'OpenSSL operation failed', $context + ['openssl' => self::summarize($errors)]);
        throw new CryptoException($userLabel, $operation . ' failed: ' . self::summarize($errors));
    }

    /**
     * Compact, single-line representation of OpenSSL errors for logs.
     *
     * @param list<string> $errors
     */
    public static function summarize(array $errors): string
    {
        $out = [];
        foreach (array_slice($errors, 0, 8) as $e) {
            // strip absolute paths from PHP warnings (e.g. temp file names)
            $out[] = (string) preg_replace('~/[^\s:!]+~', '<path>', $e);
        }
        return implode(' | ', $out);
    }

    /**
     * Is any of the errors matching the given substring?
     *
     * @param list<string> $errors
     */
    public static function hasError(array $errors, string $needle): bool
    {
        foreach ($errors as $e) {
            if (stripos($e, $needle) !== false) {
                return true;
            }
        }
        return false;
    }
}
