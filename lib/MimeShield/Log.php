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
 * Central, redacting logger.
 *
 * Writes to the Roundcube log "mimeshield" (rcube::write_log). Every message and context value is
 * sanitised: control characters (CR/LF - log injection) are replaced, PEM blocks and long base64 runs
 * are redacted, values are truncated. Callers must still never pass secrets on purpose; the redaction
 * is a safety net, not a licence.
 */
final class Log
{
    private const MAX_VALUE = 300;

    /** @var null|callable(string): void */
    private static $sink;

    private static bool $debug = false;

    /**
     * Replace the output sink (tests).
     *
     * @param null|callable(string): void $sink
     */
    public static function setSink(?callable $sink): void
    {
        self::$sink = $sink;
    }

    public static function setDebug(bool $debug): void
    {
        self::$debug = $debug;
    }

    /**
     * @param array<string, mixed> $context
     */
    public static function error(string $operation, string $message, array $context = []): void
    {
        self::write('ERROR', $operation, $message, $context);
    }

    /**
     * Unexpected exception messages may contain user data or infrastructure details. Keep the
     * exception type in normal logs; emit the sanitised message only with explicit debug logging.
     *
     * @param array<string, mixed> $context Fixed operational context, never exception-derived data
     */
    public static function exception(string $operation, \Throwable $exception, array $context = []): void
    {
        self::error($operation, 'unexpected error', ['exception' => get_class($exception)] + $context);
        self::debug($operation, $exception->getMessage(), ['exception' => get_class($exception)] + $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public static function warning(string $operation, string $message, array $context = []): void
    {
        self::write('WARN', $operation, $message, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public static function info(string $operation, string $message, array $context = []): void
    {
        self::write('INFO', $operation, $message, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public static function debug(string $operation, string $message, array $context = []): void
    {
        if (self::$debug) {
            self::write('DEBUG', $operation, $message, $context);
        }
    }

    /**
     * Sanitise a single value for the log.
     */
    public static function sanitize(mixed $value): string
    {
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if ($value === null) {
            return 'null';
        }
        if (is_array($value)) {
            $parts = [];
            foreach ($value as $k => $v) {
                $parts[] = (is_int($k) ? '' : self::sanitize((string) $k) . '=') . self::sanitize(is_scalar($v) || $v === null ? $v : get_debug_type($v));
                if (count($parts) >= 20) {
                    $parts[] = '...';
                    break;
                }
            }
            return '[' . implode(', ', $parts) . ']';
        }
        if (!is_scalar($value)) {
            return get_debug_type($value);
        }

        $s = (string) $value;
        // PEM blocks (keys, certificates, CMS) - never log
        $s = (string) preg_replace('/-----BEGIN [A-Z0-9 ]+-----.*?(-----END [A-Z0-9 ]+-----|$)/s', '[PEM-REDACTED]', $s);
        // line-wrapped base64 (MIME/PEM bodies without armour) and long base64/hex-like runs
        $s = (string) preg_replace('/(?:[A-Za-z0-9+\/=]{40,}[ \t]*\r?\n[ \t]*){1,}[A-Za-z0-9+\/=]*/', '[BLOB-REDACTED]', $s);
        $s = (string) preg_replace('/[A-Za-z0-9+\/=]{120,}/', '[BLOB-REDACTED]', $s);
        // invalid UTF-8 / binary
        if (!preg_match('//u', $s)) {
            $s = '[BINARY-REDACTED]';
        }
        // control characters (CR/LF/TAB/ESC ...) -> log injection protection
        $s = (string) preg_replace('/[\x00-\x1F\x7F]|\x{0085}|[\x{2028}\x{2029}\x{200E}\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}]/u', ' ', $s);

        if (mb_strlen($s) > self::MAX_VALUE) {
            $s = mb_substr($s, 0, self::MAX_VALUE) . '...';
        }

        return $s;
    }

    /**
     * @param array<string, mixed> $context
     */
    private static function write(string $level, string $operation, string $message, array $context): void
    {
        $line = sprintf('%s %s: %s', $level, self::sanitize($operation), self::sanitize($message));

        if (!array_key_exists('user', $context) && class_exists('rcube', false)) {
            $rc = \rcube::get_instance();
            if (!empty($rc->user) && !empty($rc->user->ID)) {
                $context = ['user' => (int) $rc->user->ID] + $context;
            }
        }

        foreach ($context as $key => $value) {
            $line .= ' ' . self::sanitize((string) $key) . '=' . self::sanitize($value);
        }

        if (self::$sink !== null) {
            (self::$sink)($line);
            return;
        }

        if (class_exists('rcube', false)) {
            \rcube::write_log('mimeshield', $line);
        } else {
            error_log('mimeshield: ' . $line);
        }
    }
}
