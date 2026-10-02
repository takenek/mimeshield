<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Trust;

/**
 * E-mail address normalisation and comparison.
 *
 * - addresses are compared after normalisation: trimmed, domain converted to ASCII (IDNA) and
 *   lowercased; the local part is compared case-insensitively. RFC 5280 7.5 allows case-sensitive
 *   local parts, but practically every mail system treats them case-insensitively and every major
 *   S/MIME client compares this way; a CA validated the mailbox, not its case.
 * - only plain ASCII "local@domain" addresses are accepted (no display names, comments, quoted local
 *   parts, IP literals or whitespace). Internationalised local parts (SmtpUTF8Mailbox, RFC 8398) are
 *   not supported and never match.
 */
final class AddressMatcher
{
    /**
     * Normalise an address, or null when it is not an acceptable plain mailbox address.
     */
    public static function normalize(string $address): ?string
    {
        $address = trim($address);
        if ($address === '' || strlen($address) > 254) {
            return null;
        }
        $at = strrpos($address, '@');
        if ($at === false || $at === 0 || $at === strlen($address) - 1) {
            return null;
        }
        $local = substr($address, 0, $at);
        $domain = substr($address, $at + 1);

        if (strlen($local) > 64 || !preg_match('/^[A-Za-z0-9!#$%&\'*+\/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&\'*+\/=?^_`{|}~-]+)*$/D', $local)) {
            return null;
        }

        if (preg_match('/[^\x20-\x7E]/', $domain)) {
            $ascii = self::idnToAscii($domain);
            if ($ascii === null) {
                return null;
            }
            $domain = $ascii;
        }
        $domain = strtolower(rtrim($domain, '.'));
        if (!preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/D', $domain)) {
            return null;
        }

        return strtolower($local) . '@' . $domain;
    }

    /**
     * Compare two addresses after normalisation.
     */
    public static function equals(string $a, string $b): bool
    {
        $na = self::normalize($a);
        $nb = self::normalize($b);
        return $na !== null && $na === $nb;
    }

    /**
     * Is $address one of $certEmails (already normalised list)?
     *
     * @param list<string> $certEmails
     */
    public static function matchesAny(string $address, array $certEmails): bool
    {
        $n = self::normalize($address);
        return $n !== null && in_array($n, $certEmails, true);
    }

    /**
     * Extract bare addresses from an RFC 5322 address-list header value.
     *
     * @param bool $decode Whether the value is still RFC 2047 encoded
     *
     * @return list<string> normalised addresses (invalid entries dropped)
     */
    public static function parseList(string $header, bool $decode = false): array
    {
        $out = [];
        if (class_exists('rcube_mime')) {
            $list = \rcube_mime::decode_address_list($header, null, $decode, null, true);
            foreach ((array) $list as $addr) {
                if (is_string($addr) && ($n = self::normalize($addr)) !== null) {
                    $out[] = $n;
                }
            }
        } else {
            // fallback used in unit tests without Roundcube: take <...> or bare tokens with @
            if (preg_match_all('/<([^<>\s]+@[^<>\s]+)>|([^\s,<>;:"]+@[^\s,<>;:"]+)/', $header, $m, PREG_SET_ORDER | PREG_UNMATCHED_AS_NULL)) {
                foreach ($m as $hit) {
                    $addr = $hit[1] ?? $hit[2] ?? '';
                    if (($n = self::normalize($addr)) !== null) {
                        $out[] = $n;
                    }
                }
            }
        }
        return array_values(array_unique($out));
    }

    /**
     * Like parseList(), but also reports address-list entries that are not acceptable mailboxes
     * (so callers can fail closed instead of silently ignoring them).
     *
     * @return array{valid: list<string>, invalid: list<string>}
     */
    public static function parseListStrict(string $header, bool $decode = false, ?string $charset = null): array
    {
        $valid = [];
        $invalid = [];
        if (class_exists('rcube_mime')) {
            foreach ((array) \rcube_mime::decode_address_list($header, null, $decode, $charset, false) as $entry) {
                $addr = is_array($entry) ? (string) ($entry['mailto'] ?? '') : (string) $entry;
                if ($addr === '' && is_array($entry) && isset($entry['string']) && str_contains((string) $entry['string'], ':;')) {
                    continue; // empty group such as "undisclosed-recipients:;"
                }
                $n = self::normalize($addr);
                if ($n === null) {
                    $invalid[] = $addr !== '' ? $addr : (is_array($entry) ? (string) ($entry['string'] ?? '') : '');
                } else {
                    $valid[] = $n;
                }
            }
        } else {
            $valid = self::parseList($header, $decode);
        }
        return ['valid' => array_values(array_unique($valid)), 'invalid' => array_values(array_unique($invalid))];
    }

    private static function idnToAscii(string $domain): ?string
    {
        if (class_exists('rcube_utils')) {
            $r = \rcube_utils::idn_to_ascii($domain);
            return is_string($r) && $r !== '' && !preg_match('/[^\x20-\x7E]/', $r) ? $r : null;
        }
        if (function_exists('idn_to_ascii')) {
            $r = idn_to_ascii($domain, IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);
            return is_string($r) ? $r : null;
        }
        return null;
    }
}
