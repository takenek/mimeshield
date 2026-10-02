<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Trust;

use MimeShield\Exception\ValidationException;
use MimeShield\Log;

/**
 * Minimal HTTP GET client hardened against SSRF, used only for CRL retrieval.
 *
 * - schemes http/https only, no userinfo, ports limited to an allow-list (default 80, 443);
 * - the host name is resolved ONCE; every resolved address must be a public unicast address
 *   (loopback, RFC 1918, CGNAT, link-local incl. cloud metadata 169.254.169.254, ULA, multicast,
 *   documentation, 6to4/Teredo/NAT64 and IPv4-mapped forms of private addresses are rejected);
 * - the connection is pinned to the checked address (CURLOPT_RESOLVE) and the connected address is
 *   verified afterwards, which defeats DNS rebinding;
 * - no redirects, strict connect/total timeouts, hard response size limit (aborts the transfer);
 * - optional host allow-list / deny-list.
 */
final class SafeHttpClient
{
    private const BLOCKED_V4 = [
        '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
        '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15',
        '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
    ];

    private const BLOCKED_V6 = [
        '::/128', '::1/128', '::ffff:0:0/96', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64',
        '2001::/32', '2001:db8::/32', '2002::/16', 'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8',
    ];

    /**
     * @param list<int>    $allowedPorts
     * @param list<string> $allowHosts   If non-empty, only these hosts (exact or ".suffix") are allowed
     * @param list<string> $denyHosts    Hosts (exact or ".suffix") always rejected
     * @param null|callable(string): list<string> $resolver Test hook for DNS resolution
     */
    public function __construct(
        private readonly int $timeout = 5,
        private readonly int $connectTimeout = 3,
        private readonly array $allowedPorts = [80, 443],
        private readonly array $allowHosts = [],
        private readonly array $denyHosts = [],
        private readonly string $proxy = '',
        private $resolver = null,
    ) {
    }

    /**
     * Fetch $url and return the body (at most $maxBytes).
     */
    public function get(string $url, int $maxBytes): string
    {
        if (!function_exists('curl_init')) {
            throw new ValidationException('revocationunavailable', 'ext-curl not available');
        }
        [$host, $port, $scheme] = $this->checkUrl($url);
        $ip = $this->resolveSafe($host);

        $body = '';
        $tooLarge = false;
        $ch = curl_init();
        if ($ch === false) {
            throw new ValidationException('revocationunavailable', 'curl_init failed');
        }
        $opts = [
            CURLOPT_URL => $url,
            CURLOPT_HTTPGET => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => $this->connectTimeout,
            CURLOPT_NOSIGNAL => true,
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_HEADER => false,
            CURLOPT_USERAGENT => 'MIME-Shield-Roundcube-CRL/1',
            CURLOPT_HTTPHEADER => ['Accept: application/pkix-crl, application/octet-stream'],
            CURLOPT_WRITEFUNCTION => static function ($ch, string $chunk) use (&$body, &$tooLarge, $maxBytes): int {
                if (strlen($body) + strlen($chunk) > $maxBytes) {
                    $tooLarge = true;
                    return 0; // abort transfer
                }
                $body .= $chunk;
                return strlen($chunk);
            },
        ];
        if (defined('CURLOPT_PROTOCOLS_STR')) {
            $opts[CURLOPT_PROTOCOLS_STR] = 'http,https';
            $opts[CURLOPT_REDIR_PROTOCOLS_STR] = 'http,https';
        } else {
            $opts[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
            $opts[CURLOPT_REDIR_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
        }
        if ($this->proxy !== '') {
            $opts[CURLOPT_PROXY] = $this->proxy;
        } else {
            $opts[CURLOPT_PROXY] = '';
            $opts[CURLOPT_NOPROXY] = '*';
            $opts[CURLOPT_RESOLVE] = [sprintf('%s:%d:%s', $host, $port, str_contains($ip, ':') ? '[' . $ip . ']' : $ip)];
        }
        if ($scheme === 'https') {
            $opts[CURLOPT_SSL_VERIFYPEER] = true;
            $opts[CURLOPT_SSL_VERIFYHOST] = 2;
        }
        curl_setopt_array($ch, $opts);
        $ok = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $primary = (string) curl_getinfo($ch, CURLINFO_PRIMARY_IP);
        $err = curl_error($ch);
        if (PHP_VERSION_ID < 80000) {
            curl_close($ch);
        }
        unset($ch);

        if ($tooLarge) {
            throw new ValidationException('revocationunavailable', 'response exceeds size limit');
        }
        if ($ok !== true) {
            throw new ValidationException('revocationunavailable', 'transfer failed: ' . $err);
        }
        if ($this->proxy === '' && $primary !== '' && inet_pton($primary) !== inet_pton($ip)) {
            Log::warning('ssrf', 'connected address differs from the checked address', ['host' => $host]);
            throw new ValidationException('revocationunavailable', 'address mismatch');
        }
        if ($code !== 200) {
            throw new ValidationException('revocationunavailable', 'HTTP status ' . $code);
        }
        return $body;
    }

    /**
     * Validate URL syntax, scheme, port and host policy.
     *
     * @return array{0: string, 1: int, 2: string}
     */
    public function checkUrl(string $url): array
    {
        if (strlen($url) > 2048 || preg_match('/[\x00-\x20\x7F-\xFF\\\\]/', $url)) {
            throw new ValidationException('revocationunavailable', 'invalid URL characters');
        }
        $p = parse_url($url);
        if (!is_array($p) || empty($p['scheme']) || empty($p['host'])) {
            throw new ValidationException('revocationunavailable', 'invalid URL');
        }
        $scheme = strtolower($p['scheme']);
        if ($scheme !== 'http' && $scheme !== 'https') {
            throw new ValidationException('revocationunavailable', 'scheme not allowed');
        }
        if (isset($p['user']) || isset($p['pass'])) {
            throw new ValidationException('revocationunavailable', 'credentials in URL not allowed');
        }
        $port = (int) ($p['port'] ?? ($scheme === 'https' ? 443 : 80));
        if (!in_array($port, $this->allowedPorts, true)) {
            throw new ValidationException('revocationunavailable', 'port not allowed');
        }
        $host = strtolower(trim($p['host'], '[]'));
        foreach ($this->denyHosts as $d) {
            if (self::hostMatches($host, strtolower($d))) {
                throw new ValidationException('revocationunavailable', 'host denied');
            }
        }
        if ($this->allowHosts !== []) {
            $allowed = false;
            foreach ($this->allowHosts as $a) {
                if (self::hostMatches($host, strtolower($a))) {
                    $allowed = true;
                    break;
                }
            }
            if (!$allowed) {
                throw new ValidationException('revocationunavailable', 'host not in allow-list');
            }
        }
        if ($host === 'localhost' || str_ends_with($host, '.localhost') || str_ends_with($host, '.local') || str_ends_with($host, '.internal')) {
            throw new ValidationException('revocationunavailable', 'host not allowed');
        }
        return [$host, $port, $scheme];
    }

    /**
     * Resolve and check every address; return the first (public) one.
     */
    public function resolveSafe(string $host): string
    {
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $ips = [$host];
        } elseif ($this->resolver !== null) {
            $ips = ($this->resolver)($host);
        } else {
            $ips = [];
            $records = @dns_get_record($host, DNS_A | DNS_AAAA);
            foreach ($records ?: [] as $r) {
                if (isset($r['ip'])) {
                    $ips[] = $r['ip'];
                } elseif (isset($r['ipv6'])) {
                    $ips[] = $r['ipv6'];
                }
            }
        }
        if ($ips === []) {
            throw new ValidationException('revocationunavailable', 'host does not resolve');
        }
        foreach ($ips as $ip) {
            if (!self::isPublicIp($ip)) {
                Log::warning('ssrf', 'blocked request to non-public address', ['host' => $host]);
                throw new ValidationException('revocationunavailable', 'non-public address');
            }
        }
        return $ips[0];
    }

    /**
     * Is $ip a public unicast address?
     */
    public static function isPublicIp(string $ip): bool
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return false;
        }
        if (strlen($bin) === 4) {
            foreach (self::BLOCKED_V4 as $cidr) {
                if (self::inCidr($bin, $cidr)) {
                    return false;
                }
            }
            return $ip !== '255.255.255.255';
        }
        foreach (self::BLOCKED_V6 as $cidr) {
            if (self::inCidr($bin, $cidr)) {
                return false;
            }
        }
        return true;
    }

    private static function inCidr(string $bin, string $cidr): bool
    {
        [$net, $bits] = explode('/', $cidr);
        $netBin = inet_pton($net);
        if ($netBin === false || strlen($netBin) !== strlen($bin)) {
            return false;
        }
        $bits = (int) $bits;
        $bytes = intdiv($bits, 8);
        if ($bytes > 0 && substr($bin, 0, $bytes) !== substr($netBin, 0, $bytes)) {
            return false;
        }
        $rem = $bits % 8;
        if ($rem === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rem)) & 0xFF;
        return (ord($bin[$bytes]) & $mask) === (ord($netBin[$bytes]) & $mask);
    }

    private static function hostMatches(string $host, string $pattern): bool
    {
        if ($pattern === '') {
            return false;
        }
        if ($pattern[0] === '.') {
            return str_ends_with($host, $pattern) || $host === substr($pattern, 1);
        }
        return $host === $pattern;
    }
}
