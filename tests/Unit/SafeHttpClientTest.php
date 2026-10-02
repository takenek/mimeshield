<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Exception\ValidationException;
use MimeShield\Tests\TestPki;
use MimeShield\Trust\SafeHttpClient;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * SSRF hardening of the CRL HTTP client.
 *
 * Network tests talk ONLY to a local "php -S 127.0.0.1:<random port>" server. That server is used
 * (a) as a target that must never be contacted (non-public address) and (b) as an explicitly
 * configured forward proxy, which lets the real curl code path (status handling, redirects, size
 * limit, headers) run end to end without internet access.
 */
final class SafeHttpClientTest extends TestCase
{
    /** @var resource|null */
    private static $server = null;

    private static int $port = 0;

    private static string $docroot = '';

    protected function setUp(): void
    {
        $GLOBALS['mimeshield_test_log'] = [];
        if (self::$docroot !== '' && is_file(self::$docroot . '/requests.log')) {
            unlink(self::$docroot . '/requests.log');
        }
    }

    public static function tearDownAfterClass(): void
    {
        if (is_resource(self::$server)) {
            proc_terminate(self::$server);
            proc_close(self::$server);
        }
        self::$server = null;
        if (self::$docroot !== '') {
            self::rmTree(self::$docroot);
            self::$docroot = '';
        }
    }

    // ------------------------------------------------------------------ isPublicIp

    /**
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function ipCases(): iterable
    {
        // IPv4 non-public
        yield 'v4 loopback' => ['127.0.0.1', false];
        yield 'v4 loopback high' => ['127.255.255.254', false];
        yield 'v4 this-network 0.0.0.0' => ['0.0.0.0', false];
        yield 'v4 this-network 0.1.2.3' => ['0.1.2.3', false];
        yield 'rfc1918 10/8 low' => ['10.0.0.1', false];
        yield 'rfc1918 10/8 high' => ['10.255.255.255', false];
        yield 'rfc1918 172.16/12 low' => ['172.16.0.1', false];
        yield 'rfc1918 172.16/12 high' => ['172.31.255.255', false];
        yield 'rfc1918 192.168/16' => ['192.168.1.1', false];
        yield 'cgnat low' => ['100.64.0.1', false];
        yield 'cgnat high' => ['100.127.255.255', false];
        yield 'link-local cloud metadata' => ['169.254.169.254', false];
        yield 'link-local low' => ['169.254.0.1', false];
        yield 'ietf protocol assignments' => ['192.0.0.8', false];
        yield 'doc TEST-NET-1' => ['192.0.2.1', false];
        yield 'doc TEST-NET-2' => ['198.51.100.7', false];
        yield 'doc TEST-NET-3' => ['203.0.113.9', false];
        yield '6to4 relay anycast' => ['192.88.99.1', false];
        yield 'benchmarking low' => ['198.18.0.1', false];
        yield 'benchmarking high' => ['198.19.255.255', false];
        yield 'multicast low' => ['224.0.0.1', false];
        yield 'multicast ssdp' => ['239.255.255.250', false];
        yield 'reserved 240/4' => ['240.0.0.1', false];
        yield 'limited broadcast' => ['255.255.255.255', false];
        // IPv6 non-public
        yield 'v6 unspecified' => ['::', false];
        yield 'v6 loopback' => ['::1', false];
        yield 'v6 loopback long form' => ['0:0:0:0:0:0:0:1', false];
        yield 'v6 link-local' => ['fe80::1', false];
        yield 'v6 link-local top' => ['febf:ffff::1', false];
        yield 'v6 site-local' => ['fec0::1', false];
        yield 'v6 ULA fc00' => ['fc00::1', false];
        yield 'v6 ULA AWS metadata' => ['fd00:ec2::254', false];
        yield 'v6 multicast' => ['ff02::1', false];
        yield 'v4-mapped loopback' => ['::ffff:127.0.0.1', false];
        yield 'v4-mapped rfc1918' => ['::ffff:10.0.0.1', false];
        yield 'v4-mapped metadata hex' => ['::ffff:a9fe:a9fe', false];
        yield 'v4-mapped public (all mapped rejected)' => ['::ffff:8.8.8.8', false];
        yield 'nat64 loopback' => ['64:ff9b::7f00:1', false];
        yield 'nat64 metadata' => ['64:ff9b::169.254.169.254', false];
        yield 'nat64 local-use' => ['64:ff9b:1::a00:1', false];
        yield '6to4 loopback' => ['2002:7f00:1::', false];
        yield '6to4 rfc1918' => ['2002:a00:1::1', false];
        yield 'teredo' => ['2001::1', false];
        yield 'teredo full' => ['2001:0:4136:e378:8000:63bf:3fff:fdd2', false];
        yield 'v6 documentation' => ['2001:db8::1', false];
        yield 'v6 discard-only' => ['100::1', false];
        // not an IP literal at all
        yield 'empty' => ['', false];
        yield 'name' => ['localhost', false];
        yield 'short v4 form' => ['127.1', false];
        yield 'decimal v4 form' => ['2130706433', false];
        yield 'hex v4 form' => ['0x7f.0.0.1', false];
        yield 'octal v4 form' => ['0177.0.0.1', false];
        yield 'bracketed v6' => ['[::1]', false];
        yield 'v6 with zone' => ['fe80::1%eth0', false];
        yield 'garbage' => ['not-an-ip', false];
        // public
        yield 'google dns' => ['8.8.8.8', true];
        yield 'cloudflare dns' => ['1.1.1.1', true];
        yield 'below 10/8' => ['9.255.255.255', true];
        yield 'above 10/8' => ['11.0.0.1', true];
        yield 'below cgnat' => ['100.63.255.255', true];
        yield 'above cgnat' => ['100.128.0.0', true];
        yield 'above loopback' => ['128.0.0.1', true];
        yield 'below link-local' => ['169.253.255.255', true];
        yield 'below 172.16/12' => ['172.15.255.255', true];
        yield 'above 172.16/12' => ['172.32.0.0', true];
        yield 'below 192.168/16' => ['192.167.255.255', true];
        yield 'above 192.0.0/24' => ['192.0.1.1', true];
        yield 'last unicast /8' => ['223.255.255.255', true];
        yield 'google dns v6' => ['2001:4860:4860::8888', true];
        yield 'cloudflare dns v6' => ['2606:4700:4700::1111', true];
        yield 'global unicast v6' => ['2a00:1450:4001::1', true];
        yield 'v6 2001:200 (not teredo)' => ['2001:200::1', true];
    }

    #[DataProvider('ipCases')]
    public function testIsPublicIp(string $ip, bool $public): void
    {
        self::assertSame($public, SafeHttpClient::isPublicIp($ip));
    }

    /**
     * Deprecated IPv4-compatible (::a.b.c.d, ::/96) and SIIT IPv4-translated (::ffff:0:a.b.c.d)
     * addresses embed private IPv4 addresses but are classified as public.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function embeddedV4Cases(): iterable
    {
        yield 'ipv4-compatible loopback' => ['::127.0.0.1'];
        yield 'ipv4-compatible metadata' => ['::169.254.169.254'];
        yield 'ipv4-translated loopback' => ['::ffff:0:127.0.0.1'];
    }

    #[DataProvider('embeddedV4Cases')]
    public function testAddressesEmbeddingPrivateIpv4AreNotPublic(string $ip): void
    {
        self::assertFalse(SafeHttpClient::isPublicIp($ip), $ip . ' embeds a non-public IPv4 address');
    }

    // ------------------------------------------------------------------ checkUrl

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function rejectedUrls(): iterable
    {
        yield 'file scheme (no host)' => ['file:///etc/passwd', 'invalid URL'];
        yield 'file scheme with host' => ['file://crl.example.test/etc/passwd', 'scheme not allowed'];
        yield 'ftp scheme' => ['ftp://crl.example.test/int.crl', 'scheme not allowed'];
        yield 'ldap scheme' => ['ldap://ldap.example.test/cn=int?certificateRevocationList', 'scheme not allowed'];
        yield 'ldaps scheme' => ['ldaps://ldap.example.test/int', 'scheme not allowed'];
        yield 'gopher scheme' => ['gopher://crl.example.test:70/_x', 'scheme not allowed'];
        yield 'dict scheme' => ['dict://crl.example.test:2628/info', 'scheme not allowed'];
        yield 'php filter scheme' => ['php://filter/resource=/etc/passwd', 'scheme not allowed'];
        yield 'javascript' => ['javascript:alert(1)', 'invalid URL'];
        yield 'no host' => ['http:///int.crl', 'invalid URL'];
        yield 'single slash' => ['http:/crl.example.test/int.crl', 'invalid URL'];
        yield 'scheme relative' => ['//crl.example.test/int.crl', 'invalid URL'];
        yield 'userinfo' => ['http://user@crl.example.test/int.crl', 'credentials in URL not allowed'];
        yield 'userinfo with password' => ['http://user:pw@crl.example.test/int.crl', 'credentials in URL not allowed'];
        yield 'userinfo disguising loopback' => ['http://crl.example.test:80@127.0.0.1/int.crl', 'credentials in URL not allowed'];
        yield 'encoded slash userinfo' => ['http://127.0.0.1%2f@crl.example.test/', 'credentials in URL not allowed'];
        yield 'port 8080' => ['http://crl.example.test:8080/int.crl', 'port not allowed'];
        yield 'port 22' => ['http://crl.example.test:22/', 'port not allowed'];
        yield 'port 6379 redis' => ['http://crl.example.test:6379/', 'port not allowed'];
        yield 'port 0' => ['http://crl.example.test:0/', 'port not allowed'];
        yield 'localhost' => ['http://localhost/int.crl', 'host not allowed'];
        yield 'LOCALHOST upper' => ['http://LOCALHOST/int.crl', 'host not allowed'];
        yield 'sub.localhost' => ['http://crl.localhost/int.crl', 'host not allowed'];
        yield 'mdns .local' => ['http://printer.local/int.crl', 'host not allowed'];
        yield 'gcp metadata .internal' => ['http://metadata.google.internal/computeMetadata/v1/', 'host not allowed'];
        yield 'NUL byte' => ["http://crl.example.test/int.crl\x00.pem", 'invalid URL characters'];
        yield 'space' => ['http://crl.example.test/a b', 'invalid URL characters'];
        yield 'tab' => ["http://crl.example.test/\tx", 'invalid URL characters'];
        yield 'CRLF header injection' => ["http://crl.example.test/x\r\nHost: 127.0.0.1", 'invalid URL characters'];
        yield 'DEL' => ["http://crl.example.test/\x7F", 'invalid URL characters'];
        yield 'raw utf-8' => ['http://crl.example.test/zażółć', 'invalid URL characters'];
        yield 'backslash host confusion' => ['http://crl.example.test\\@127.0.0.1/', 'invalid URL characters'];
        yield 'leading space' => [' http://crl.example.test/', 'invalid URL characters'];
        yield 'overlong' => ['http://crl.example.test/' . str_repeat('a', 2030), 'invalid URL characters'];
    }

    #[DataProvider('rejectedUrls')]
    public function testCheckUrlRejects(string $url, string $message): void
    {
        $client = new SafeHttpClient();
        try {
            $client->checkUrl($url);
            self::fail('accepted ' . json_encode($url));
        } catch (ValidationException $e) {
            self::assertSame($message, $e->getMessage());
            self::assertSame('revocationunavailable', $e->getUserLabel());
        }
    }

    public function testUrlLengthLimitBoundary(): void
    {
        $client = new SafeHttpClient();
        $base = 'http://crl.example.test/';
        $ok = $base . str_repeat('a', 2048 - strlen($base));
        self::assertSame(2048, strlen($ok));
        self::assertSame(['crl.example.test', 80, 'http'], $client->checkUrl($ok));
        $this->expectException(ValidationException::class);
        $client->checkUrl($ok . 'a');
    }

    /**
     * @return iterable<string, array{0: string, 1: array{0: string, 1: int, 2: string}}>
     */
    public static function acceptedUrls(): iterable
    {
        yield 'plain http' => ['http://crl.example.test/int.crl', ['crl.example.test', 80, 'http']];
        yield 'https default port' => ['https://crl.example.test/int.crl', ['crl.example.test', 443, 'https']];
        yield 'case folded scheme and host' => ['HTTPS://CRL.Example.TEST/Int.crl', ['crl.example.test', 443, 'https']];
        yield 'explicit port 80' => ['http://crl.example.test:80/int.crl', ['crl.example.test', 80, 'http']];
        yield 'explicit port 443 over http' => ['http://crl.example.test:443/int.crl', ['crl.example.test', 443, 'http']];
        yield 'empty port' => ['http://crl.example.test:/int.crl', ['crl.example.test', 80, 'http']];
        yield 'query with at sign stays query' => ['http://crl.example.test?@127.0.0.1/', ['crl.example.test', 80, 'http']];
        yield 'fragment with at sign stays fragment' => ['http://crl.example.test#@127.0.0.1/', ['crl.example.test', 80, 'http']];
        yield 'ipv4 literal (checked later)' => ['http://8.8.8.8/int.crl', ['8.8.8.8', 80, 'http']];
        yield 'ipv6 literal brackets stripped' => ['http://[2001:4860:4860::8888]/int.crl', ['2001:4860:4860::8888', 80, 'http']];
    }

    /**
     * @param array{0: string, 1: int, 2: string} $expected
     */
    #[DataProvider('acceptedUrls')]
    public function testCheckUrlAccepts(string $url, array $expected): void
    {
        self::assertSame($expected, (new SafeHttpClient())->checkUrl($url));
    }

    public function testCustomPortAllowList(): void
    {
        $client = new SafeHttpClient(allowedPorts: [8080]);
        self::assertSame(['crl.example.test', 8080, 'http'], $client->checkUrl('http://crl.example.test:8080/x'));
        $this->expectExceptionMessage('port not allowed');
        $client->checkUrl('http://crl.example.test/x');
    }

    /**
     * @return iterable<string, array{0: list<string>, 1: list<string>, 2: string, 3: ?string}>
     */
    public static function hostListCases(): iterable
    {
        $suffix = ['.example.test'];
        yield 'suffix allow: subdomain' => [$suffix, [], 'http://crl.example.test/x', null];
        yield 'suffix allow: deep subdomain' => [$suffix, [], 'http://a.b.example.test/x', null];
        yield 'suffix allow: apex' => [$suffix, [], 'http://example.test/x', null];
        yield 'suffix allow: lookalike prefix' => [$suffix, [], 'http://notexample.test/x', 'host not in allow-list'];
        yield 'suffix allow: appended domain' => [$suffix, [], 'http://crl.example.test.evil.test/x', 'host not in allow-list'];
        yield 'suffix allow: ip literal' => [$suffix, [], 'http://8.8.8.8/x', 'host not in allow-list'];
        yield 'exact allow: match' => [['crl.example.test'], [], 'http://crl.example.test/x', null];
        yield 'exact allow: subdomain refused' => [['crl.example.test'], [], 'http://sub.crl.example.test/x', 'host not in allow-list'];
        yield 'allow list case-insensitive' => [['CRL.Example.Test'], [], 'http://crl.EXAMPLE.test/x', null];
        yield 'empty pattern ignored' => [[''], [], 'http://crl.example.test/x', 'host not in allow-list'];
        yield 'deny exact' => [[], ['crl.evil.test'], 'http://crl.evil.test/x', 'host denied'];
        yield 'deny exact case-insensitive' => [[], ['CRL.EVIL.TEST'], 'http://crl.evil.test/x', 'host denied'];
        yield 'deny suffix subdomain' => [[], ['.evil.test'], 'http://a.evil.test/x', 'host denied'];
        yield 'deny suffix apex' => [[], ['.evil.test'], 'http://evil.test/x', 'host denied'];
        yield 'deny suffix other host ok' => [[], ['.evil.test'], 'http://crl.example.test/x', null];
        yield 'deny wins over allow' => [['.example.test'], ['bad.example.test'], 'http://bad.example.test/x', 'host denied'];
        yield 'deny ip literal' => [[], ['8.8.8.8'], 'http://8.8.8.8/x', 'host denied'];
    }

    /**
     * @param list<string> $allow
     * @param list<string> $deny
     */
    #[DataProvider('hostListCases')]
    public function testHostAllowDenyLists(array $allow, array $deny, string $url, ?string $error): void
    {
        $client = new SafeHttpClient(allowHosts: $allow, denyHosts: $deny);
        if ($error === null) {
            self::assertSame(80, $client->checkUrl($url)[1]);
            return;
        }
        try {
            $client->checkUrl($url);
            self::fail('accepted ' . $url);
        } catch (ValidationException $e) {
            self::assertSame($error, $e->getMessage());
        }
    }

    /**
     * A fully-qualified host name with a trailing dot designates the same host; it must not bypass
     * the deny-list or the localhost/.local/.internal name filter (such names are refused outright,
     * because curl would also resolve them outside the CURLOPT_RESOLVE pin).
     */
    public function testDenyListCannotBeBypassedWithTrailingDot(): void
    {
        $client = new SafeHttpClient(denyHosts: ['crl.evil.test', '.blocked.test']);
        foreach (['http://crl.evil.test./x', 'http://a.blocked.test./x'] as $url) {
            try {
                $r = $client->checkUrl($url);
                self::fail($url . ' passed the deny-list as host ' . $r[0]);
            } catch (ValidationException $e) {
                self::assertContains($e->getMessage(), ['host denied', 'invalid host']);
            }
        }
    }

    public function testLocalNameFilterCannotBeBypassedWithTrailingDot(): void
    {
        $client = new SafeHttpClient();
        foreach (['http://localhost./x', 'http://metadata.google.internal./x', 'http://printer.local./x'] as $url) {
            try {
                $r = $client->checkUrl($url);
                self::fail($url . ' passed the name filter as host ' . $r[0]);
            } catch (ValidationException $e) {
                self::assertContains($e->getMessage(), ['host not allowed', 'invalid host']);
            }
        }
    }

    // ------------------------------------------------------------------ resolveSafe

    public function testResolveSafeReturnsPublicAddressFromResolver(): void
    {
        $asked = [];
        $client = new SafeHttpClient(resolver: static function (string $h) use (&$asked): array {
            $asked[] = $h;
            return ['8.8.8.8', '2001:4860:4860::8888'];
        });
        self::assertSame('8.8.8.8', $client->resolveSafe('crl.example.test'));
        self::assertSame(['crl.example.test'], $asked);
    }

    /**
     * @return iterable<string, array{0: list<string>}>
     */
    public static function rebindingAnswers(): iterable
    {
        yield 'public then loopback' => [['8.8.8.8', '127.0.0.1']];
        yield 'private first' => [['10.0.0.1', '8.8.8.8']];
        yield 'metadata hidden among publics' => [['1.1.1.1', '8.8.8.8', '169.254.169.254']];
        yield 'v6 public plus v6 loopback' => [['2001:4860:4860::8888', '::1']];
        yield 'v4 public plus mapped loopback' => [['8.8.8.8', '::ffff:127.0.0.1']];
        yield 'only cgnat' => [['100.64.1.1']];
        yield 'garbage answer' => [['8.8.8.8', 'not-an-ip']];
    }

    /**
     * @param list<string> $answers
     */
    #[DataProvider('rebindingAnswers')]
    public function testResolveSafeRejectsAnyNonPublicAnswer(array $answers): void
    {
        $client = new SafeHttpClient(resolver: static fn (string $h): array => $answers);
        try {
            $client->resolveSafe('crl.example.test');
            self::fail('accepted ' . implode(',', $answers));
        } catch (ValidationException $e) {
            self::assertSame('non-public address', $e->getMessage());
        }
        self::assertStringContainsString('blocked request to non-public address', implode("\n", $GLOBALS['mimeshield_test_log']));
    }

    public function testResolveSafeRejectsEmptyAnswer(): void
    {
        $client = new SafeHttpClient(resolver: static fn (string $h): array => []);
        $this->expectExceptionMessage('host does not resolve');
        $client->resolveSafe('crl.example.test');
    }

    /**
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function literalHosts(): iterable
    {
        yield 'loopback' => ['127.0.0.1', false];
        yield 'metadata' => ['169.254.169.254', false];
        yield 'rfc1918' => ['192.168.0.1', false];
        yield 'v6 loopback' => ['::1', false];
        yield 'mapped loopback' => ['::ffff:127.0.0.1', false];
        yield 'public v4' => ['8.8.8.8', true];
        yield 'public v6' => ['2001:4860:4860::8888', true];
    }

    #[DataProvider('literalHosts')]
    public function testResolveSafeLiteralIpBypassesResolverButIsChecked(string $host, bool $public): void
    {
        $called = false;
        $client = new SafeHttpClient(resolver: static function (string $h) use (&$called): array {
            $called = true;
            return ['8.8.8.8'];
        });
        if ($public) {
            self::assertSame($host, $client->resolveSafe($host));
        } else {
            try {
                $client->resolveSafe($host);
                self::fail('accepted literal ' . $host);
            } catch (ValidationException $e) {
                self::assertSame('non-public address', $e->getMessage());
            }
        }
        self::assertFalse($called, 'an IP literal must not be sent to the resolver');
    }

    // ------------------------------------------------------------------ get() without network

    public function testGetRejectsBeforeResolvingForBadUrls(): void
    {
        $called = 0;
        $client = new SafeHttpClient(resolver: static function (string $h) use (&$called): array {
            $called++;
            return ['8.8.8.8'];
        });
        foreach (['file:///etc/passwd', 'gopher://crl.example.test/', 'http://crl.example.test:25/', 'http://localhost/'] as $url) {
            try {
                $client->get($url, 1000);
                self::fail('get accepted ' . $url);
            } catch (ValidationException $e) {
                self::assertSame('revocationunavailable', $e->getUserLabel());
            }
        }
        self::assertSame(0, $called);
    }

    // ------------------------------------------------------------------ get() against a local server

    public function testLocalServerIsReachableSanityCheck(): void
    {
        $port = self::server();
        $fp = fsockopen('127.0.0.1', $port, $errno, $errstr, 3);
        self::assertIsResource($fp, $errstr);
        fwrite($fp, "GET /x HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n");
        $resp = stream_get_contents($fp);
        fclose($fp);
        self::assertStringContainsString('hello-crl-body', (string) $resp);
        self::assertCount(1, self::requests());
    }

    public function testGetToLoopbackLiteralIsRefusedBeforeConnecting(): void
    {
        $port = self::server();
        $client = new SafeHttpClient(allowedPorts: [$port]);
        try {
            $client->get('http://127.0.0.1:' . $port . '/x', 1000);
            self::fail('request to 127.0.0.1 was allowed');
        } catch (ValidationException $e) {
            self::assertSame('non-public address', $e->getMessage());
        }
        self::assertSame([], self::requests(), 'the local server must not have been contacted');
    }

    public function testGetWithDefaultPortsRefusesLoopbackPort(): void
    {
        $port = self::server();
        try {
            (new SafeHttpClient())->get('http://127.0.0.1:' . $port . '/x', 1000);
            self::fail('request allowed');
        } catch (ValidationException $e) {
            self::assertSame('port not allowed', $e->getMessage());
        }
        self::assertSame([], self::requests());
    }

    /**
     * @return iterable<string, array{0: list<string>}>
     */
    public static function loopbackResolutions(): iterable
    {
        yield 'A 127.0.0.1' => [['127.0.0.1']];
        yield 'AAAA ::1' => [['::1']];
        yield 'mapped' => [['::ffff:127.0.0.1']];
        yield 'public plus loopback (rebinding)' => [['8.8.8.8', '127.0.0.1']];
    }

    /**
     * @param list<string> $answers
     */
    #[DataProvider('loopbackResolutions')]
    public function testGetToNameResolvingToLoopbackIsRefused(array $answers): void
    {
        $port = self::server();
        $client = new SafeHttpClient(allowedPorts: [$port], resolver: static fn (string $h): array => $answers);
        try {
            $client->get('http://crl.example.test:' . $port . '/x', 1000);
            self::fail('request allowed');
        } catch (ValidationException $e) {
            self::assertSame('non-public address', $e->getMessage());
        }
        self::assertSame([], self::requests());
    }

    public function testGetViaConfiguredProxyReturnsBody(): void
    {
        $client = self::proxyClient();
        self::assertSame('hello-crl-body', $client->get('http://crl.example.test/x', 1000));
        $req = self::requests();
        self::assertCount(1, $req);
        self::assertSame('http://crl.example.test/x', $req[0]['uri']);
        self::assertSame('crl.example.test', $req[0]['host']);
        self::assertSame('MIME-Shield-Roundcube-CRL/1', $req[0]['ua']);
        self::assertStringContainsString('application/pkix-crl', $req[0]['accept']);
    }

    public function testQueryContainingAtSignDoesNotChangeTheTargetHost(): void
    {
        $client = self::proxyClient();
        self::assertSame('hello-crl-body', $client->get('http://crl.example.test/x?@127.0.0.1/', 1000));
        $req = self::requests();
        self::assertCount(1, $req);
        self::assertSame('crl.example.test', $req[0]['host']);
    }

    public function testProxyModeStillRefusesNonPublicTargets(): void
    {
        $client = self::proxyClient(['10.1.2.3']);
        foreach (['http://crl.example.test/x', 'http://169.254.169.254/latest/meta-data/', 'http://[::1]/x'] as $url) {
            try {
                $client->get($url, 1000);
                self::fail('allowed ' . $url);
            } catch (ValidationException $e) {
                self::assertSame('non-public address', $e->getMessage());
            }
        }
        self::assertSame([], self::requests(), 'nothing may reach the proxy');
    }

    public function testRedirectIsNotFollowed(): void
    {
        $client = self::proxyClient();
        try {
            $client->get('http://crl.example.test/redirect', 1000);
            self::fail('redirect response accepted');
        } catch (ValidationException $e) {
            self::assertSame('HTTP status 302', $e->getMessage());
        }
        $uris = array_column(self::requests(), 'uri');
        self::assertSame(['http://crl.example.test/redirect'], $uris, 'the Location target must not be requested');
    }

    public function testNon200StatusIsRejected(): void
    {
        $client = self::proxyClient();
        $this->expectExceptionMessage('HTTP status 404');
        $client->get('http://crl.example.test/notfound', 1000);
    }

    public function testResponseSizeLimitAbortsTransfer(): void
    {
        $client = self::proxyClient();
        try {
            $client->get('http://crl.example.test/big', 100000);
            self::fail('oversized body accepted');
        } catch (ValidationException $e) {
            self::assertSame('response exceeds size limit', $e->getMessage());
        }
        // exactly at the limit is fine
        self::assertSame(300000, strlen($client->get('http://crl.example.test/big', 300000)));
    }

    public function testTimeoutIsEnforced(): void
    {
        $port = self::server();
        $client = new SafeHttpClient(1, 1, [80, 443], [], [], 'http://127.0.0.1:' . $port, static fn (string $h): array => ['8.8.8.8']);
        $t = microtime(true);
        try {
            $client->get('http://crl.example.test/slow', 1000);
            self::fail('slow response accepted');
        } catch (ValidationException $e) {
            self::assertStringStartsWith('transfer failed', $e->getMessage());
        }
        self::assertLessThan(2.5, microtime(true) - $t);
    }

    public function testDirectConnectionPinningToPublicAddressRequiresInternet(): void
    {
        self::markTestSkipped(
            'Pinned-address / redirect checks on a DIRECT connection need curl to connect to the public address returned '
            . 'by the resolver hook (CURLOPT_RESOLVE pins host:port to it); this suite has no internet access, and '
            . 'loopback targets are (correctly) refused before connecting. Redirect handling is covered via the proxy path.'
        );
    }

    // ------------------------------------------------------------------ helpers

    /**
     * @param list<string> $answers
     */
    private static function proxyClient(array $answers = ['8.8.8.8']): SafeHttpClient
    {
        $port = self::server();
        return new SafeHttpClient(5, 3, [80, 443], [], [], 'http://127.0.0.1:' . $port, static fn (string $h): array => $answers);
    }

    /**
     * @return list<array{uri: string, host: string, ua: string, accept: string}>
     */
    private static function requests(): array
    {
        $f = self::$docroot . '/requests.log';
        if (self::$docroot === '' || !is_file($f)) {
            return [];
        }
        $out = [];
        foreach (file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            $out[] = json_decode($line, true, 4, JSON_THROW_ON_ERROR);
        }
        return $out;
    }

    private static function server(): int
    {
        if (is_resource(self::$server)) {
            return self::$port;
        }
        self::$docroot = TestPki::tempDir();
        $router = <<<'PHP'
<?php
file_put_contents(__DIR__ . '/requests.log', json_encode([
    'uri' => $_SERVER['REQUEST_URI'],
    'host' => $_SERVER['HTTP_HOST'] ?? '',
    'ua' => $_SERVER['HTTP_USER_AGENT'] ?? '',
    'accept' => $_SERVER['HTTP_ACCEPT'] ?? '',
]) . "\n", FILE_APPEND | LOCK_EX);
$path = (string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
switch ($path) {
    case '/x':
        header('Content-Type: application/pkix-crl');
        echo 'hello-crl-body';
        break;
    case '/redirect':
        header('Location: http://crl.example.test/after-redirect', true, 302);
        echo 'moved';
        break;
    case '/big':
        echo str_repeat('A', 300000);
        break;
    case '/slow':
        sleep(2);
        echo 'late';
        break;
    default:
        http_response_code(404);
        echo 'not found';
}
PHP;
        file_put_contents(self::$docroot . '/router.php', $router);

        $sock = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertIsResource($sock, $errstr);
        $name = (string) stream_socket_get_name($sock, false);
        fclose($sock);
        self::$port = (int) substr($name, strrpos($name, ':') + 1);

        $proc = proc_open(
            [PHP_BINARY, '-n', '-S', '127.0.0.1:' . self::$port, '-t', self::$docroot, self::$docroot . '/router.php'],
            [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes,
        );
        self::assertIsResource($proc);
        self::$server = $proc;
        $deadline = microtime(true) + 10;
        while (microtime(true) < $deadline) {
            $fp = @fsockopen('127.0.0.1', self::$port, $errno, $errstr, 0.2);
            if (is_resource($fp)) {
                fclose($fp);
                return self::$port;
            }
            usleep(50000);
        }
        self::fail('local test server did not start');
    }

    private static function rmTree(string $dir): void
    {
        foreach (scandir($dir) ?: [] as $f) {
            if ($f === '.' || $f === '..') {
                continue;
            }
            $p = $dir . '/' . $f;
            is_dir($p) && !is_link($p) ? self::rmTree($p) : unlink($p);
        }
        rmdir($dir);
    }
}
