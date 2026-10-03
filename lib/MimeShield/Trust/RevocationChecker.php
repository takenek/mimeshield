<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Trust;

use MimeShield\Cert\Certificate;
use MimeShield\Crypto\Asn1;
use MimeShield\Crypto\Asn1Node;
use MimeShield\Crypto\OpenSsl;
use MimeShield\Exception\ValidationException;
use MimeShield\Log;

/**
 * CRL based revocation checking (RFC 5280 section 5/6.3), OPT-IN.
 *
 * Policy (RFC 8550 section 6): revocation information is fetched ONLY for certificates whose chain
 * already validated to a configured trust anchor, so attacker-supplied certificates cannot trigger
 * requests (tracking / SSRF / DoS). Only http(s) CRL distribution points are used, through
 * SafeHttpClient. CRLs are cached (file cache) until nextUpdate, bounded by a maximum age.
 *
 * The CRL signature is verified with the issuer's public key (openssl_verify over tbsCertList), the
 * issuer name must match, thisUpdate/nextUpdate must be current, delta and indirect CRLs and unknown
 * critical extensions lead to "unknown" (never to "good").
 *
 * Every certificate of the accepted path below its anchor is checked (RFC 5280 6.3, audit F-04), each
 * against the CRL of its issuer ON THAT PATH (audit F-05). OCSP is not implemented (PHP has no OCSP
 * API); with checking enabled, a certificate without a usable (http/https) CRL DP has an UNKNOWN
 * status - "not checked" is reserved for disabled checking (audit F-06). A CRL that could not be
 * obtained is not requested again for NEGATIVE_TTL seconds, and the number of network fetches per
 * request is bounded (audit F-14).
 *
 * Rollback protection (audit I-02): with a CrlNumberStore, the highest cRLNumber per issuer name, AKI
 * and distribution point is remembered; a validly signed, unexpired but OLDER CRL (replayed over plain
 * http, or a stale cache) yields "unknown" instead of a possibly outdated "good". Within a CRL's
 * validity window this is the only freshness signal RFC 5280 offers; CRLs without cRLNumber are
 * evaluated as before (deliberate: nothing to compare, audit I-02 decision 2026-10-03).
 */
final class RevocationChecker
{
    public const MODE_OFF = 'off';
    public const MODE_CRL = 'crl';

    private const OID_CRL_NUMBER = '2.5.29.20';
    private const OID_DELTA_CRL = '2.5.29.27';
    private const OID_IDP = '2.5.29.28';
    private const OID_AKI = '2.5.29.35';
    private const OID_REASON = '2.5.29.21';
    private const OID_INVALIDITY = '2.5.29.24';
    private const OID_CERT_ISSUER = '2.5.29.29';

    private const SIG_ALGS = [
        '1.2.840.113549.1.1.11' => OPENSSL_ALGO_SHA256,
        '1.2.840.113549.1.1.12' => OPENSSL_ALGO_SHA384,
        '1.2.840.113549.1.1.13' => OPENSSL_ALGO_SHA512,
        '1.2.840.10045.4.3.2' => OPENSSL_ALGO_SHA256,
        '1.2.840.10045.4.3.3' => OPENSSL_ALGO_SHA384,
        '1.2.840.10045.4.3.4' => OPENSSL_ALGO_SHA512,
        '1.2.840.113549.1.1.5' => OPENSSL_ALGO_SHA1,
        '1.2.840.10045.4.1' => OPENSSL_ALGO_SHA1,
    ];

    /** SHA-1 CRL signatures, accepted only with $acceptSha1 (audit I-09) */
    private const SHA1_SIG_ALGS = ['1.2.840.113549.1.1.5', '1.2.840.10045.4.1'];

    private const CLOCK_SKEW = 300;

    /** Seconds a CRL URL that could not be fetched / validated is not requested again */
    public const NEGATIVE_TTL = 300;
    /** Failures this close to the request's transfer deadline may be caused by the shortened timeout (seconds). */
    private const DEADLINE_MARGIN = 0.1;

    /** @var array<string, string> per-request memory cache url => DER */
    private array $memory = [];

    /** @var array<string, int> per-request negative cache (URL or URL + issuer) => failure time */
    private array $failed = [];

    private int $fetches = 0;

    /** Monotonic deadline shared by all network fetches in this request. Cached CRLs remain usable. */
    private ?float $fetchDeadline = null;

    /** @var array<string, string> per-request cRLNumber already compared with the store, key => number */
    private array $numbersSeen = [];

    private bool $storeFailureLogged = false;

    /**
     * $acceptSha1: SHA-1 signed CRLs follow mimeshield_legacy_digests (Services passes whether 'sha1'
     * is listed). Deliberate: a CA that still signs CRLs with SHA-1 is a legacy CA the administrator
     * has chosen to accept for signatures too; rejecting only its CRLs would turn every check into
     * "unknown" without protecting anything (audit I-09 decision 2026-10-03). A rejected CRL is
     * "unknown", never "good", so mimeshield_revocation_unknown decides.
     */
    public function __construct(
        private readonly string $mode,
        private readonly ?SafeHttpClient $http,
        private readonly string $cacheDir,
        private readonly int $maxCrlBytes = 10485760,
        private readonly int $maxCacheAge = 86400,
        private readonly int $maxUrls = 2,
        private readonly int $maxFetchesPerRequest = 8,
        private readonly float $maxFetchSecondsPerRequest = 10.0,
        private readonly bool $acceptSha1 = true,
        private readonly ?CrlNumberStore $crlNumbers = null,
    ) {
    }

    public function isEnabled(): bool
    {
        return $this->mode === self::MODE_CRL && $this->http !== null;
    }

    /**
     * Revocation status of a validated path: every certificate below the anchor is checked against
     * the CRL of its issuer on the same path. REVOKED anywhere wins; otherwise the first status that
     * is not GOOD (UNKNOWN) is returned, so the caller's revocation_unknown policy applies to the
     * intermediates as well. The leaf result is returned when the whole path is GOOD.
     *
     * When the issuer on the path may not sign CRLs, an administrator-controlled certificate of the
     * same CA that may sign them is used instead ($store); never a certificate from a message.
     *
     * @param list<Certificate> $path leaf first, trust anchor last (ChainResult::$certs)
     */
    public function checkPath(array $path, ?TrustStore $store = null, ?int $now = null): RevocationResult
    {
        if (!$this->isEnabled()) {
            return new RevocationResult(RevocationResult::NOT_CHECKED, 'disabled');
        }
        if (count($path) < 2) {
            return new RevocationResult(RevocationResult::UNKNOWN, 'noissuer');
        }
        $leaf = null;
        $first = null;
        for ($i = 0, $n = count($path) - 1; $i < $n; $i++) {
            $cert = $path[$i];
            $issuer = $path[$i + 1];
            if (!$issuer->hasKeyUsage(Certificate::KU_CRL_SIGN) && $store !== null) {
                $issuer = $store->trustedCrlIssuer($cert) ?? $issuer;
            }
            $r = $this->check($cert, $issuer, $now);
            if ($r->status === RevocationResult::REVOKED) {
                return $r;
            }
            $leaf ??= $r;
            if ($r->status !== RevocationResult::GOOD) {
                $first ??= $r;
            }
        }
        return $first ?? $leaf ?? new RevocationResult(RevocationResult::UNKNOWN, 'noissuer');
    }

    /**
     * Check $cert (issued by $issuer). The chain MUST already be validated by the caller.
     */
    public function check(Certificate $cert, ?Certificate $issuer, ?int $now = null): RevocationResult
    {
        if (!$this->isEnabled()) {
            return new RevocationResult(RevocationResult::NOT_CHECKED, 'disabled');
        }
        if ($issuer === null) {
            return new RevocationResult(RevocationResult::UNKNOWN, 'noissuer');
        }
        $now ??= time();

        $urls = array_values(array_filter($cert->crlUrls, static fn (string $u) => preg_match('~^https?://~i', $u) === 1));
        if ($urls === []) {
            // checking is enabled but there is no evidence: undetermined, never "not checked" (F-06)
            return new RevocationResult(RevocationResult::UNKNOWN, 'nocrldp');
        }

        $lastReason = 'unavailable';
        foreach (array_slice($urls, 0, $this->maxUrls) as $url) {
            try {
                $der = $this->obtain($url, $issuer, $now);
                return $this->evaluate($der, $cert, $issuer, $now);
            } catch (ValidationException $e) {
                $lastReason = $e->getUserLabel();
                Log::info('revocation', 'CRL check failed: ' . $e->getMessage(), ['fingerprint' => $cert->fingerprint]);
            } catch (\TypeError | \ValueError $e) {
                // malformed (but validly signed) CRL structures must never break message display
                $lastReason = 'revocationunavailable';
                Log::info('revocation', 'malformed CRL: ' . $e->getMessage(), ['fingerprint' => $cert->fingerprint]);
            }
        }

        return new RevocationResult(RevocationResult::UNKNOWN, $lastReason);
    }

    /**
     * Evaluate a CRL (DER) for $cert. Public for tests. No cRLNumber tracking here: that belongs to the
     * CRLs actually obtained for a distribution point (obtain()).
     */
    public function evaluate(string $crlDer, Certificate $cert, Certificate $issuer, int $now): RevocationResult
    {
        $crl = $this->parse($crlDer, $issuer);

        // RFC 5280 6.3.3 (b)(2): a CRL whose IssuingDistributionPoint names another distribution
        // point is out of scope for this certificate. A fullName with only unsupported name forms
        // (e.g. directoryName) is still a scope restriction, never "no IDP" (audit MS-06).
        if ($crl['idpScoped'] && array_intersect($crl['idpUris'], $cert->crlUrls) === []) {
            throw new ValidationException('revocationunavailable', 'CRL scope (distribution point) mismatch');
        }
        // RFC 5280 6.3.3 (b)(2): a CRL limited to CA certificates covers only CAs (audit F-04), one
        // limited to end-entity certificates never covers a CA
        if ($crl['onlyCa'] && !$cert->isCa) {
            throw new ValidationException('revocationunavailable', 'CA-only CRL');
        }
        if ($crl['onlyUser'] && $cert->isCa) {
            throw new ValidationException('revocationunavailable', 'end-entity-only CRL for a CA certificate');
        }

        if ($crl['thisUpdate'] > $now + self::CLOCK_SKEW) {
            throw new ValidationException('revocationunavailable', 'CRL not yet valid');
        }
        if ($crl['nextUpdate'] === null || $crl['nextUpdate'] < $now - self::CLOCK_SKEW) {
            throw new ValidationException('revocationunavailable', 'CRL expired');
        }

        $serial = $cert->serialHex;
        foreach ($crl['entries'] as $entry) {
            if ($entry['serial'] === $serial) {
                return new RevocationResult(RevocationResult::REVOKED, $entry['reason'], $entry['date']);
            }
        }
        return new RevocationResult(RevocationResult::GOOD, '', null, $crl['nextUpdate']);
    }

    /**
     * Fetch (or load from cache) a CRL for $url. Cached CRLs are re-validated on every use.
     */
    private function obtain(string $url, Certificate $issuer, int $now): string
    {
        if (isset($this->memory[$url])) {
            return $this->memory[$url];
        }
        $cacheFile = $this->cacheFile($url);
        if ($cacheFile !== null && is_file($cacheFile) && !is_link($cacheFile)) {
            $age = $now - (int) @filemtime($cacheFile);
            if ($age >= 0 && $age < $this->maxCacheAge) {
                $der = (string) @file_get_contents($cacheFile, false, null, 0, $this->maxCrlBytes + 1);
                try {
                    $crl = $this->parse($der, $issuer);
                    if ($crl['nextUpdate'] !== null && $crl['nextUpdate'] >= $now) {
                        // an older CRL than already seen elsewhere (another server) is refetched (I-02)
                        $this->checkNumber($crl, $issuer, $url);
                        return $this->memory[$url] = $der;
                    }
                } catch (ValidationException) {
                    // fall through: refetch
                }
            }
        }

        // Transport failures apply to the URL; validation failures apply only to this issuer. A
        // CRL unavailable for one CA must not suppress a valid CRL check for another CA (F-14).
        $failFile = $cacheFile !== null ? substr($cacheFile, 0, -4) . '.fail' : null;
        $issuerKey = $url . "\0" . $issuer->fingerprint;
        $issuerFailFile = $cacheFile !== null ? dirname($cacheFile) . '/' . hash('sha256', $issuerKey) . '.fail' : null;
        foreach ([$url => $failFile, $issuerKey => $issuerFailFile] as $key => $file) {
            $failedAt = $this->failed[$key] ?? ($file !== null && is_file($file) && !is_link($file) ? (int) @filemtime($file) : null);
            if ($failedAt !== null && $failedAt <= $now && $now - $failedAt < self::NEGATIVE_TTL) {
                $this->failed[$key] = $failedAt;
                throw new ValidationException('revocationunavailable', 'CRL recently unavailable');
            }
        }
        $this->fetchDeadline ??= hrtime(true) / 1e9 + $this->maxFetchSecondsPerRequest;
        if (hrtime(true) / 1e9 >= $this->fetchDeadline) {
            throw new ValidationException('revocationunavailable', 'CRL time budget of this request exhausted');
        }
        if (++$this->fetches > $this->maxFetchesPerRequest) {
            throw new ValidationException('revocationunavailable', 'CRL fetch budget of this request exhausted');
        }
        if ($this->http === null) {
            throw new ValidationException('revocationunavailable', 'no HTTP client');
        }

        try {
            $der = $this->http->get($url, $this->maxCrlBytes, $this->fetchDeadline);
            if (str_starts_with(ltrim($der), '-----BEGIN X509 CRL-----')) {
                if (!preg_match('/-----BEGIN X509 CRL-----([A-Za-z0-9+\/=\s]+)-----END X509 CRL-----/', $der, $m)) {
                    throw new ValidationException('revocationunavailable', 'bad PEM CRL');
                }
                $der = (string) base64_decode(preg_replace('/\s+/', '', $m[1]) ?? '', true);
            }
        } catch (ValidationException | \TypeError | \ValueError $e) {
            // An exhausted request budget says nothing about the URL's availability for a new
            // request. In particular, a shortened transfer timeout must not poison its cache: curl's
            // millisecond timeout can end a clamped transfer just before the deadline itself.
            if (hrtime(true) / 1e9 < $this->fetchDeadline - self::DEADLINE_MARGIN) {
                $this->rememberFailure($url, $failFile, $now);
            }
            throw $e;
        }
        try {
            // validate before caching; issuer-dependent errors must not poison the URL-wide cache
            $crl = $this->parse($der, $issuer);
            // an outdated CRL is as unusable as an unreachable one: do not fetch it again (F-14)
            if ($crl['nextUpdate'] === null || $crl['nextUpdate'] < $now - self::CLOCK_SKEW) {
                throw new ValidationException('revocationunavailable', 'CRL expired');
            }
            // a replayed older CRL is neither used nor cached (audit I-02)
            $this->checkNumber($crl, $issuer, $url);
        } catch (ValidationException | \TypeError | \ValueError $e) {
            $this->rememberFailure($issuerKey, $issuerFailFile, $now);
            throw $e;
        }
        foreach ([$failFile, $issuerFailFile] as $file) {
            if ($file !== null && is_file($file)) {
                @unlink($file);
            }
        }
        unset($this->failed[$url], $this->failed[$issuerKey]);

        if ($cacheFile !== null) {
            $tmp = $cacheFile . '.' . bin2hex(random_bytes(6));
            if (@file_put_contents($tmp, $der, LOCK_EX) !== false) {
                @chmod($tmp, 0600);
                @rename($tmp, $cacheFile);
            }
        }
        return $this->memory[$url] = $der;
    }

    /**
     * Compare the cRLNumber of a validly signed, unexpired CRL with the highest one seen for the same
     * issuer and distribution point; throws when it is lower, stores it when it is higher (audit I-02).
     * Store failures never break the check: without the store there is simply no rollback protection.
     *
     * @param array{number: ?string, aki: string} $crl
     */
    private function checkNumber(array $crl, Certificate $issuer, string $url): void
    {
        $number = $crl['number'];
        if ($this->crlNumbers === null || $number === null) {
            return;
        }
        $key = hash('sha256', self::lp($issuer->subjectNameDer) . self::lp($crl['aki'] !== '' ? $crl['aki'] : $issuer->subjectKeyId) . self::lp($url));
        if (($this->numbersSeen[$key] ?? null) === $number) {
            return;
        }
        try {
            $seen = $this->crlNumbers->get($key);
        } catch (\Throwable $e) {
            $this->storeFailed($e);
            return;
        }
        $seen = $seen !== null && preg_match('/^[0-9A-Fa-f]{1,128}$/D', $seen) === 1 ? $seen : null;
        $cmp = $seen === null ? 1 : self::compareNumbers($number, $seen);
        if ($cmp < 0) {
            Log::info('revocation', 'CRL number lower than previously seen: ' . $number . ' < ' . $seen, ['url' => $url]);
            throw new ValidationException('revocationunavailable', 'CRL number lower than previously seen');
        }
        if ($cmp > 0) {
            try {
                $this->crlNumbers->put($key, $number);
            } catch (\Throwable $e) {
                $this->storeFailed($e);
            }
        }
        $this->numbersSeen[$key] = $number;
    }

    private function storeFailed(\Throwable $e): void
    {
        if (!$this->storeFailureLogged) {
            $this->storeFailureLogged = true;
            Log::info('revocation', 'CRL number store unavailable: ' . $e->getMessage());
        }
    }

    /**
     * Compare two non-negative integers given as hex: length of the normalised form first, then
     * lexicographically.
     */
    public static function compareNumbers(string $a, string $b): int
    {
        $a = ltrim(strtoupper($a), '0');
        $b = ltrim(strtoupper($b), '0');
        return strlen($a) <=> strlen($b) ?: strcmp($a, $b) <=> 0;
    }

    private static function lp(string $s): string
    {
        return pack('N', strlen($s)) . $s;
    }

    private function rememberFailure(string $key, ?string $file, int $now): void
    {
        $this->failed[$key] = $now;
        if ($file !== null && !is_link($file)) {
            @touch($file, $now);
            @chmod($file, 0600);
        }
    }

    private function cacheFile(string $url): ?string
    {
        if ($this->cacheDir === '') {
            return null;
        }
        $base = rtrim($this->cacheDir, '/');
        $dir = $base . '/crl';
        // Both the cache and its immediate parent must be private. Otherwise another local user
        // could replace a CRL or plant a failure marker (audit F-14). Do not repair permissions on
        // existing directories: their entries may already be untrusted. Continue without disk cache.
        foreach ([$base, $dir] as $path) {
            if (!file_exists($path) && !is_link($path)) {
                $old = umask(0077);
                try {
                    @mkdir($path, 0700, true);
                } finally {
                    umask($old);
                }
            }
            clearstatcache(true, $path);
            $st = @lstat($path);
            if ($st === false || is_link($path) || !is_dir($path)
                || (function_exists('posix_geteuid') && $st['uid'] !== posix_geteuid()) || ($st['mode'] & 0077) !== 0) {
                Log::warning('revocation', 'CRL disk cache disabled: unsafe directory');
                return null;
            }
        }
        return $dir . '/' . hash('sha256', $url) . '.crl';
    }

    /**
     * Parse and verify a CRL against $issuer.
     *
     * @return array{thisUpdate: int, nextUpdate: ?int, entries: list<array{serial: string, date: ?int, reason: string}>, idpUris: list<string>, idpScoped: bool, onlyUser: bool, onlyCa: bool, number: ?string, aki: string}
     */
    private function parse(string $der, Certificate $issuer): array
    {
        if ($der === '' || strlen($der) > $this->maxCrlBytes) {
            throw new ValidationException('revocationunavailable', 'CRL size out of range');
        }
        $root = Asn1::parseShallow($der);
        $top = iterator_to_array(Asn1::iterate($root, 3), false);
        if (count($top) !== 3) {
            throw new ValidationException('revocationunavailable', 'bad CRL structure');
        }
        [$tbs, $sigAlgNode, $sigNode] = $top;

        // signature algorithm + verification against the issuer's key
        $sigAlg = Asn1::oid($sigAlgNode->child(0));
        if (!isset(self::SIG_ALGS[$sigAlg])) {
            throw new ValidationException('revocationunavailable', 'unsupported CRL signature algorithm');
        }
        if (!$this->acceptSha1 && in_array($sigAlg, self::SHA1_SIG_ALGS, true)) {
            throw new ValidationException('revocationunavailable', 'SHA-1 CRL signature not allowed (mimeshield_legacy_digests)');
        }
        [$sigBytes] = Asn1::bitString($sigNode);
        if (!$issuer->hasKeyUsage(Certificate::KU_CRL_SIGN)) {
            throw new ValidationException('revocationunavailable', 'issuer may not sign CRLs');
        }
        $issuerPem = $issuer->pem;
        [$pub] = OpenSsl::run(static fn () => openssl_pkey_get_public($issuerPem));
        if (!$pub instanceof \OpenSSLAsymmetricKey) {
            throw new ValidationException('revocationunavailable', 'issuer key unavailable');
        }
        $tbsRaw = $tbs->raw();
        $alg = self::SIG_ALGS[$sigAlg];
        [$ok] = OpenSsl::run(static fn () => openssl_verify($tbsRaw, $sigBytes, $pub, $alg));
        if ($ok !== 1) {
            throw new ValidationException('revocationunavailable', 'CRL signature invalid');
        }

        // tbsCertList
        $fields = [];
        foreach (Asn1::iterate($tbs, 16) as $f) {
            $fields[] = $f;
        }
        $i = 0;
        if (isset($fields[0]) && $fields[0]->isUniversal(Asn1::TAG_INTEGER)) {
            $i = 1; // version
        }
        $innerSigAlg = $fields[$i++] ?? throw new ValidationException('revocationunavailable', 'bad CRL');
        if ($innerSigAlg->raw() !== $sigAlgNode->raw()) {
            throw new ValidationException('revocationunavailable', 'CRL signature algorithms differ');
        }
        $issuerName = $fields[$i++] ?? throw new ValidationException('revocationunavailable', 'bad CRL');
        if ($issuerName->raw() !== $issuer->subjectNameDer) {
            throw new ValidationException('revocationunavailable', 'CRL issuer mismatch');
        }
        $thisUpdate = Asn1::time($fields[$i++] ?? throw new ValidationException('revocationunavailable', 'bad CRL'));
        $nextUpdate = null;
        if (isset($fields[$i]) && ($fields[$i]->isUniversal(Asn1::TAG_UTCTIME) || $fields[$i]->isUniversal(Asn1::TAG_GENTIME))) {
            $nextUpdate = Asn1::time($fields[$i++]);
        }
        $revoked = null;
        if (isset($fields[$i]) && $fields[$i]->isUniversal(Asn1::TAG_SEQUENCE)) {
            $revoked = $fields[$i++];
        }
        $idp = ['uris' => [], 'scoped' => false, 'onlyUser' => false, 'onlyCa' => false, 'number' => null, 'aki' => ''];
        if (isset($fields[$i]) && $fields[$i]->isContext(0)) {
            $idp = $this->checkCrlExtensions($fields[$i]);
        }

        $entries = [];
        if ($revoked !== null) {
            foreach (Asn1::iterate($revoked) as $entry) {
                $e = $entry->children();
                $serial = Asn1::integerHex($e[0] ?? throw new ValidationException('revocationunavailable', 'bad CRL entry'));
                $date = isset($e[1]) ? Asn1::time($e[1]) : null;
                $reason = 'unspecified';
                if (isset($e[2])) {
                    foreach ($e[2]->children() as $ext) {
                        $x = self::extension($ext);
                        $oid = Asn1::oid($x[0]);
                        $critical = count($x) === 3 && $x[1]->isUniversal(Asn1::TAG_BOOLEAN) && $x[1]->content() !== "\x00";
                        if ($oid === self::OID_REASON) {
                            $reason = self::reasonName(Asn1::parseContent($x[count($x) - 1])->content());
                        } elseif ($oid === self::OID_CERT_ISSUER) {
                            throw new ValidationException('revocationunavailable', 'indirect CRL not supported');
                        } elseif ($critical && $oid !== self::OID_INVALIDITY) {
                            throw new ValidationException('revocationunavailable', 'unknown critical CRL entry extension');
                        }
                    }
                }
                $entries[] = ['serial' => $serial, 'date' => $date, 'reason' => $reason];
            }
        }

        return ['thisUpdate' => $thisUpdate, 'nextUpdate' => $nextUpdate, 'entries' => $entries, 'idpUris' => $idp['uris'], 'idpScoped' => $idp['scoped'],
            'onlyUser' => $idp['onlyUser'], 'onlyCa' => $idp['onlyCa'], 'number' => $idp['number'], 'aki' => $idp['aki']];
    }

    /**
     * Validate CRL extensions; returns the URIs of the IssuingDistributionPoint fullName (if any),
     * whether a fullName (in any name form) restricts the scope of the CRL and whether the CRL only
     * covers end-entity (onlyContainsUserCerts) or CA (onlyContainsCACerts) certificates, plus the
     * cRLNumber (hex, null when absent or not a non-negative INTEGER) and the AKI keyIdentifier (hex).
     *
     * @return array{uris: list<string>, scoped: bool, onlyUser: bool, onlyCa: bool, number: ?string, aki: string}
     */
    private function checkCrlExtensions(Asn1Node $wrapper): array
    {
        $uris = [];
        $scoped = false;
        $onlyUser = false;
        $onlyCa = false;
        $number = null;
        $aki = '';
        foreach ($wrapper->child(0)->children() as $ext) {
            $x = self::extension($ext);
            $oid = Asn1::oid($x[0]);
            $critical = count($x) === 3 && $x[1]->isUniversal(Asn1::TAG_BOOLEAN) && $x[1]->content() !== "\x00";
            if ($oid === self::OID_DELTA_CRL) {
                throw new ValidationException('revocationunavailable', 'delta CRL not supported');
            }
            if ($oid === self::OID_IDP) {
                foreach (Asn1::parseContent($x[count($x) - 1])->children() as $f) {
                    if ($f->isContext(0)) {
                        // distributionPoint: fullName [0] GeneralNames | nameRelativeToCRLIssuer [1]
                        foreach ($f->children() as $dpn) {
                            if (!$dpn->isContext(0)) {
                                throw new ValidationException('revocationunavailable', 'unsupported IDP name form');
                            }
                            $scoped = true;
                            foreach ($dpn->children() as $gn) {
                                if ($gn->isContext(6) && !$gn->constructed) {
                                    $uris[] = $gn->content();
                                }
                            }
                        }
                    } elseif ($f->isContext(3)) {
                        // onlySomeReasons: a reason-partitioned CRL cannot prove "not revoked"
                        throw new ValidationException('revocationunavailable', 'partitioned CRL (onlySomeReasons) not supported');
                    } elseif (($f->isContext(4) || $f->isContext(5)) && $f->content() !== "\x00") {
                        throw new ValidationException('revocationunavailable', 'indirect or attribute CRL not supported');
                    } elseif ($f->isContext(1) && $f->content() !== "\x00") {
                        $onlyUser = true;
                    } elseif ($f->isContext(2) && $f->content() !== "\x00") {
                        $onlyCa = true;
                    }
                }
                continue;
            }
            // Only read for rollback tracking (I-02): a malformed value means "no number" / "no AKI",
            // exactly as before the tracking existed, never a rejected CRL.
            try {
                if ($oid === self::OID_CRL_NUMBER) {
                    // RFC 5280 5.2.3: non-negative INTEGER
                    $n = Asn1::parseContent($x[count($x) - 1]);
                    if ($n->isUniversal(Asn1::TAG_INTEGER) && !$n->constructed && $n->content() !== '' && (ord($n->content()[0]) & 0x80) === 0) {
                        $number = Asn1::integerHex($n);
                    }
                } elseif ($oid === self::OID_AKI) {
                    foreach (Asn1::parseContent($x[count($x) - 1])->children() as $a) {
                        if ($a->isContext(0) && !$a->constructed) {
                            $aki = strtoupper(bin2hex($a->content()));
                        }
                    }
                }
            } catch (ValidationException | \TypeError | \ValueError) {
                // ignored, see above
            }
            if ($critical && !in_array($oid, [self::OID_CRL_NUMBER, self::OID_AKI], true)) {
                throw new ValidationException('revocationunavailable', 'unknown critical CRL extension');
            }
        }
        return ['uris' => $uris, 'scoped' => $scoped, 'onlyUser' => $onlyUser, 'onlyCa' => $onlyCa, 'number' => $number, 'aki' => $aki];
    }

    /**
     * Children of an Extension SEQUENCE { extnID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }.
     *
     * @return list<Asn1Node>
     */
    private static function extension(Asn1Node $ext): array
    {
        $x = $ext->children();
        $n = count($x);
        if (($n !== 2 && $n !== 3) || !$x[0]->isUniversal(Asn1::TAG_OID) || !$x[$n - 1]->isUniversal(Asn1::TAG_OCTET_STRING)
            || ($n === 3 && !$x[1]->isUniversal(Asn1::TAG_BOOLEAN))) {
            throw new ValidationException('revocationunavailable', 'malformed CRL extension');
        }
        return $x;
    }

    private static function reasonName(string $enumerated): string
    {
        $code = $enumerated === '' ? 0 : ord($enumerated[strlen($enumerated) - 1]);
        return match ($code) {
            1 => 'keyCompromise',
            2 => 'cACompromise',
            3 => 'affiliationChanged',
            4 => 'superseded',
            5 => 'cessationOfOperation',
            6 => 'certificateHold',
            9 => 'privilegeWithdrawn',
            10 => 'aACompromise',
            default => 'unspecified',
        };
    }
}
