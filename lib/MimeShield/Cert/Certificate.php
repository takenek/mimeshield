<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Cert;

use MimeShield\Crypto\Asn1;
use MimeShield\Crypto\Asn1Node;
use MimeShield\Crypto\OpenSsl;
use MimeShield\Exception\ValidationException;
use MimeShield\Trust\AddressMatcher;

/**
 * Immutable X.509 certificate value object.
 *
 * All fields are derived from the certificate itself. Every string coming from a certificate is
 * UNTRUSTED data: it must be escaped before output (the UI layer uses rcube::Q / html::*).
 *
 * Security-relevant fields (SAN rfc822Name, KeyUsage, EKU, basicConstraints, CRL DP, AIA) are read
 * from DER, never from openssl_x509_parse() text output, whose subjectAltName string is ambiguous
 * (an rfc822Name containing ", email:x" is indistinguishable from two entries).
 */
final class Certificate
{
    public const KU_DIGITAL_SIGNATURE = 1 << 0;
    public const KU_NON_REPUDIATION = 1 << 1;
    public const KU_KEY_ENCIPHERMENT = 1 << 2;
    public const KU_DATA_ENCIPHERMENT = 1 << 3;
    public const KU_KEY_AGREEMENT = 1 << 4;
    public const KU_KEY_CERT_SIGN = 1 << 5;
    public const KU_CRL_SIGN = 1 << 6;
    public const KU_ENCIPHER_ONLY = 1 << 7;
    public const KU_DECIPHER_ONLY = 1 << 8;

    public const EKU_EMAIL_PROTECTION = '1.3.6.1.5.5.7.3.4';
    public const EKU_ANY = '2.5.29.37.0';

    private const OID_SAN = '2.5.29.17';
    private const OID_KU = '2.5.29.15';
    private const OID_EKU = '2.5.29.37';
    private const OID_BC = '2.5.29.19';
    private const OID_CRLDP = '2.5.29.31';
    private const OID_AIA = '1.3.6.1.5.5.7.1.1';
    private const OID_SKI = '2.5.29.14';
    private const OID_AKI = '2.5.29.35';
    private const OID_EMAIL_ATTR = '1.2.840.113549.1.9.1';
    private const OID_AD_OCSP = '1.3.6.1.5.5.7.48.1';
    private const OID_AD_CAISSUERS = '1.3.6.1.5.5.7.48.2';

    private const EKU_NAMES = [
        '1.3.6.1.5.5.7.3.1' => 'TLS Web Server Authentication',
        '1.3.6.1.5.5.7.3.2' => 'TLS Web Client Authentication',
        '1.3.6.1.5.5.7.3.3' => 'Code Signing',
        '1.3.6.1.5.5.7.3.4' => 'E-mail Protection',
        '1.3.6.1.5.5.7.3.8' => 'Time Stamping',
        '1.3.6.1.5.5.7.3.9' => 'OCSP Signing',
        '1.3.6.1.4.1.311.10.3.4' => 'Microsoft Encrypted File System',
        '1.3.6.1.4.1.311.20.2.2' => 'Microsoft Smartcard Login',
        '1.3.6.1.4.1.311.10.3.12' => 'Microsoft Document Signing',
        '2.5.29.37.0' => 'Any Extended Key Usage',
    ];

    private const KU_NAMES = [
        self::KU_DIGITAL_SIGNATURE => 'Digital Signature',
        self::KU_NON_REPUDIATION => 'Non Repudiation',
        self::KU_KEY_ENCIPHERMENT => 'Key Encipherment',
        self::KU_DATA_ENCIPHERMENT => 'Data Encipherment',
        self::KU_KEY_AGREEMENT => 'Key Agreement',
        self::KU_KEY_CERT_SIGN => 'Certificate Sign',
        self::KU_CRL_SIGN => 'CRL Sign',
        self::KU_ENCIPHER_ONLY => 'Encipher Only',
        self::KU_DECIPHER_ONLY => 'Decipher Only',
    ];

    /** @var list<string> */
    public readonly array $sanEmails;
    /** @var list<string> */
    public readonly array $subjectEmails;
    /** @var list<string> SAN rfc822Name values rejected as malformed */
    public readonly array $rejectedEmails;
    public readonly ?int $keyUsage;
    /** @var null|list<string> */
    public readonly ?array $extendedKeyUsage;
    public readonly bool $isCa;
    /** @var list<string> */
    public readonly array $crlUrls;
    /** @var list<string> */
    public readonly array $ocspUrls;
    /** @var list<string> */
    public readonly array $caIssuerUrls;
    public readonly string $subjectKeyId;
    public readonly string $authorityKeyId;
    public readonly string $issuerNameDer;
    public readonly string $subjectNameDer;
    public readonly string $serialHex;
    public readonly int $notBefore;
    public readonly int $notAfter;
    public readonly string $fingerprint;
    public readonly string $subject;
    public readonly string $issuer;
    /** @var array<string, string|list<string>> */
    public readonly array $subjectParts;
    /** @var array<string, string|list<string>> */
    public readonly array $issuerParts;
    public readonly string $keyType;
    public readonly int $keyBits;
    public readonly string $curve;
    public readonly string $signatureAlgorithm;

    private function __construct(public readonly string $pem, public readonly string $der)
    {
        // untrusted input: refuse certificates that trigger CVE-2026-35189 before libcrypto parses them (audit F-16)
        CertPrecheck::assertSafe($der);
        [$x509, $err] = OpenSsl::run(static fn () => openssl_x509_read($pem));
        if (!$x509 instanceof \OpenSSLCertificate) {
            throw new ValidationException('certinvalid', 'openssl_x509_read failed: ' . OpenSsl::summarize($err));
        }
        [$info] = OpenSsl::run(static fn () => openssl_x509_parse($x509, true));
        if (!is_array($info)) {
            throw new ValidationException('certinvalid', 'openssl_x509_parse failed');
        }
        [$fp] = OpenSsl::run(static fn () => openssl_x509_fingerprint($x509, 'sha256'));
        if (!is_string($fp) || strlen($fp) !== 64) {
            throw new ValidationException('certinvalid', 'fingerprint failed');
        }
        $this->fingerprint = strtolower($fp);
        $this->subjectParts = self::stringParts($info['subject'] ?? []);
        $this->issuerParts = self::stringParts($info['issuer'] ?? []);
        $this->subject = self::formatDn($this->subjectParts);
        $this->issuer = self::formatDn($this->issuerParts);
        $this->signatureAlgorithm = (string) ($info['signatureTypeLN'] ?? $info['signatureTypeSN'] ?? '');

        // key details
        $keyType = 'unknown';
        $bits = 0;
        $curve = '';
        [$pub] = OpenSsl::run(static fn () => openssl_pkey_get_public($x509));
        if ($pub instanceof \OpenSSLAsymmetricKey) {
            [$d] = OpenSsl::run(static fn () => openssl_pkey_get_details($pub));
            if (is_array($d)) {
                $bits = (int) ($d['bits'] ?? 0);
                switch ($d['type'] ?? -1) {
                    case OPENSSL_KEYTYPE_RSA:
                        $keyType = 'RSA';
                        break;
                    case OPENSSL_KEYTYPE_EC:
                        $keyType = 'EC';
                        $curve = (string) ($d['ec']['curve_name'] ?? '');
                        break;
                    case OPENSSL_KEYTYPE_DSA:
                        $keyType = 'DSA';
                        break;
                    default:
                        $keyType = 'other';
                }
            }
        }
        $this->keyType = $keyType;
        $this->keyBits = $bits;
        $this->curve = $curve;

        $d = self::parseDer($der);
        $this->serialHex = $d['serialHex'];
        $this->issuerNameDer = $d['issuerNameDer'];
        $this->subjectNameDer = $d['subjectNameDer'];
        $this->notBefore = $d['notBefore'];
        $this->notAfter = $d['notAfter'];
        $this->sanEmails = $d['sanEmails'];
        $this->subjectEmails = $d['subjectEmails'];
        $this->rejectedEmails = $d['rejectedEmails'];
        $this->keyUsage = $d['keyUsage'];
        $this->extendedKeyUsage = $d['extendedKeyUsage'];
        $this->isCa = $d['isCa'];
        $this->crlUrls = $d['crlUrls'];
        $this->ocspUrls = $d['ocspUrls'];
        $this->caIssuerUrls = $d['caIssuerUrls'];
        $this->subjectKeyId = $d['subjectKeyId'];
        $this->authorityKeyId = $d['authorityKeyId'];
    }

    /**
     * Build from PEM (single certificate) or DER bytes.
     */
    public static function fromString(string $data): self
    {
        // never trim raw DER: its last byte may legitimately be whitespace or NUL
        if (str_contains($data, '-----BEGIN CERTIFICATE-----')) {
            if (!preg_match('/-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+\/=\s]+?)\s*-----END CERTIFICATE-----/', $data, $m)) {
                throw new ValidationException('certinvalid', 'bad PEM');
            }
            $der = base64_decode(preg_replace('/\s+/', '', $m[1]) ?? '', true);
            if ($der === false || $der === '') {
                throw new ValidationException('certinvalid', 'bad PEM base64');
            }
        } else {
            $der = $data;
        }
        return self::fromDer($der);
    }

    public static function fromDer(string $der): self
    {
        if ($der === '' || strlen($der) > 65536) {
            throw new ValidationException('certinvalid', 'certificate size out of range');
        }
        // strict DER structure check before handing it to OpenSSL
        $root = Asn1::parse($der);
        $root->expect(Asn1::TAG_SEQUENCE, true);
        return new self(self::derToPem($der), $der);
    }

    public static function derToPem(string $der): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
    }

    /**
     * Split a PEM bundle into individual certificate PEMs (other PEM blocks are ignored).
     *
     * @return list<string>
     */
    public static function splitPemBundle(string $bundle, int $max = 500): array
    {
        preg_match_all('/-----BEGIN CERTIFICATE-----[A-Za-z0-9+\/=\s]+?-----END CERTIFICATE-----/', $bundle, $m);
        $out = [];
        foreach ($m[0] as $pem) {
            $out[] = $pem . "\n";
            if (count($out) >= $max) {
                break;
            }
        }
        return $out;
    }

    public function x509(): \OpenSSLCertificate
    {
        [$x509] = OpenSsl::run(fn () => openssl_x509_read($this->pem));
        if (!$x509 instanceof \OpenSSLCertificate) {
            throw new ValidationException('certinvalid', 'openssl_x509_read failed');
        }
        return $x509;
    }

    /**
     * Mailbox addresses bound to this certificate.
     *
     * SAN rfc822Name is authoritative (RFC 8550 section 3). The legacy emailAddress attribute of the
     * subject DN is only used when the SAN contains no rfc822Name and $allowSubjectFallback is set.
     *
     * @return list<string>
     */
    public function emails(bool $allowSubjectFallback = true): array
    {
        if ($this->sanEmails !== []) {
            return $this->sanEmails;
        }
        // RFC 8550: the subject attribute is only a fallback for certificates WITHOUT rfc822Name;
        // when SAN rfc822Names exist but were rejected, do not silently use the subject instead
        return $allowSubjectFallback && $this->rejectedEmails === [] ? $this->subjectEmails : [];
    }

    /**
     * Whether emails() comes from the legacy subject attribute.
     */
    public function usesLegacySubjectEmail(): bool
    {
        return $this->sanEmails === [] && $this->rejectedEmails === [] && $this->subjectEmails !== [];
    }

    public function isTimeValid(?int $now = null): bool
    {
        $now ??= time();
        return $now >= $this->notBefore && $now <= $this->notAfter;
    }

    public function isExpired(?int $now = null): bool
    {
        return ($now ?? time()) > $this->notAfter;
    }

    public function isNotYetValid(?int $now = null): bool
    {
        return ($now ?? time()) < $this->notBefore;
    }

    public function isSelfIssued(): bool
    {
        return $this->issuerNameDer === $this->subjectNameDer;
    }

    public function hasKeyUsage(int $bits): bool
    {
        // absent extension = no restriction (RFC 5280 4.2.1.3)
        return $this->keyUsage === null || ($this->keyUsage & $bits) !== 0;
    }

    /**
     * EKU check for S/MIME: absent extension or emailProtection / anyExtendedKeyUsage.
     */
    public function allowsEmailProtection(): bool
    {
        if ($this->extendedKeyUsage === null) {
            return true;
        }
        return in_array(self::EKU_EMAIL_PROTECTION, $this->extendedKeyUsage, true)
            || in_array(self::EKU_ANY, $this->extendedKeyUsage, true);
    }

    /**
     * Usable for signing (key usage + EKU), regardless of time and chain.
     */
    public function canSign(): bool
    {
        return !$this->isCa
            && $this->hasKeyUsage(self::KU_DIGITAL_SIGNATURE | self::KU_NON_REPUDIATION)
            && $this->allowsEmailProtection()
            && in_array($this->keyType, ['RSA', 'EC'], true);
    }

    /**
     * Usable as encryption recipient (key usage + EKU + key type), regardless of time and chain.
     */
    public function canEncrypt(): bool
    {
        if ($this->isCa || !$this->allowsEmailProtection()) {
            return false;
        }
        if ($this->keyType === 'RSA') {
            return $this->hasKeyUsage(self::KU_KEY_ENCIPHERMENT);
        }
        if ($this->keyType === 'EC') {
            return $this->hasKeyUsage(self::KU_KEY_AGREEMENT);
        }
        return false;
    }

    /**
     * Human readable key usage names.
     *
     * @return list<string>
     */
    public function keyUsageNames(): array
    {
        if ($this->keyUsage === null) {
            return [];
        }
        $out = [];
        foreach (self::KU_NAMES as $bit => $name) {
            if ($this->keyUsage & $bit) {
                $out[] = $name;
            }
        }
        return $out;
    }

    /**
     * Human readable EKU names (unknown OIDs are shown dotted).
     *
     * @return list<string>
     */
    public function extendedKeyUsageNames(): array
    {
        $out = [];
        foreach ($this->extendedKeyUsage ?? [] as $oid) {
            $out[] = self::EKU_NAMES[$oid] ?? $oid;
        }
        return $out;
    }

    public function keyDescription(): string
    {
        if ($this->keyType === 'EC') {
            return 'EC ' . ($this->curve !== '' ? $this->curve . ' ' : '') . '(' . $this->keyBits . ' bit)';
        }
        return $this->keyType . ($this->keyBits ? ' ' . $this->keyBits . ' bit' : '');
    }

    /**
     * Display name: CN, else first email, else subject.
     */
    public function displayName(): string
    {
        $cn = $this->subjectParts['CN'] ?? null;
        if (is_array($cn)) {
            $cn = $cn[0] ?? null;
        }
        if (is_string($cn) && $cn !== '') {
            return $cn;
        }
        return $this->emails()[0] ?? $this->subject;
    }

    public function issuerDisplayName(): string
    {
        foreach (['CN', 'O', 'OU'] as $k) {
            $v = $this->issuerParts[$k] ?? null;
            if (is_array($v)) {
                $v = $v[0] ?? null;
            }
            if (is_string($v) && $v !== '') {
                return $v;
            }
        }
        return $this->issuer;
    }

    /**
     * Is $other the issuer of this certificate (name match + signature check by OpenSSL)?
     */
    public function isIssuedBy(self $other): bool
    {
        if ($this->issuerNameDer !== $other->subjectNameDer) {
            return false;
        }
        if ($this->authorityKeyId !== '' && $other->subjectKeyId !== '' && $this->authorityKeyId !== $other->subjectKeyId) {
            return false;
        }
        $self = $this;
        [$pub] = OpenSsl::run(static fn () => openssl_pkey_get_public($other->pem));
        if (!$pub instanceof \OpenSSLAsymmetricKey) {
            return false;
        }
        [$ok] = OpenSsl::run(static fn () => openssl_x509_verify($self->pem, $pub));
        return $ok === 1;
    }

    /**
     * @param array<mixed> $parts
     *
     * @return array<string, string|list<string>>
     */
    private static function stringParts(array $parts): array
    {
        $out = [];
        foreach ($parts as $k => $v) {
            if (is_array($v)) {
                $out[self::displaySafe((string) $k)] = array_values(array_map(static fn ($x) => self::displaySafe((string) $x), $v));
            } else {
                $out[self::displaySafe((string) $k)] = self::displaySafe((string) $v);
            }
        }
        return $out;
    }

    /**
     * Neutralise characters in certificate names that could spoof the display: control characters
     * (incl. CR/LF), Unicode line/paragraph separators and bidirectional overrides/isolates.
     */
    public static function displaySafe(string $s): string
    {
        if (!preg_match('//u', $s)) {
            $s = mb_convert_encoding($s, 'UTF-8', 'UTF-8');
        }
        return (string) preg_replace('/[\x00-\x1F\x7F\x{0080}-\x{009F}\x{2028}\x{2029}\x{200E}\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{061C}]/u', "\u{FFFD}", $s);
    }

    /**
     * @param array<string, string|list<string>> $parts
     */
    private static function formatDn(array $parts): string
    {
        $out = [];
        foreach ($parts as $k => $v) {
            foreach ((array) $v as $vv) {
                $out[] = $k . '=' . $vv;
            }
        }
        return implode(', ', $out);
    }

    /**
     * Security-relevant fields parsed from DER.
     *
     * @return array<string, mixed>
     */
    private static function parseDer(string $der): array
    {
        $out = [];
        $cert = Asn1::parse($der);
        $tbs = $cert->child(0)->expect(Asn1::TAG_SEQUENCE, true);
        $f = $tbs->children();
        $i = 0;
        if (isset($f[0]) && $f[0]->isContext(0)) {
            $i = 1;
        }
        $serial = $f[$i] ?? throw new ValidationException('certinvalid', 'no serial');
        $out['serialHex'] = Asn1::integerHex($serial);
        $issuer = $f[$i + 2] ?? throw new ValidationException('certinvalid', 'no issuer');
        $validity = $f[$i + 3] ?? throw new ValidationException('certinvalid', 'no validity');
        $subject = $f[$i + 4] ?? throw new ValidationException('certinvalid', 'no subject');
        $issuer->expect(Asn1::TAG_SEQUENCE, true);
        $subject->expect(Asn1::TAG_SEQUENCE, true);
        $out['issuerNameDer'] = $issuer->raw();
        $out['subjectNameDer'] = $subject->raw();
        $v = $validity->expect(Asn1::TAG_SEQUENCE, true)->children();
        if (count($v) !== 2) {
            throw new ValidationException('certinvalid', 'bad validity');
        }
        $out['notBefore'] = Asn1::time($v[0]);
        $out['notAfter'] = Asn1::time($v[1]);

        // subject emailAddress attributes (legacy)
        $subjectEmails = [];
        foreach ($subject->children() as $rdn) {
            foreach ($rdn->expect(Asn1::TAG_SET, true)->children() as $atv) {
                $parts = $atv->expect(Asn1::TAG_SEQUENCE, true)->children();
                if (count($parts) === 2 && Asn1::oid($parts[0]) === self::OID_EMAIL_ATTR) {
                    $email = AddressMatcher::normalize(Asn1::string($parts[1]));
                    if ($email !== null) {
                        $subjectEmails[] = $email;
                    }
                }
            }
        }

        $san = [];
        $rejected = [];
        $ku = null;
        $eku = null;
        $isCa = false;
        $crl = [];
        $ocsp = [];
        $caIssuers = [];
        $ski = '';
        $aki = '';
        $seen = [];

        foreach ($f as $node) {
            if (!$node->isContext(3)) {
                continue;
            }
            foreach (Asn1::parseContent($node)->expect(Asn1::TAG_SEQUENCE, true)->children() as $ext) {
                $e = $ext->expect(Asn1::TAG_SEQUENCE, true)->children();
                $oid = Asn1::oid($e[0] ?? throw new ValidationException('certinvalid', 'bad extension'));
                if (isset($seen[$oid])) {
                    // RFC 5280 4.2: a certificate MUST NOT include more than one instance of an extension
                    throw new ValidationException('certinvalid', 'duplicate extension ' . $oid);
                }
                $seen[$oid] = true;
                $valueNode = end($e);
                if (!$valueNode instanceof Asn1Node || !$valueNode->isUniversal(Asn1::TAG_OCTET_STRING)) {
                    throw new ValidationException('certinvalid', 'bad extension value');
                }
                $value = Asn1::parseContent($valueNode);

                switch ($oid) {
                    case self::OID_SAN:
                        foreach ($value->expect(Asn1::TAG_SEQUENCE, true)->children() as $gn) {
                            if ($gn->isContext(1) && !$gn->constructed) {
                                $raw = $gn->content();
                                $email = preg_match('/^[\x21-\x7E]+$/D', $raw) ? AddressMatcher::normalize($raw) : null;
                                if ($email === null) {
                                    $rejected[] = $raw;
                                } else {
                                    $san[] = $email;
                                }
                            }
                        }
                        break;
                    case self::OID_KU:
                        [$bytes, $unused] = Asn1::bitString($value);
                        $bits = 0;
                        $n = strlen($bytes);
                        for ($b = 0; $b < 9; $b++) {
                            $byte = intdiv($b, 8);
                            if ($byte < $n && (ord($bytes[$byte]) & (0x80 >> ($b % 8)))) {
                                $bits |= 1 << $b;
                            }
                        }
                        $ku = $bits;
                        break;
                    case self::OID_EKU:
                        $eku = [];
                        foreach ($value->expect(Asn1::TAG_SEQUENCE, true)->children() as $o) {
                            $eku[] = Asn1::oid($o);
                        }
                        break;
                    case self::OID_BC:
                        $bc = $value->expect(Asn1::TAG_SEQUENCE, true)->children();
                        if (isset($bc[0]) && $bc[0]->isUniversal(Asn1::TAG_BOOLEAN)) {
                            $isCa = $bc[0]->content() !== "\x00";
                        }
                        break;
                    case self::OID_CRLDP:
                        foreach ($value->expect(Asn1::TAG_SEQUENCE, true)->children() as $dp) {
                            foreach ($dp->children() as $dpf) {
                                if ($dpf->isContext(0) && $dpf->constructed) {
                                    foreach ($dpf->children() as $dpn) {
                                        if ($dpn->isContext(0) && $dpn->constructed) {
                                            foreach ($dpn->children() as $gn) {
                                                if ($gn->isContext(6) && !$gn->constructed) {
                                                    $crl[] = $gn->content();
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        break;
                    case self::OID_AIA:
                        foreach ($value->expect(Asn1::TAG_SEQUENCE, true)->children() as $ad) {
                            $adc = $ad->children();
                            if (count($adc) === 2 && $adc[1]->isContext(6) && !$adc[1]->constructed) {
                                $method = Asn1::oid($adc[0]);
                                if ($method === self::OID_AD_OCSP) {
                                    $ocsp[] = $adc[1]->content();
                                } elseif ($method === self::OID_AD_CAISSUERS) {
                                    $caIssuers[] = $adc[1]->content();
                                }
                            }
                        }
                        break;
                    case self::OID_SKI:
                        $ski = strtoupper(bin2hex($value->content()));
                        break;
                    case self::OID_AKI:
                        foreach ($value->expect(Asn1::TAG_SEQUENCE, true)->children() as $a) {
                            if ($a->isContext(0) && !$a->constructed) {
                                $aki = strtoupper(bin2hex($a->content()));
                            }
                        }
                        break;
                }
            }
        }

        $out['sanEmails'] = array_values(array_unique($san));
        $out['subjectEmails'] = array_values(array_unique($subjectEmails));
        $out['rejectedEmails'] = $rejected;
        $out['keyUsage'] = $ku;
        $out['extendedKeyUsage'] = $eku;
        $out['isCa'] = $isCa;
        $out['crlUrls'] = array_values(array_filter($crl, static fn ($u) => preg_match('/^[\x21-\x7E]{1,2048}$/D', $u) === 1));
        $out['ocspUrls'] = array_values(array_filter($ocsp, static fn ($u) => preg_match('/^[\x21-\x7E]{1,2048}$/D', $u) === 1));
        $out['caIssuerUrls'] = array_values(array_filter($caIssuers, static fn ($u) => preg_match('/^[\x21-\x7E]{1,2048}$/D', $u) === 1));
        $out['subjectKeyId'] = $ski;
        $out['authorityKeyId'] = $aki;

        return $out;
    }
}
