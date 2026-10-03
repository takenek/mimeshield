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
use MimeShield\Exception\ValidationException;

/**
 * Structural pre-check of an UNTRUSTED certificate before any OpenSSL function parses it.
 *
 * CVE-2026-35189 (OpenSSL advisory 2026-09-29): libcrypto allocates excessive memory while caching
 * the extensions of a certificate with many relative CRL distribution points (nameRelativeToCRLIssuer,
 * each expanded to a copy of the issuer name). Certificates from incoming mail reach libcrypto in
 * openssl_x509_read / openssl_cms_verify / openssl_cms_read / openssl_cms_decrypt before any other
 * plugin check. Updating OpenSSL is the fix (`diag` warns); this check protects installations whose
 * libcrypto lacks it (audit F-16 decision 2026-10-03).
 *
 * Deliberate refusals (no legitimate S/MIME certificate is affected): the plugin itself only uses
 * http(s) fullName URIs of cRLDistributionPoints (Certificate::parseDer), so a relative name is never
 * needed; more than MAX_DISTRIBUTION_POINTS points or a repeated extension (RFC 5280 4.2) is refused
 * as well. A certificate the plugin's own hardened parser (Asn1 limits) cannot read is refused too:
 * fail closed, OpenSSL is never asked to parse what this check could not inspect.
 */
final class CertPrecheck
{
    /** Upper bound of DistributionPoints per certificate (real CAs use 1-3) */
    public const MAX_DISTRIBUTION_POINTS = 8;

    private const OID_CRLDP = '2.5.29.31';

    /**
     * @throws ValidationException 'certinvalid' when the certificate must not be handed to OpenSSL
     */
    public static function assertSafe(string $certDer): void
    {
        try {
            self::check($certDer);
        } catch (ValidationException $e) {
            // ASN.1 errors carry the label 'malformed'; callers of certificate parsing expect 'certinvalid'
            throw new ValidationException('certinvalid', 'certificate pre-check (CVE-2026-35189): ' . $e->getMessage(), [], $e);
        }
    }

    private static function check(string $der): void
    {
        $cert = Asn1::parse($der)->expect(Asn1::TAG_SEQUENCE, true);
        $tbs = $cert->child(0)->expect(Asn1::TAG_SEQUENCE, true);
        $found = 0;
        foreach ($tbs->children() as $node) {
            if (!$node->isContext(3)) {
                continue;
            }
            // extensions [3] EXPLICIT Extensions
            foreach (Asn1::parseContent($node)->expect(Asn1::TAG_SEQUENCE, true)->children() as $ext) {
                $e = $ext->expect(Asn1::TAG_SEQUENCE, true)->children();
                if (Asn1::oid($e[0] ?? throw new ValidationException('certinvalid', 'bad extension')) !== self::OID_CRLDP) {
                    continue;
                }
                if (++$found > 1) {
                    throw new ValidationException('certinvalid', 'duplicate cRLDistributionPoints extension');
                }
                $value = end($e);
                if (!$value instanceof Asn1Node || !$value->isUniversal(Asn1::TAG_OCTET_STRING) || $value->constructed) {
                    throw new ValidationException('certinvalid', 'bad cRLDistributionPoints value');
                }
                self::checkDistributionPoints(Asn1::parseContent($value));
            }
        }
    }

    private static function checkDistributionPoints(Asn1Node $value): void
    {
        $points = $value->expect(Asn1::TAG_SEQUENCE, true)->children();
        if (count($points) > self::MAX_DISTRIBUTION_POINTS) {
            throw new ValidationException('certinvalid', 'too many CRL distribution points: ' . count($points));
        }
        foreach ($points as $dp) {
            // DistributionPoint: distributionPoint [0] DistributionPointName, reasons [1], cRLIssuer [2]
            foreach ($dp->expect(Asn1::TAG_SEQUENCE, true)->children() as $field) {
                if (!$field->isContext(0)) {
                    continue;
                }
                // DistributionPointName CHOICE (explicit): fullName [0] | nameRelativeToCRLIssuer [1]
                foreach ($field->children() as $name) {
                    if ($name->isContext(1)) {
                        throw new ValidationException('certinvalid', 'CRL distribution point with nameRelativeToCRLIssuer');
                    }
                }
            }
        }
    }
}
