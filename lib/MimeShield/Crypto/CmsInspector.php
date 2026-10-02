<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Crypto;

use MimeShield\Exception\ValidationException;

/**
 * Read-only inspection of CMS ContentInfo structures (RFC 5652 / 5083).
 *
 * Provides metadata that PHP's OpenSSL extension does not expose: content type (authoritative
 * instead of the smime-type MIME parameter), digest and signature algorithms, signingTime,
 * recipient identifiers and content-encryption algorithm. Inspection results are informational
 * (algorithm policy, UI, key selection); all cryptographic verification is done by OpenSSL.
 */
final class CmsInspector
{
    public const OID_DATA = '1.2.840.113549.1.7.1';
    public const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
    public const OID_ENVELOPED_DATA = '1.2.840.113549.1.7.3';
    public const OID_AUTH_ENVELOPED_DATA = '1.2.840.113549.1.9.16.1.23';
    public const OID_COMPRESSED_DATA = '1.2.840.113549.1.9.16.1.9';
    public const OID_SIGNING_TIME = '1.2.840.113549.1.9.5';

    private const DIGESTS = [
        '1.2.840.113549.2.5' => 'md5',
        '1.3.14.3.2.26' => 'sha1',
        '2.16.840.1.101.3.4.2.4' => 'sha224',
        '2.16.840.1.101.3.4.2.1' => 'sha256',
        '2.16.840.1.101.3.4.2.2' => 'sha384',
        '2.16.840.1.101.3.4.2.3' => 'sha512',
    ];

    private const SIGNATURE_ALGS = [
        '1.2.840.113549.1.1.1' => 'rsa',
        '1.2.840.113549.1.1.4' => 'rsa-md5',
        '1.2.840.113549.1.1.5' => 'rsa-sha1',
        '1.2.840.113549.1.1.10' => 'rsa-pss',
        '1.2.840.113549.1.1.11' => 'rsa-sha256',
        '1.2.840.113549.1.1.12' => 'rsa-sha384',
        '1.2.840.113549.1.1.13' => 'rsa-sha512',
        '1.2.840.10045.4.1' => 'ecdsa-sha1',
        '1.2.840.10045.4.3.2' => 'ecdsa-sha256',
        '1.2.840.10045.4.3.3' => 'ecdsa-sha384',
        '1.2.840.10045.4.3.4' => 'ecdsa-sha512',
        '1.2.840.10045.2.1' => 'ecdsa',
        '1.3.101.112' => 'ed25519',
        '1.2.840.10040.4.3' => 'dsa-sha1',
    ];

    private const CIPHERS = [
        '2.16.840.1.101.3.4.1.2' => 'aes-128-cbc',
        '2.16.840.1.101.3.4.1.22' => 'aes-192-cbc',
        '2.16.840.1.101.3.4.1.42' => 'aes-256-cbc',
        '2.16.840.1.101.3.4.1.6' => 'aes-128-gcm',
        '2.16.840.1.101.3.4.1.26' => 'aes-192-gcm',
        '2.16.840.1.101.3.4.1.46' => 'aes-256-gcm',
        '1.2.840.113549.3.7' => 'des-ede3-cbc',
        '1.3.14.3.2.7' => 'des-cbc',
        '1.2.840.113549.3.2' => 'rc2-cbc',
        '1.2.840.113549.1.9.16.3.18' => 'chacha20-poly1305',
    ];

    /**
     * Content type OID of a ContentInfo.
     */
    public static function contentType(string $der): string
    {
        $ci = Asn1::parse($der, true, true)->expect(Asn1::TAG_SEQUENCE, true);
        return Asn1::oid($ci->child(0));
    }

    /**
     * Human-readable name of a CMS content type.
     */
    public static function contentTypeName(string $oid): string
    {
        return match ($oid) {
            self::OID_SIGNED_DATA => 'signed-data',
            self::OID_ENVELOPED_DATA => 'enveloped-data',
            self::OID_AUTH_ENVELOPED_DATA => 'authEnveloped-data',
            self::OID_COMPRESSED_DATA => 'compressed-data',
            self::OID_DATA => 'data',
            default => 'unknown',
        };
    }

    /**
     * Inspect SignedData.
     *
     * @return array{detached: bool, digests: list<string>, signers: list<array{digest: string, signature: string, signingTime: ?int, sid: array<string, string>}>, certificates: int}
     */
    public static function signedData(string $der): array
    {
        $sd = self::content($der, self::OID_SIGNED_DATA);
        $f = $sd->children();
        // version, digestAlgorithms, encapContentInfo, [0] certificates, [1] crls, signerInfos
        $digests = [];
        foreach (($f[1] ?? throw new ValidationException('malformed', 'CMS: no digestAlgorithms'))->children() as $alg) {
            $digests[] = self::digestName(Asn1::oid($alg->child(0)));
        }
        $eci = ($f[2] ?? throw new ValidationException('malformed', 'CMS: no encapContentInfo'))->children();
        $detached = count($eci) < 2;
        $certCount = 0;
        $signerInfos = null;
        for ($i = 3; $i < count($f); $i++) {
            if ($f[$i]->isContext(0)) {
                $certCount = count($f[$i]->children());
            } elseif ($f[$i]->isUniversal(Asn1::TAG_SET)) {
                $signerInfos = $f[$i];
            }
        }
        $signers = [];
        foreach ($signerInfos?->children() ?? [] as $si) {
            $s = $si->children();
            // version, sid, digestAlgorithm, [0] signedAttrs, signatureAlgorithm, signature, [1] unsigned
            $sid = [];
            if (isset($s[1])) {
                if ($s[1]->isUniversal(Asn1::TAG_SEQUENCE)) {
                    $sid = ['issuer' => $s[1]->child(0)->raw(), 'serial' => Asn1::integerHex($s[1]->child(1))];
                } elseif ($s[1]->isContext(0)) {
                    $sid = ['ski' => strtoupper(bin2hex($s[1]->content()))];
                }
            }
            $digest = isset($s[2]) ? self::digestName(Asn1::oid($s[2]->child(0))) : 'unknown';
            $idx = 3;
            $signingTime = null;
            if (isset($s[3]) && $s[3]->isContext(0)) {
                foreach ($s[3]->children() as $attr) {
                    $a = $attr->children();
                    if (count($a) >= 2 && Asn1::oid($a[0]) === self::OID_SIGNING_TIME) {
                        $vals = $a[1]->children();
                        if (isset($vals[0])) {
                            try {
                                $signingTime = Asn1::time($vals[0]);
                            } catch (ValidationException) {
                                $signingTime = null;
                            }
                        }
                    }
                }
                $idx = 4;
            }
            $sig = isset($s[$idx]) ? (self::SIGNATURE_ALGS[Asn1::oid($s[$idx]->child(0))] ?? 'unknown') : 'unknown';
            $signers[] = ['digest' => $digest, 'signature' => $sig, 'signingTime' => $signingTime, 'sid' => $sid];
        }

        return ['detached' => $detached, 'digests' => $digests, 'signers' => $signers, 'certificates' => $certCount];
    }

    /**
     * Inspect EnvelopedData / AuthEnvelopedData.
     *
     * @return array{type: string, cipher: string, recipients: list<array<string, string>>}
     */
    public static function envelopedData(string $der): array
    {
        $type = self::contentType($der);
        if ($type !== self::OID_ENVELOPED_DATA && $type !== self::OID_AUTH_ENVELOPED_DATA) {
            throw new ValidationException('malformed', 'CMS: not enveloped');
        }
        $ed = self::content($der, $type);
        $f = $ed->children();
        $i = 1;
        if (isset($f[1]) && $f[1]->isContext(0)) {
            $i = 2; // originatorInfo
        }
        $ris = $f[$i] ?? throw new ValidationException('malformed', 'CMS: no recipientInfos');
        $recipients = [];
        foreach ($ris->children() as $ri) {
            if ($ri->isUniversal(Asn1::TAG_SEQUENCE)) {
                // KeyTransRecipientInfo: version, rid, keyEncryptionAlgorithm, encryptedKey
                $r = $ri->children();
                $rid = $r[1] ?? null;
                $entry = ['type' => 'ktri', 'alg' => isset($r[2]) ? Asn1::oid($r[2]->child(0)) : ''];
                if ($rid !== null && $rid->isUniversal(Asn1::TAG_SEQUENCE)) {
                    $entry['issuer'] = $rid->child(0)->raw();
                    $entry['serial'] = Asn1::integerHex($rid->child(1));
                } elseif ($rid !== null && $rid->isContext(0)) {
                    $entry['ski'] = strtoupper(bin2hex($rid->content()));
                }
                $recipients[] = $entry;
            } elseif ($ri->isContext(1)) {
                // KeyAgreeRecipientInfo: version, [0] originator, [1] ukm?, keyEncAlg, recipientEncryptedKeys
                $r = $ri->children();
                foreach ($r as $node) {
                    if (!$node->isUniversal(Asn1::TAG_SEQUENCE) || $node->children() === [] || !$node->child(0)->isUniversal(Asn1::TAG_SEQUENCE)) {
                        continue;
                    }
                    foreach ($node->children() as $rek) {
                        $kid = $rek->child(0);
                        $entry = ['type' => 'kari'];
                        if ($kid->isUniversal(Asn1::TAG_SEQUENCE)) {
                            $entry['issuer'] = $kid->child(0)->raw();
                            $entry['serial'] = Asn1::integerHex($kid->child(1));
                        } elseif ($kid->isContext(0)) {
                            $entry['ski'] = strtoupper(bin2hex($kid->child(0)->content()));
                        }
                        $recipients[] = $entry;
                    }
                }
            } else {
                $recipients[] = ['type' => 'other'];
            }
        }
        $eci = $f[$i + 1] ?? throw new ValidationException('malformed', 'CMS: no encryptedContentInfo');
        $alg = Asn1::oid($eci->child(1)->child(0));

        return [
            'type' => self::contentTypeName($type),
            'cipher' => self::CIPHERS[$alg] ?? $alg,
            'recipients' => $recipients,
        ];
    }

    /**
     * Fix AuthEnvelopedData with AES-GCM whose GCMParameters omit aes-ICVlen (RFC 5084 DEFAULT 12).
     *
     * OpenSSL 3 refuses GCMParameters without the INTEGER, and some Microsoft Exchange components emit
     * them that way (with a 16 byte tag). The ICV length is set to the actual length of the `mac` field.
     * Only unauthenticated algorithm parameters are touched; GCM still authenticates ciphertext and tag.
     * Returns the patched DER, or null when no fix is needed or possible.
     */
    public static function fixGcmIcvLength(string $der): ?string
    {
        try {
            $root = Asn1::parse($der);
            if (Asn1::oid($root->child(0)) !== self::OID_AUTH_ENVELOPED_DATA) {
                return null;
            }
            $wrapper = $root->child(1);
            $aed = $wrapper->child(0);
            $f = $aed->children();
            $i = 1;
            if (isset($f[1]) && $f[1]->isContext(0)) {
                $i = 2;
            }
            $aeciIdx = $i + 1;
            $aeci = $f[$aeciIdx] ?? null;
            if ($aeci === null) {
                return null;
            }
            $alg = $aeci->child(1);
            $params = $alg->children()[1] ?? null;
            if ($params === null || !$params->isUniversal(Asn1::TAG_SEQUENCE)) {
                return null;
            }
            $pc = $params->children();
            if (count($pc) !== 1) {
                return null; // ICVlen present (or unexpected)
            }
            // mac: first OCTET STRING after aeci (authAttrs [1] may precede it)
            $mac = null;
            for ($j = $aeciIdx + 1; $j < count($f); $j++) {
                if ($f[$j]->isUniversal(Asn1::TAG_OCTET_STRING)) {
                    $mac = $f[$j];
                    break;
                }
            }
            if ($mac === null) {
                return null;
            }
            $tagLen = strlen($mac->content());
            if ($tagLen < 12 || $tagLen > 16) {
                return null;
            }
            $newParams = Asn1::encode("\x30", $pc[0]->raw() . Asn1::encode("\x02", chr($tagLen)));
            return Asn1::replaceAt($root, [1, 0, $aeciIdx, 1, 1], $newParams);
        } catch (ValidationException) {
            return null;
        }
    }

    public static function digestName(string $oid): string
    {
        return self::DIGESTS[$oid] ?? $oid;
    }

    /**
     * micalg value (RFC 8551 3.5.3.2) for a digest name.
     */
    public static function micalg(string $digest): ?string
    {
        return match ($digest) {
            'sha256' => 'sha-256',
            'sha384' => 'sha-384',
            'sha512' => 'sha-512',
            default => null,
        };
    }

    /**
     * Explicitly-tagged content of a ContentInfo of the expected type.
     */
    private static function content(string $der, string $expectedType): Asn1Node
    {
        $ci = Asn1::parse($der, true, true)->expect(Asn1::TAG_SEQUENCE, true);
        if (Asn1::oid($ci->child(0)) !== $expectedType) {
            throw new ValidationException('malformed', 'CMS: unexpected content type');
        }
        $wrapper = $ci->child(1);
        if (!$wrapper->isContext(0)) {
            throw new ValidationException('malformed', 'CMS: missing [0] content');
        }
        return $wrapper->child(0)->expect(Asn1::TAG_SEQUENCE, true);
    }
}
