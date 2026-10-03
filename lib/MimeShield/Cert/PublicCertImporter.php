<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Cert;

use MimeShield\Crypto\Asn1;
use MimeShield\Crypto\CmsInspector;
use MimeShield\Crypto\OpenSsl;
use MimeShield\Exception\ValidationException;

/**
 * Parses public certificate uploads: PEM (.pem/.crt/.cer), DER (.cer/.crt/.der) and PKCS#7
 * certs-only bundles (.p7b/.p7c, PEM or DER). Returns end-entity and CA certificates separately.
 */
final class PublicCertImporter
{
    public function __construct(private readonly int $maxBytes = 65536, private readonly int $maxCerts = 10)
    {
    }

    /**
     * @return array{entities: list<Certificate>, cas: list<Certificate>}
     */
    public function parse(string $data): array
    {
        if ($data === '') {
            throw new ValidationException('importempty', 'empty upload');
        }
        if (strlen($data) > $this->maxBytes) {
            throw new ValidationException('importtoolarge', 'certificate file too large');
        }
        if (str_contains($data, 'PRIVATE KEY-----')) {
            // never accept (and never store) private keys through the public certificate store
            throw new ValidationException('publiccontainskey', 'upload contains a private key');
        }

        $pems = [];
        if (str_contains($data, '-----BEGIN CERTIFICATE-----')) {
            $pems = Certificate::splitPemBundle($data, $this->maxCerts + 1);
        } elseif (str_contains($data, '-----BEGIN PKCS7-----') || str_contains($data, '-----BEGIN CMS-----')) {
            if (!preg_match('/-----BEGIN (PKCS7|CMS)-----\s*([A-Za-z0-9+\/=\s]+?)\s*-----END \1-----/', $data, $m)) {
                throw new ValidationException('certinvalid', 'bad PKCS#7 PEM');
            }
            $der = base64_decode(preg_replace('/\s+/', '', $m[2]) ?? '', true);
            if ($der === false || $der === '') {
                throw new ValidationException('certinvalid', 'bad PKCS#7 PEM base64');
            }
            $pems = $this->readPkcs7($der);
        } else {
            // DER: a certificate or a PKCS#7 SignedData (certs-only)
            try {
                $root = Asn1::parse($data);
                $first = $root->child(0);
            } catch (ValidationException) {
                throw new ValidationException('certinvalid', 'not a DER structure');
            }
            if ($first->isUniversal(Asn1::TAG_OID)) {
                $pems = $this->readPkcs7($data);
            } else {
                $pems = [Certificate::derToPem($data)];
            }
        }

        if ($pems === []) {
            throw new ValidationException('certinvalid', 'no certificate found');
        }
        if (count($pems) > $this->maxCerts) {
            throw new ValidationException('importtoomany', 'too many certificates in file');
        }

        $entities = [];
        $cas = [];
        foreach ($pems as $pem) {
            $c = Certificate::fromString($pem);
            if ($c->isCa) {
                $cas[] = $c;
            } else {
                $entities[] = $c;
            }
        }
        return ['entities' => $entities, 'cas' => $cas];
    }

    /**
     * Certificates of a PKCS#7 certs-only bundle (DER).
     *
     * @return list<string>
     */
    private function readPkcs7(string $der): array
    {
        // a bundle may hold certificates received from anyone: each one passes the CVE-2026-35189
        // pre-check before openssl_pkcs7_read parses it (audit F-16). Only SignedData is accepted
        // (deliberate: the certificates of other PKCS#7 types could not be pre-checked)
        try {
            $isSigned = CmsInspector::contentType($der) === CmsInspector::OID_SIGNED_DATA;
            $choices = $isSigned ? CmsInspector::certificateChoices($der)['certificates'] : [];
        } catch (ValidationException) {
            throw new ValidationException('certinvalid', 'PKCS#7 bundle unreadable');
        }
        if (!$isSigned) {
            throw new ValidationException('certinvalid', 'PKCS#7 bundle is not SignedData');
        }
        if (count($choices) > $this->maxCerts) {
            throw new ValidationException('importtoomany', 'too many certificates in file');
        }
        foreach ($choices as $certDer) {
            CertPrecheck::assertSafe($certDer);
        }
        $pem = "-----BEGIN PKCS7-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PKCS7-----\n";
        $certs = [];
        [$ok] = OpenSsl::run(static function () use ($pem, &$certs) {
            return openssl_pkcs7_read($pem, $certs);
        });
        if ($ok !== true || !is_array($certs)) {
            throw new ValidationException('certinvalid', 'PKCS#7 bundle unreadable');
        }
        return array_values(array_filter($certs, 'is_string'));
    }
}
