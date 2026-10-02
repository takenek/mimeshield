<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Cert;

use MimeShield\Crypto\Asn1;
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
            $pems = $this->readPkcs7(str_replace('CMS-----', 'PKCS7-----', $data));
        } else {
            // DER: a certificate or a PKCS#7 SignedData (certs-only)
            try {
                $root = Asn1::parse($data);
                $first = $root->child(0);
            } catch (ValidationException) {
                throw new ValidationException('certinvalid', 'not a DER structure');
            }
            if ($first->isUniversal(Asn1::TAG_OID)) {
                $pem = "-----BEGIN PKCS7-----\n" . chunk_split(base64_encode($data), 64, "\n") . "-----END PKCS7-----\n";
                $pems = $this->readPkcs7($pem);
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
     * @return list<string>
     */
    private function readPkcs7(string $pem): array
    {
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
