<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Cert;

use MimeShield\Crypto\OpenSsl;
use MimeShield\Exception\ValidationException;
use MimeShield\Log;

/**
 * Imports a user's certificate + private key from PKCS#12 (.p12/.pfx) or a PEM bundle.
 *
 * The password is used only for this import and never stored; the caller wipes it afterwards.
 * The private key is returned as an UNENCRYPTED PKCS#8 PEM string held in memory only - the caller
 * must immediately wrap it with the KeyVault and wipe the variable.
 */
final class KeyImporter
{
    public function __construct(private readonly int $maxBytes = 102400, private readonly int $minRsaBits = 2048)
    {
    }

    public function import(#[\SensitiveParameter] string $data, #[\SensitiveParameter] string $password): ImportedKey
    {
        if ($data === '') {
            throw new ValidationException('importempty', 'empty upload');
        }
        if (strlen($data) > $this->maxBytes) {
            throw new ValidationException('importtoolarge', 'key file too large');
        }

        if (str_contains($data, '-----BEGIN ')) {
            [$certPems, $keyPem] = $this->readPem($data, $password);
        } else {
            [$certPems, $keyPem] = $this->readPkcs12($data, $password);
        }

        // normalise the key (also validates it)
        [$key, $err] = OpenSsl::run(static fn () => openssl_pkey_get_private($keyPem));
        if (!$key instanceof \OpenSSLAsymmetricKey) {
            throw new ValidationException('keyinvalid', 'private key unreadable: ' . OpenSsl::summarize($err));
        }
        [$details] = OpenSsl::run(static fn () => openssl_pkey_get_details($key));
        if (!is_array($details)) {
            throw new ValidationException('keyinvalid', 'key details unavailable');
        }
        $type = $details['type'] ?? -1;
        if ($type === OPENSSL_KEYTYPE_RSA) {
            if (($details['bits'] ?? 0) < $this->minRsaBits) {
                throw new ValidationException('keytooweak', 'RSA key too small', ['bits' => (string) ($details['bits'] ?? 0)]);
            }
        } elseif ($type === OPENSSL_KEYTYPE_EC) {
            $curve = (string) ($details['ec']['curve_name'] ?? '');
            if (!in_array($curve, ['prime256v1', 'secp384r1', 'secp521r1'], true)) {
                throw new ValidationException('keyunsupported', 'unsupported EC curve ' . $curve);
            }
        } else {
            throw new ValidationException('keyunsupported', 'unsupported key type');
        }

        // locate the end-entity certificate matching the key
        $leaf = null;
        $chain = [];
        foreach ($certPems as $pem) {
            try {
                $c = Certificate::fromString($pem);
            } catch (ValidationException) {
                continue;
            }
            if ($leaf === null && !$c->isCa) {
                $cpem = $c->pem;
                [$match] = OpenSsl::run(static fn () => openssl_x509_check_private_key($cpem, $key));
                if ($match === true) {
                    $leaf = $c;
                    continue;
                }
            }
            $chain[] = $c;
        }

        if ($leaf === null) {
            // either no certificate at all, or none matches the key
            $hasEe = false;
            foreach ($chain as $c) {
                if (!$c->isCa) {
                    $hasEe = true;
                }
            }
            throw new ValidationException($hasEe ? 'keymismatch' : 'importnocert', 'no certificate matching the private key');
        }

        $exported = '';
        [$ok] = OpenSsl::run(static function () use ($key, &$exported) {
            return openssl_pkey_export($key, $exported);
        });
        if ($ok !== true || !is_string($exported) || !str_contains($exported, 'PRIVATE KEY')) {
            throw new ValidationException('keyinvalid', 'cannot export private key');
        }

        // keep only CA certificates of the chain, never the leaf again
        $chain = array_values(array_filter($chain, static fn (Certificate $c) => $c->isCa && $c->fingerprint !== $leaf->fingerprint));

        return new ImportedKey($leaf, $exported, $chain);
    }

    /**
     * @return array{0: list<string>, 1: string}
     */
    private function readPkcs12(#[\SensitiveParameter] string $data, #[\SensitiveParameter] string $password): array
    {
        // reject absurd KDF cost parameters before OpenSSL runs them (CPU DoS), including those
        // hidden inside encrypted SafeContents (decrypted with the password for inspection, MS-05)
        KdfInspector::check($data, 'p12invalid', $password);
        $certs = [];
        [$ok, $errors] = OpenSsl::run(static function () use ($data, &$certs, $password) {
            return openssl_pkcs12_read($data, $certs, $password);
        });
        if ($ok !== true) {
            if (OpenSsl::hasError($errors, 'mac verify failure') || OpenSsl::hasError($errors, 'invalid password')) {
                throw new ValidationException('badpassword', 'PKCS#12 MAC verification failed');
            }
            if (OpenSsl::hasError($errors, 'unsupported') || OpenSsl::hasError($errors, 'unknown cipher') || OpenSsl::hasError($errors, 'pkcs12 cipherfinal')) {
                // MAC was fine (otherwise "mac verify failure"), but a bag uses a legacy cipher (RC2-40)
                Log::info('import', 'PKCS#12 uses a legacy algorithm unsupported by OpenSSL 3 default provider');
                throw new ValidationException('p12legacy', 'PKCS#12 uses legacy cipher');
            }
            throw new ValidationException('p12invalid', 'PKCS#12 unreadable: ' . OpenSsl::summarize($errors));
        }
        if (empty($certs['pkey']) || !is_string($certs['pkey'])) {
            throw new ValidationException('p12nokey', 'PKCS#12 contains no private key');
        }
        $pems = [];
        if (!empty($certs['cert']) && is_string($certs['cert'])) {
            $pems[] = $certs['cert'];
        }
        foreach ((array) ($certs['extracerts'] ?? []) as $x) {
            if (is_string($x)) {
                $pems[] = $x;
            }
            if (count($pems) > 16) {
                break;
            }
        }
        return [$pems, $certs['pkey']];
    }

    /**
     * @return array{0: list<string>, 1: string}
     */
    private function readPem(#[\SensitiveParameter] string $data, #[\SensitiveParameter] string $password): array
    {
        $certPems = Certificate::splitPemBundle($data, 16);
        if (!preg_match('/-----BEGIN ((?:ENCRYPTED |RSA |EC )?PRIVATE KEY)-----.+?-----END \1-----/s', $data, $m)) {
            throw new ValidationException('p12nokey', 'PEM bundle contains no private key');
        }
        $keyPem = $m[0];
        $isEncrypted = str_contains($keyPem, 'ENCRYPTED');
        $blocks = KdfInspector::encryptedPkcs8Blocks($keyPem);
        if ($m[1] === 'ENCRYPTED PRIVATE KEY' && $blocks === []) {
            // never hand an encrypted PKCS#8 key to OpenSSL whose KDF cost was not inspected (F-03)
            throw new ValidationException('keyinvalid', 'encrypted PEM private key not inspectable');
        }
        foreach ($blocks as $der) {
            KdfInspector::check($der, 'keyinvalid');
        }
        $pw = $isEncrypted ? $password : null;
        [$key, $errors] = OpenSsl::run(static fn () => openssl_pkey_get_private($keyPem, $pw));
        if (!$key instanceof \OpenSSLAsymmetricKey) {
            if ($isEncrypted) {
                throw new ValidationException('badpassword', 'cannot decrypt PEM private key');
            }
            throw new ValidationException('keyinvalid', 'PEM private key unreadable: ' . OpenSsl::summarize($errors));
        }
        $exported = '';
        [$ok] = OpenSsl::run(static function () use ($key, &$exported) {
            return openssl_pkey_export($key, $exported);
        });
        if ($ok !== true) {
            throw new ValidationException('keyinvalid', 'cannot export key');
        }
        return [$certPems, $exported];
    }
}
