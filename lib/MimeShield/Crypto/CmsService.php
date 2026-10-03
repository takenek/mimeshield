<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Crypto;

use MimeShield\Cert\CertPrecheck;
use MimeShield\Cert\Certificate;
use MimeShield\Exception\CryptoException;
use MimeShield\Exception\ValidationException;
use MimeShield\Log;

/**
 * CMS operations on top of PHP's openssl_cms_* functions.
 *
 * All operations work on exact bytes (OPENSSL_CMS_BINARY); MIME canonicalisation is done by the
 * caller. Private keys are passed to OpenSSL as PEM strings (never written to disk). Message data
 * passes through SecureTemp files, which are removed in `finally`.
 */
final class CmsService
{
    public const CIPHER_AES_128_CBC = 'aes-128-cbc';
    public const CIPHER_AES_256_CBC = 'aes-256-cbc';
    public const CIPHER_AES_128_GCM = 'aes-128-gcm';
    public const CIPHER_AES_256_GCM = 'aes-256-gcm';

    public function __construct(private readonly string $tempBaseDir, private readonly bool $includeSmimeCapabilities = false)
    {
    }

    /**
     * Ciphers usable for NEW messages on this PHP build.
     *
     * @return list<string>
     */
    public static function supportedCiphers(): array
    {
        $list = [self::CIPHER_AES_256_CBC, self::CIPHER_AES_128_CBC];
        if (PHP_VERSION_ID >= 80500) {
            // string cipher names (and therefore AuthEnvelopedData/GCM) are accepted from PHP 8.5
            $list[] = self::CIPHER_AES_256_GCM;
            $list[] = self::CIPHER_AES_128_GCM;
        }
        return $list;
    }

    /**
     * Create a detached CMS SignedData (DER) over the exact $content bytes.
     *
     * @param list<string> $chainPems Intermediate certificates to embed (no roots)
     *
     * @return string DER SignedData
     */
    public function signDetached(string $content, Certificate $signer, #[\SensitiveParameter] string $privateKeyPem, array $chainPems = []): string
    {
        $tmp = new SecureTemp($this->tempBaseDir);
        try {
            $in = $tmp->file($content);
            $out = $tmp->file();
            $chainFile = $chainPems !== [] ? $tmp->file(implode("\n", $chainPems)) : null;
            $flags = OPENSSL_CMS_DETACHED | OPENSSL_CMS_BINARY;
            if (!$this->includeSmimeCapabilities) {
                $flags |= OpenSsl::CMS_NOSMIMECAP;
            }
            $certPem = $signer->pem;
            [$ok, $errors] = OpenSsl::run(static fn () => openssl_cms_sign($in, $out, $certPem, $privateKeyPem, null, $flags, OPENSSL_ENCODING_DER, $chainFile));
            if ($ok !== true) {
                OpenSsl::fail('sign', 'signfailed', $errors, ['fingerprint' => $signer->fingerprint]);
            }
            $der = $tmp->read($out);
            if ($der === '') {
                OpenSsl::fail('sign', 'signfailed', ['empty output'], ['fingerprint' => $signer->fingerprint]);
            }
            return $der;
        } finally {
            $tmp->cleanup();
        }
    }

    /**
     * Encrypt $content for the given recipient certificates.
     *
     * @param list<Certificate> $recipients
     *
     * @return string DER EnvelopedData / AuthEnvelopedData
     */
    public function encrypt(string $content, array $recipients, string $cipher = self::CIPHER_AES_256_CBC): string
    {
        if ($recipients === []) {
            // openssl_cms_encrypt() happily produces an undecryptable message with zero recipients
            throw new CryptoException('encryptfailed', 'no recipients');
        }
        if (!in_array($cipher, self::supportedCiphers(), true)) {
            throw new CryptoException('encryptfailed', 'cipher not supported on this PHP version: ' . $cipher);
        }
        $cipherArg = match ($cipher) {
            self::CIPHER_AES_256_CBC => OPENSSL_CIPHER_AES_256_CBC,
            self::CIPHER_AES_128_CBC => OPENSSL_CIPHER_AES_128_CBC,
            default => $cipher, // GCM: string names, PHP >= 8.5 only (checked above)
        };
        $certs = array_map(static fn (Certificate $c) => $c->pem, $recipients);

        $tmp = new SecureTemp($this->tempBaseDir);
        try {
            $in = $tmp->file($content);
            $out = $tmp->file();
            [$ok, $errors] = OpenSsl::run(static fn () => openssl_cms_encrypt($in, $out, $certs, null, OPENSSL_CMS_BINARY, OPENSSL_ENCODING_DER, $cipherArg));
            if ($ok !== true) {
                OpenSsl::fail('encrypt', 'encryptfailed', $errors, ['recipients' => count($certs), 'cipher' => $cipher]);
            }
            $der = $tmp->read($out);
            if ($der === '') {
                OpenSsl::fail('encrypt', 'encryptfailed', ['empty output'], []);
            }
            return $der;
        } finally {
            $tmp->cleanup();
        }
    }

    /**
     * Decrypt EnvelopedData / AuthEnvelopedData with one certificate + key.
     *
     * @return null|string Plaintext MIME entity, or null when the message is not decryptable with this key
     */
    public function decrypt(string $der, Certificate $cert, #[\SensitiveParameter] string $privateKeyPem): ?string
    {
        $type = '';
        try {
            $type = CmsInspector::contentType($der);
        } catch (ValidationException) {
            // not a ContentInfo: refused by the certificate pre-check below
        }
        if ($type === CmsInspector::OID_AUTH_ENVELOPED_DATA) {
            // fail closed: the tag must be verifiable as 12..16 octets (RFC 5084), otherwise refuse
            try {
                $tag = CmsInspector::gcmTagInfo($der);
            } catch (ValidationException $e) {
                throw new CryptoException('malformed', 'AuthEnvelopedData not inspectable: ' . $e->getMessage());
            }
            if ($tag['macLength'] < 12 || $tag['macLength'] > 16 || ($tag['icvLength'] !== null && $tag['icvLength'] !== $tag['macLength'])) {
                throw new CryptoException('unsupportedalgorithm', 'AuthEnvelopedData with truncated authentication tag');
            }
        }
        // OriginatorInfo certificates are parsed by libcrypto during openssl_cms_decrypt: pre-check
        // them (CVE-2026-35189, audit F-16); an unreadable structure or a refused certificate gives an
        // error status instead of an OpenSSL attempt
        try {
            self::assertCertificatesSafe($der);
        } catch (ValidationException $e) {
            throw new CryptoException($e->getUserLabel(), 'decrypt refused before OpenSSL: ' . $e->getMessage());
        }
        $fixed = CmsInspector::fixGcmIcvLength($der);
        if ($fixed !== null) {
            Log::debug('decrypt', 'patched GCMParameters missing aes-ICVlen');
            $der = $fixed;
        }

        // Verify that the private key really belongs to the supplied certificate before CMS
        // decryption. OpenSSL >= 3.2 uses RSA PKCS#1 v1.5 "implicit rejection": with a wrong RSA
        // key it can deliberately derive pseudorandom key material instead of returning a padding
        // error (Bleichenbacher-oracle protection). With unauthenticated CBC content that garbage
        // can occasionally have valid padding and make CMS_decrypt() report success. Do not rely
        // on that return value to detect a mismatched certificate/key pair.
        [$privateKey] = OpenSsl::run(static fn () => openssl_pkey_get_private($privateKeyPem));
        if (!$privateKey instanceof \OpenSSLAsymmetricKey) {
            Log::debug('decrypt', 'private key is unreadable', ['fingerprint' => $cert->fingerprint]);
            return null;
        }
        [$keyMatches] = OpenSsl::run(static fn () => openssl_x509_check_private_key($cert->pem, $privateKey));
        if ($keyMatches !== true) {
            Log::debug('decrypt', 'private key does not match certificate', ['fingerprint' => $cert->fingerprint]);
            return null;
        }

        $tmp = new SecureTemp($this->tempBaseDir);
        try {
            $in = $tmp->file($der);
            $out = $tmp->file();
            $certPem = $cert->pem;
            [$ok, $errors] = OpenSsl::run(static fn () => openssl_cms_decrypt($in, $out, $certPem, $privateKey, OPENSSL_ENCODING_DER));
            if ($ok !== true) {
                // on failure the output file may contain partial/garbage plaintext: discard it
                $tmp->remove($out);
                if (OpenSsl::hasError($errors, 'unsupported') || OpenSsl::hasError($errors, 'cipher initialisation') || OpenSsl::hasError($errors, 'unknown cipher')) {
                    OpenSsl::fail('decrypt', 'unsupportedalgorithm', $errors, ['fingerprint' => $cert->fingerprint]);
                }
                Log::debug('decrypt', 'not decryptable with this key', ['fingerprint' => $cert->fingerprint, 'openssl' => OpenSsl::summarize($errors)]);
                return null;
            }
            return $tmp->read($out);
        } finally {
            $tmp->cleanup();
        }
    }

    /**
     * Verify a detached signature over exact content bytes.
     *
     * Cryptographic verification only (OPENSSL_CMS_NOVERIFY: the certificate chain is evaluated
     * separately by the trust layer, so that "signature valid" and "chain trusted" stay distinct).
     * NOSIGS is never used.
     */
    public function verifyDetached(string $content, string $signatureDer, bool $allowTextCanonicalization = true): SignatureCheck
    {
        $refused = self::refuseUnsafeCertificates($signatureDer);
        if ($refused !== null) {
            return $refused;
        }
        $tmp = new SecureTemp($this->tempBaseDir);
        try {
            $in = $tmp->file($content);
            $sig = $tmp->file($signatureDer);
            $signers = $tmp->file();
            $pk7 = $tmp->file();

            $flags = OPENSSL_CMS_DETACHED | OPENSSL_CMS_BINARY | OPENSSL_CMS_NOVERIFY;
            [$ok, $errors] = OpenSsl::run(static fn () => openssl_cms_verify($in, $flags, $signers, [], null, null, $pk7, $sig, OPENSSL_ENCODING_DER));
            $canonicalized = false;

            if ($ok !== true && $allowTextCanonicalization && self::isContentDigestError($errors)) {
                // the content may have had its line endings converted in transit/storage: OpenSSL text
                // mode canonicalises LF -> CRLF before hashing (RFC 8551 3.1.1 canonical form)
                $flags2 = OPENSSL_CMS_DETACHED | OPENSSL_CMS_NOVERIFY;
                [$ok2, $errors2] = OpenSsl::run(static fn () => openssl_cms_verify($in, $flags2, $signers, [], null, null, $pk7, $sig, OPENSSL_ENCODING_DER));
                if ($ok2 === true) {
                    $ok = true;
                    $canonicalized = true;
                } else {
                    $errors = array_merge($errors, $errors2);
                }
            }

            return $this->buildCheck($ok === true, $errors, $tmp, $signers, $pk7, $signatureDer, null, $canonicalized);
        } finally {
            $tmp->cleanup();
        }
    }

    /**
     * Verify an opaque (encapsulated) SignedData and extract its content.
     */
    public function verifyOpaque(string $der): SignatureCheck
    {
        $refused = self::refuseUnsafeCertificates($der);
        if ($refused !== null) {
            return $refused;
        }
        $tmp = new SecureTemp($this->tempBaseDir);
        try {
            $in = $tmp->file($der);
            $signers = $tmp->file();
            $pk7 = $tmp->file();
            $contentOut = $tmp->file();
            $flags = OPENSSL_CMS_BINARY | OPENSSL_CMS_NOVERIFY;
            [$ok, $errors] = OpenSsl::run(static fn () => openssl_cms_verify($in, $flags, $signers, [], null, $contentOut, $pk7, null, OPENSSL_ENCODING_DER));
            $content = null;
            if ($ok === true) {
                $content = $tmp->read($contentOut);
            }
            return $this->buildCheck($ok === true, $errors, $tmp, $signers, $pk7, $der, $content, false);
        } finally {
            $tmp->cleanup();
        }
    }

    /**
     * Extract the content of an opaque SignedData WITHOUT a valid signature (only used to display a
     * message whose signature is broken, clearly marked as such).
     */
    public function extractOpaqueContent(string $der): ?string
    {
        try {
            $sd = CmsInspector::signedData($der);
            if ($sd['detached']) {
                return null;
            }
            $ci = Asn1::parse($der, true, true);
            $eci = $ci->child(1)->child(0)->child(2);
            $wrapped = $eci->children()[1] ?? null;
            if ($wrapped === null) {
                return null;
            }
            $octets = $wrapped->child(0);
            return $octets->content();
        } catch (ValidationException) {
            return null;
        }
    }

    /**
     * All certificates embedded in a CMS structure (PEM list).
     *
     * @return list<string>
     */
    public static function embeddedCertificates(string $der): array
    {
        try {
            self::assertCertificatesSafe($der);
        } catch (ValidationException) {
            return [];
        }
        $pem = "-----BEGIN CMS-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CMS-----\n";
        $certs = [];
        [$ok] = OpenSsl::run(static function () use ($pem, &$certs) {
            return openssl_cms_read($pem, $certs);
        });
        if ($ok !== true || !is_array($certs)) {
            return [];
        }
        return array_values(array_filter($certs, 'is_string'));
    }

    /**
     * CVE-2026-35189 pre-check (audit F-16 decision 2026-10-03): every certificate a CMS structure
     * carries is checked by CertPrecheck before libcrypto parses it. Fail closed: a structure the
     * plugin's parser cannot read is not handed to OpenSSL either (deliberate; real-world CMS, including
     * BER streamed messages within the size limit, stays within the Asn1 limits).
     *
     * @throws ValidationException
     */
    private static function assertCertificatesSafe(string $der): void
    {
        foreach (CmsInspector::certificateChoices($der)['certificates'] as $certDer) {
            CertPrecheck::assertSafe($certDer);
        }
    }

    /**
     * Invalid (malformed) SignatureCheck without any OpenSSL call when the pre-check refuses the
     * SignedData, null when it may be verified. The message is still displayed, never as validly signed.
     */
    private static function refuseUnsafeCertificates(string $der): ?SignatureCheck
    {
        try {
            self::assertCertificatesSafe($der);
            return null;
        } catch (ValidationException $e) {
            Log::info('verify', 'SignedData refused before OpenSSL: ' . $e->getMessage());
        }
        $info = null;
        try {
            $info = CmsInspector::signedData($der);
        } catch (ValidationException) {
            $info = null;
        }
        return new SignatureCheck(false, SignatureCheck::FAIL_MALFORMED, [], [], $info, null, false);
    }

    /**
     * @param list<string> $errors
     */
    private static function isContentDigestError(array $errors): bool
    {
        return OpenSsl::hasError($errors, 'content verify error') || OpenSsl::hasError($errors, 'verification failure');
    }

    /**
     * @param list<string> $errors
     */
    private function buildCheck(bool $valid, array $errors, SecureTemp $tmp, string $signersFile, string $pk7File, string $cmsDer, ?string $content, bool $canonicalized): SignatureCheck
    {
        $signerPems = Certificate::splitPemBundle($tmp->read($signersFile), 16);
        $embedded = self::embeddedCertificates($cmsDer);

        $info = null;
        try {
            $info = CmsInspector::signedData($cmsDer);
        } catch (ValidationException $e) {
            Log::debug('verify', 'cannot inspect SignedData: ' . $e->getMessage());
        }

        $failure = SignatureCheck::FAIL_NONE;
        if (!$valid) {
            if (self::isContentDigestError($errors)) {
                $failure = SignatureCheck::FAIL_MODIFIED;
            } elseif (OpenSsl::hasError($errors, 'unsupported') || OpenSsl::hasError($errors, 'unknown digest') || OpenSsl::hasError($errors, 'unknown cipher')) {
                $failure = SignatureCheck::FAIL_UNSUPPORTED;
            } elseif (OpenSsl::hasError($errors, 'signer certificate not found') || OpenSsl::hasError($errors, 'no signers')) {
                $failure = SignatureCheck::FAIL_NO_SIGNER;
            } else {
                $failure = SignatureCheck::FAIL_MALFORMED;
            }
            Log::info('verify', 'signature verification failed', ['reason' => $failure, 'openssl' => OpenSsl::summarize($errors)]);
        }

        // when OpenSSL could not write signers (failed verify), try to identify the signer certificate
        // from the embedded certificates and the SignerInfo sid, for display only
        if ($signerPems === [] && $info !== null && isset($info['signers'][0])) {
            $sid = $info['signers'][0]['sid'];
            foreach ($embedded as $pem) {
                try {
                    $c = Certificate::fromString($pem);
                } catch (ValidationException) {
                    continue;
                }
                if ((isset($sid['serial']) && $sid['serial'] === $c->serialHex && $sid['issuer'] === $c->issuerNameDer)
                    || (isset($sid['ski']) && $sid['ski'] === $c->subjectKeyId)) {
                    $signerPems = [$pem];
                    break;
                }
            }
        }

        return new SignatureCheck($valid, $failure, $signerPems, $embedded, $info, $content, $canonicalized);
    }
}
