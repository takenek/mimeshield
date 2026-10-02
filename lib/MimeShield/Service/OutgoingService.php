<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Service;

use MimeShield\Cert\Certificate;
use MimeShield\Crypto\CmsInspector;
use MimeShield\Crypto\CmsService;
use MimeShield\Exception\CryptoException;
use MimeShield\Exception\MissingCertificatesException;
use MimeShield\Exception\ValidationException;
use MimeShield\KeyStore\KeyVault;
use MimeShield\Log;
use MimeShield\Mime\EntityBuilder;
use MimeShield\Mime\SmimeMessage;
use MimeShield\Trust\AddressMatcher;

/**
 * Turns Roundcube's outgoing Mail_mime message into a signed and/or encrypted S/MIME message.
 *
 * Order for sign + encrypt: SIGN first (clear-signed multipart/signed), then ENCRYPT the complete
 * signed entity (RFC 8551 3.7; identical to Thunderbird and to Outlook/OWA's default, no triple
 * wrap). Every failure throws: the caller aborts sending (fail closed, never a silent downgrade).
 */
final class OutgoingService
{
    public const DRAFT_HEADER = 'X-MimeShield-Options';

    public function __construct(
        private readonly KeyService $keys,
        private readonly CertificateService $certs,
        private readonly CmsService $cms,
        private readonly string $cipher,
        private readonly bool $encryptToSelf,
        private readonly bool $encryptDrafts,
        private readonly string $bccMode,
        private readonly int $maxMessageSize,
        private readonly int $maxRecipients,
    ) {
    }

    /**
     * @param array{identity_id: int|string, email: string} $identity Identity selected in compose (verified as the user's own)
     */
    public function process(\Mail_mime $message, array $identity, bool $sign, bool $encrypt, bool $draft): ?SmimeMessage
    {
        if ($message instanceof SmimeMessage) {
            throw new ValidationException('conflictotherplugin', 'message already processed');
        }
        $ctype = (string) $message->getParam('ctype');
        if ($ctype !== '' && preg_match('~^(multipart/(encrypted|signed)|application/(x-)?pkcs7-mime)~i', $ctype)) {
            throw new ValidationException('conflictotherplugin', 'message already wrapped by another plugin (' . $ctype . ')');
        }

        if ($draft) {
            return $this->processDraft($message, $identity, $sign, $encrypt);
        }
        if (!$sign && !$encrypt) {
            return null;
        }

        $headers = SmimeMessage::rawHeaders($message);
        $this->assertFromMatchesIdentity($headers, $identity);

        // collect & check recipients BEFORE touching the private key
        $recipientPlan = $encrypt ? $this->planRecipients($headers, $identity) : null;

        EntityBuilder::prepareOriginal($message, $sign && !$encrypt);
        $inner = EntityBuilder::innerEntity($message);
        if (strlen($inner) > $this->maxMessageSize) {
            throw new ValidationException('messagetoolarge', 'message exceeds S/MIME size limit');
        }

        $content = $inner;
        $signedInfo = null;
        if ($sign) {
            $signedInfo = $this->sign($inner, $identity);
            if (!$encrypt) {
                $s = EntityBuilder::clearSigned($inner, $signedInfo['der'], $signedInfo['micalg']);
                $out = new SmimeMessage($message, ['Content-Type' => $s['contentType']], $s['body'], true, false);
                Log::info('send', 'message signed', ['fingerprint' => $signedInfo['fingerprint'], 'digest' => $signedInfo['micalg']]);
                return $out;
            }
            $content = EntityBuilder::clearSignedEntity($inner, $signedInfo['der'], $signedInfo['micalg']);
        }

        // encrypt (main envelope + optional separate Bcc envelopes)
        $gcm = str_contains($this->cipher, 'gcm');
        $der = $this->cms->encrypt($content, $recipientPlan['main'], $this->cipher);
        $env = EntityBuilder::enveloped($der, $gcm);
        $out = new SmimeMessage($message, $env['headers'], $env['body'], $sign, true);

        $bccEnvelopes = [];
        foreach ($recipientPlan['bcc'] as $address => $certs) {
            $bder = $this->cms->encrypt($content, $certs, $this->cipher);
            $bccEnvelopes[] = ['address' => $address, 'body' => EntityBuilder::enveloped($bder, $gcm)['body']];
        }
        $out->setBccEnvelopes($bccEnvelopes);

        Log::info('send', 'message encrypted', [
            'recipients' => count($recipientPlan['main']), 'bcc_envelopes' => count($bccEnvelopes),
            'cipher' => $this->cipher, 'signed' => $sign,
        ]);
        return $out;
    }

    /**
     * Drafts are never signed (a signature would be invalid after the next edit and would need the
     * key on every autosave). With encryption requested they are encrypted to the sender only.
     *
     * @param array{identity_id: int|string, email: string} $identity
     */
    private function processDraft(\Mail_mime $message, array $identity, bool $sign, bool $encrypt): ?SmimeMessage
    {
        $message->headers([self::DRAFT_HEADER => 'sign=' . ($sign ? '1' : '0') . '; encrypt=' . ($encrypt ? '1' : '0')], true);
        if (!$encrypt || !$this->encryptDrafts) {
            return null;
        }
        $self = $this->keys->encryptionCertFor((string) $identity['email'], (int) $identity['identity_id']);
        if ($self === null) {
            throw new ValidationException('draftnoselfcert', 'cannot encrypt draft: no own encryption certificate');
        }
        EntityBuilder::prepareOriginal($message, false);
        $inner = EntityBuilder::innerEntity($message);
        if (strlen($inner) > $this->maxMessageSize) {
            throw new ValidationException('messagetoolarge', 'message exceeds S/MIME size limit');
        }
        $der = $this->cms->encrypt($inner, [$self], $this->cipher);
        $env = EntityBuilder::enveloped($der, str_contains($this->cipher, 'gcm'));
        return new SmimeMessage($message, $env['headers'], $env['body'], false, true, true);
    }

    /**
     * @param array<string, mixed> $headers raw headers
     * @param array{identity_id: int|string, email: string} $identity
     */
    private function assertFromMatchesIdentity(array $headers, array $identity): void
    {
        $from = AddressMatcher::parseList((string) ($headers['From'] ?? ''));
        if (count($from) !== 1 || !AddressMatcher::equals($from[0], (string) $identity['email'])) {
            throw new ValidationException('fromidentitymismatch', 'From header does not match the selected identity');
        }
    }

    /**
     * @param array{identity_id: int|string, email: string} $identity
     *
     * @return array{der: string, micalg: string, fingerprint: string}
     */
    private function sign(string $inner, array $identity): array
    {
        $record = $this->keys->signerFor($identity);
        $cert = $record->certificate();
        $key = $this->keys->privateKey($record);
        try {
            $der = $this->cms->signDetached($inner, $cert, $key, $record->embeddableChain());
        } finally {
            KeyVault::wipe($key);
        }
        $info = CmsInspector::signedData($der);
        $micalg = CmsInspector::micalg($info['digests'][0] ?? '');
        if ($micalg === null) {
            // never emit MD5/SHA-1 signatures
            throw new CryptoException('signfailed', 'unexpected signature digest ' . ($info['digests'][0] ?? '?'));
        }
        return ['der' => $der, 'micalg' => $micalg, 'fingerprint' => $cert->fingerprint];
    }

    /**
     * @param array<string, mixed> $headers
     * @param array{identity_id: int|string, email: string} $identity
     *
     * @return array{main: list<Certificate>, bcc: array<string, list<Certificate>>}
     */
    private function planRecipients(array $headers, array $identity): array
    {
        $to = array_merge(
            AddressMatcher::parseList((string) ($headers['To'] ?? '')),
            AddressMatcher::parseList((string) ($headers['Cc'] ?? ''))
        );
        $bcc = AddressMatcher::parseList((string) ($headers['Bcc'] ?? ''));
        $to = array_values(array_unique($to));
        $bcc = array_values(array_diff(array_unique($bcc), $to));

        if (count($to) + count($bcc) > $this->maxRecipients) {
            throw new ValidationException('toomanyrecipients', 'too many recipients', ['max' => (string) $this->maxRecipients]);
        }
        if ($to === [] && $bcc === []) {
            throw new ValidationException('norecipients', 'no recipients');
        }

        $resolved = $this->certs->resolveRecipients(array_merge($to, $bcc));
        $missing = [];
        foreach ($resolved as $addr => $r) {
            if (!in_array($r['status'], [CertificateService::R_OK, CertificateService::R_UNTRUSTED], true) || $r['cert'] === null) {
                $missing[$addr] = $r['status'] . ($r['detail'] !== '' ? ':' . $r['detail'] : '');
            }
        }
        if ($missing !== []) {
            throw new MissingCertificatesException($missing);
        }

        $self = null;
        if ($this->encryptToSelf) {
            $self = $this->keys->encryptionCertFor((string) $identity['email'], (int) $identity['identity_id']);
            if ($self === null) {
                Log::info('send', 'encrypt-to-self skipped: no own encryption certificate for identity');
            }
        }

        $separate = $this->bccMode === 'separate';
        $main = [];
        foreach (($separate ? $to : array_merge($to, $bcc)) as $addr) {
            $main[$resolved[$addr]['cert']->fingerprint] = $resolved[$addr]['cert'];
        }
        if ($self !== null) {
            $main[$self->fingerprint] = $self;
        }
        if ($main === []) {
            // Bcc only: the main envelope (Sent copy, To: undisclosed) still needs a recipient
            if ($self === null) {
                throw new ValidationException('encryptnoself', 'Bcc-only encrypted message needs an own certificate');
            }
        }

        $bccPlan = [];
        if ($separate) {
            foreach ($bcc as $addr) {
                $set = [$resolved[$addr]['cert']->fingerprint => $resolved[$addr]['cert']];
                if ($self !== null) {
                    $set[$self->fingerprint] = $self;
                }
                $bccPlan[$addr] = array_values($set);
            }
        }

        return ['main' => array_values($main), 'bcc' => $bccPlan];
    }
}
