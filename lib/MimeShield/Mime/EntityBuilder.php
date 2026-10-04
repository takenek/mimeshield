<?php

declare(strict_types=1);

/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Original author: Marek Królikowski (TaKeN)
 * Original project: https://github.com/takenek/mimeshield
 * SPDX-License-Identifier: GPL-3.0-or-later
 * See LICENSE and COPYRIGHT for the license and GPL section 7 attribution terms.
 *
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Mime;

use MimeShield\Exception\CryptoException;

/**
 * Builds the MIME entities of outgoing S/MIME messages (RFC 8551 section 3, RFC 1847).
 *
 *  - inner entity: the message content (Content-Type [+ CTE] headers + body) exactly as it will be
 *    transmitted, canonical: CRLF line endings, all text parts quoted-printable (7-bit safe),
 *    "From " at the start of QP lines escaped as "=46rom " (RFC 2049 section 3);
 *  - clear-signed: multipart/signed; protocol="application/pkcs7-signature"; micalg=...
 *  - enveloped:   application/pkcs7-mime; smime-type=enveloped-data / authEnveloped-data.
 */
final class EntityBuilder
{
    public const PREAMBLE_SIGNED = 'This is an S/MIME cryptographically signed message';

    /**
     * Prepare Roundcube's Mail_mime object so that its serialisation is 7-bit safe.
     */
    public static function prepareOriginal(\Mail_mime $message, bool $forClearSigning): void
    {
        $message->setParam('text_encoding', 'quoted-printable');
        $message->setParam('html_encoding', 'quoted-printable');
        $message->setParam('calendar_encoding', 'quoted-printable');
        $message->setParam('delay_file_io', false);
        if ($forClearSigning) {
            SmimeMessage::convert8bitMessageParts($message);
        }
    }

    /**
     * Serialise the content of $message as a MIME entity (headers + body).
     */
    public static function innerEntity(\Mail_mime $message): string
    {
        SmimeMessage::resetContentHeaders($message);
        $body = $message->get();
        if (!is_string($body) || \Mail_mime::isError($body)) {
            throw new CryptoException('internalerror', 'Mail_mime::get() failed');
        }
        $headers = SmimeMessage::rawHeaders($message);
        $ct = (string) ($headers['Content-Type'] ?? '');
        if ($ct === '') {
            throw new CryptoException('internalerror', 'no Content-Type after get()');
        }
        $entity = 'Content-Type: ' . $ct . "\r\n";
        if (!empty($headers['Content-Transfer-Encoding'])) {
            $entity .= 'Content-Transfer-Encoding: ' . $headers['Content-Transfer-Encoding'] . "\r\n";
        }
        if (!empty($headers['Content-Disposition'])) {
            $entity .= 'Content-Disposition: ' . $headers['Content-Disposition'] . "\r\n";
        }
        $entity .= "\r\n" . $body;

        return self::escapeFromLines(self::canonicalizeLineEndings($entity));
    }

    /**
     * Convert every line ending to CRLF (SMTP does the same to bare CR/LF; signing the converted
     * form guarantees the signed bytes equal the transmitted bytes).
     */
    public static function canonicalizeLineEndings(string $s): string
    {
        return (string) preg_replace('/\r\n|\r|\n/', "\r\n", $s);
    }

    /**
     * Escape "From " at the beginning of lines inside quoted-printable bodies as "=46rom ".
     */
    public static function escapeFromLines(string $entity): string
    {
        if (!str_contains($entity, "\nFrom ") && !str_starts_with($entity, 'From ')) {
            return $entity;
        }
        $lines = explode("\r\n", $entity);
        $state = 'headers';
        $hdr = '';
        $boundaries = []; // boundaries declared by enclosing multipart Content-Type headers
        foreach ($lines as $i => $line) {
            if ($state === 'headers') {
                if ($line === '') {
                    // unfold header lines and remember a declared boundary
                    $unfolded = (string) preg_replace('/\n[ \t]+/', ' ', $hdr);
                    if (preg_match('/^content-type:\s*multipart\/[^\n]*?boundary=(?:"([^"\n]+)"|([^\s;"]+))/im', $unfolded, $m)) {
                        $boundaries[] = $m[1] !== '' ? $m[1] : ($m[2] ?? '');
                    }
                    $state = preg_match('/^content-transfer-encoding:\s*quoted-printable\s*$/imD', $unfolded) ? 'qp' : 'body';
                    $hdr = '';
                } else {
                    $hdr .= $line . "\n";
                }
                continue;
            }
            // leave a body only on a real delimiter line ("--b" or "--b--" of an enclosing boundary);
            // a "-- " signature separator or any other line starting with "--" stays body content
            if (str_starts_with($line, '--') && self::isDelimiter($line, $boundaries)) {
                $state = 'headers';
                $hdr = '';
                continue;
            }
            if ($state === 'qp' && str_starts_with($line, 'From ')) {
                $lines[$i] = '=46rom ' . substr($line, 5);
            }
        }
        return implode("\r\n", $lines);
    }

    /**
     * @param list<string> $boundaries
     */
    private static function isDelimiter(string $line, array $boundaries): bool
    {
        $line = rtrim($line, " \t");
        foreach ($boundaries as $b) {
            if ($b !== '' && ($line === '--' . $b || $line === '--' . $b . '--')) {
                return true;
            }
        }
        return false;
    }

    /**
     * Random boundary without '.' (keeps Net_SMTP dot handling away from boundaries).
     */
    public static function boundary(): string
    {
        return '----MS' . bin2hex(random_bytes(14));
    }

    /**
     * Build the body of a multipart/signed entity.
     *
     * @return array{contentType: string, body: string}
     */
    public static function clearSigned(string $innerEntity, string $signatureDer, string $micalg): array
    {
        $b = self::boundary();
        // the boundary must not occur in the signed content (it is random: practically impossible)
        while (str_contains($innerEntity, $b)) {
            $b = self::boundary();
        }
        $body = self::PREAMBLE_SIGNED . "\r\n"
            . '--' . $b . "\r\n"
            . $innerEntity . "\r\n"
            . '--' . $b . "\r\n"
            . "Content-Type: application/pkcs7-signature; name=\"smime.p7s\"\r\n"
            . "Content-Transfer-Encoding: base64\r\n"
            . "Content-Disposition: attachment; filename=\"smime.p7s\"\r\n"
            . "Content-Description: S/MIME Cryptographic Signature\r\n"
            . "\r\n"
            . rtrim(chunk_split(base64_encode($signatureDer), 76, "\r\n"), "\r\n") . "\r\n"
            . '--' . $b . "--\r\n";

        $ct = 'multipart/signed; protocol="application/pkcs7-signature"; micalg=' . $micalg . '; boundary="' . $b . '"';

        return ['contentType' => $ct, 'body' => $body];
    }

    /**
     * Inner entity of a clear-signed message (used as the content of an envelope for sign+encrypt).
     */
    public static function clearSignedEntity(string $innerEntity, string $signatureDer, string $micalg): string
    {
        $s = self::clearSigned($innerEntity, $signatureDer, $micalg);
        return 'Content-Type: ' . self::fold($s['contentType']) . "\r\n\r\n" . $s['body'];
    }

    /**
     * Top-level headers + body of an application/pkcs7-mime enveloped message.
     *
     * @return array{headers: array<string, string>, body: string}
     */
    public static function enveloped(string $der, bool $authEnveloped): array
    {
        $type = $authEnveloped ? 'authEnveloped-data' : 'enveloped-data';
        return [
            'headers' => [
                'Content-Type' => 'application/pkcs7-mime; smime-type=' . $type . '; name="smime.p7m"',
                'Content-Transfer-Encoding' => 'base64',
                'Content-Disposition' => 'attachment; filename="smime.p7m"',
                'Content-Description' => 'S/MIME Encrypted Message',
            ],
            'body' => rtrim(chunk_split(base64_encode($der), 76, "\r\n"), "\r\n") . "\r\n",
        ];
    }

    /**
     * Fold a header value at "; " boundaries (keeps lines short, values unchanged semantically).
     */
    public static function fold(string $value): string
    {
        return str_replace('; ', ";\r\n ", $value);
    }
}
