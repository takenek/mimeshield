<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Mime;

use MimeShield\Crypto\CmsInspector;
use MimeShield\Crypto\CmsService;
use MimeShield\Exception\CryptoException;
use MimeShield\Exception\MimeShieldException;
use MimeShield\Exception\ValidationException;
use MimeShield\KeyStore\KeyVault;
use MimeShield\Log;
use MimeShield\Service\KeyService;
use MimeShield\Service\SignatureVerifier;
use MimeShield\Trust\AddressMatcher;
use MimeShield\Trust\VerificationResult;

/**
 * Detects, decrypts and verifies S/MIME in incoming messages (message_part_structure hook).
 *
 * Decrypted content is parsed with Roundcube's own MIME parser and injected into the rcube_message
 * as a NEW part tree (original part objects are never modified, so nothing decrypted can end up in
 * the messages cache). Roundcube then renders it through its standard pipeline (washtml HTML
 * sanitiser, remote content blocking, attachment handling).
 *
 * EFAIL hardening (RFC 8551 section 6, same rule as Thunderbird): only S/MIME at the message root,
 * or directly inside an outer S/MIME layer, is decrypted / treated as covering the message.
 * S/MIME nested in other multiparts or forwarded messages is labelled separately ("partially
 * signed") and is never decrypted.
 */
final class IncomingProcessor
{
    private const MAX_DEPTH = 4;

    private const SIG_TYPES = ['application/pkcs7-signature', 'application/x-pkcs7-signature'];
    private const MIME_TYPES = ['application/pkcs7-mime', 'application/x-pkcs7-mime'];

    /** @var array<string, PartStatus> */
    private array $status = [];

    /** @var array<string, string> injected part id => raw (decrypted / unwrapped) MIME entity (byte buffer only) */
    private array $raw = [];

    /**
     * @var array<string, true> injected part ids whose content comes from the message root (or from
     *                          an S/MIME layer directly at the root). The decision "this part is the
     *                          message root" depends on this origin, never on the fact that bytes were
     *                          unwrapped (a forwarded opaque SignedData is unwrapped too, audit MS-02).
     */
    private array $rootIds = [];

    /** @var array<string, true> part ids of injected (decrypted) content */
    private array $decryptedIds = [];

    /** @var array<string, true> signature attachment part ids to hide */
    private array $hidden = [];

    /** @var null|callable(): \rcube_storage */
    private $storageFactory;

    /** @var array<string, true> first parts of a root multipart/signed (S/MIME directly inside an outer layer) */
    private array $outerChildren = [];

    /** Whether the message root is a single part (root part id '1') */
    private bool $singlePartRoot = false;

    public function __construct(
        private readonly KeyService $keys,
        private readonly CmsService $cms,
        private readonly ?SignatureVerifier $verifier,
        callable $storageFactory,
        private readonly int $maxSize,
        private readonly bool $allowDecrypt = true,
    ) {
        $this->storageFactory = $storageFactory;
    }

    /**
     * message_part_structure handler.
     *
     * @param array<string, mixed> $p
     *
     * @return array<string, mixed>
     */
    public function partStructure(array $p, int $depth = 0): array
    {
        $struct = $p['structure'] ?? null;
        $msg = $p['object'] ?? null;
        if (!$struct instanceof \rcube_message_part || !$msg instanceof \rcube_message || $depth > self::MAX_DEPTH) {
            return $p;
        }
        $mimetype = strtolower((string) ($p['mimetype'] ?? $struct->mimetype));
        if ($depth === 0 && $struct === ($msg->headers->structure ?? null) && empty($struct->parts)) {
            $this->singlePartRoot = true;
        }

        try {
            if (in_array($mimetype, self::MIME_TYPES, true) || $this->isP7mOctetStream($struct, $mimetype)) {
                return $this->handlePkcs7Mime($p, $struct, $msg, $depth);
            }
            if ($mimetype === 'multipart/signed' && $this->isSmimeSigned($struct)) {
                $this->handleSigned($p, $struct, $msg);
                $p = $this->unwrapSignedEnvelope($p, $struct, $msg, $depth);
            }
        } catch (MimeShieldException $e) {
            $st = $this->statusOf((string) $struct->mime_id);
            if ($st->decryption === null && $mimetype !== 'multipart/signed') {
                $st->decryption = $e->getUserLabel();
            } else {
                $st->signatureError = $e->getUserLabel();
            }
            Log::info('incoming', 'S/MIME processing failed: ' . $e->getMessage());
        } catch (\Throwable $e) {
            // never break message display because of a plugin error
            Log::error('incoming', 'unexpected error: ' . get_class($e) . ': ' . $e->getMessage());
            $this->statusOf((string) $struct->mime_id)->signatureError = 'internalerror';
        }

        return $p;
    }

    /**
     * Status for a part or its nearest ancestor with a status.
     */
    public function statusFor(string $partId): ?PartStatus
    {
        $id = $partId;
        while (true) {
            if (isset($this->status[$id])) {
                return $this->status[$id];
            }
            if ($id === '' || $id === '0') {
                // '1' is the root only for single-part messages
                return $this->status['0'] ?? ($this->singlePartRoot ? ($this->status['1'] ?? null) : null);
            }
            $pos = strrpos($id, '.');
            $id = $pos === false ? '0' : substr($id, 0, $pos);
        }
    }

    /**
     * @return array<string, PartStatus>
     */
    public function statuses(): array
    {
        return $this->status;
    }

    /**
     * @return list<string>
     */
    public function hiddenParts(): array
    {
        // array keys like '2' become ints in PHP: always return strings
        return array_map('strval', array_keys($this->hidden));
    }

    public function isDecryptedPart(string $partId): bool
    {
        if (isset($this->decryptedIds[$partId])) {
            return true;
        }
        foreach (array_keys($this->decryptedIds) as $root) {
            if (str_starts_with($partId, $root . '.')) {
                return true;
            }
        }
        return false;
    }

    public function hasDecrypted(): bool
    {
        foreach ($this->status as $s) {
            if ($s->decryption === true) {
                return true;
            }
        }
        return false;
    }

    public function hasSignature(): bool
    {
        foreach ($this->status as $s) {
            if ($s->isSigned()) {
                return true;
            }
        }
        return false;
    }

    private function statusOf(string $id): PartStatus
    {
        return $this->status[$id] ??= new PartStatus($id);
    }

    /**
     * @param array<string, mixed> $p
     */
    private function isRoot(array $p, \rcube_message_part $struct): bool
    {
        $msg = $p['object'];
        return $struct === ($msg->headers->structure ?? null)
            || isset($this->outerChildren[(string) $struct->mime_id])
            || isset($this->rootIds[(string) $struct->mime_id])
            || ($struct->mime_id === '1' && empty($msg->headers->structure->parts));
    }

    private function isP7mOctetStream(\rcube_message_part $struct, string $mimetype): bool
    {
        // Outlook/Exchange sometimes send application/octet-stream + *.p7m (RFC 8551 3.10)
        return $mimetype === 'application/octet-stream'
            && preg_match('/\.p7m$/iD', (string) ($struct->filename ?: ($struct->ctype_parameters['name'] ?? ''))) === 1;
    }

    private function isSmimeSigned(\rcube_message_part $struct): bool
    {
        $protocol = strtolower((string) ($struct->ctype_parameters['protocol'] ?? ''));
        $second = isset($struct->parts[1]) ? strtolower((string) $struct->parts[1]->mimetype) : '';
        return count($struct->parts) === 2 && (in_array($protocol, self::SIG_TYPES, true) || in_array($second, self::SIG_TYPES, true));
    }

    /**
     * @param array<string, mixed> $p
     *
     * @return array<string, mixed>
     */
    private function handlePkcs7Mime(array $p, \rcube_message_part $struct, \rcube_message $msg, int $depth): array
    {
        $id = (string) $struct->mime_id;
        $root = $this->isRoot($p, $struct);
        $st = $this->statusOf($id);

        if ((int) $struct->size > $this->maxSize || (int) ($msg->headers->size ?? 0) > $this->maxSize) {
            throw new ValidationException('messagetoolarge', 'S/MIME part too large');
        }

        if (strtolower((string) $struct->mimetype) === 'message/rfc822' && !$root) {
            // S/MIME forwarded as message/rfc822: BODY[id] is the whole embedded message
            $der = $this->embeddedMessageBody($struct, $msg);
        } else {
            $der = $this->partBytes($struct, $msg);
        }
        if ($der === '') {
            throw new ValidationException('malformed', 'empty S/MIME part');
        }
        if ($der[0] !== "\x30" && preg_match('/^[A-Za-z0-9+\/=\s]+$/D', $der)) {
            // base64 without Content-Transfer-Encoding header
            $der = (string) base64_decode(preg_replace('/\s+/', '', $der) ?? '', true);
        }

        try {
            $type = CmsInspector::contentType($der);
        } catch (ValidationException) {
            throw new ValidationException('malformed', 'not a CMS structure');
        }

        if ($type === CmsInspector::OID_ENVELOPED_DATA || $type === CmsInspector::OID_AUTH_ENVELOPED_DATA) {
            if (!$root || !$this->allowDecrypt) {
                // never decrypt nested / forwarded encrypted parts (EFAIL, decryption oracle)
                $st->notDecrypted = true;
                return $p;
            }
            try {
                $info = CmsInspector::envelopedData($der);
                $st->cipher = $info['cipher'];
            } catch (ValidationException) {
                $info = null;
            }
            $plain = $this->decrypt($der);
            $st->decryption = true;
            $st->unauthenticated = $type === CmsInspector::OID_ENVELOPED_DATA;
            $p = $this->inject($p, $plain, true); // only reached for $root
            // inner layer (typically a clear-signed message) is processed recursively: the hook is
            // not called by Roundcube for the replaced root node
            $inner = $this->partStructure(['object' => $msg, 'structure' => $p['structure'], 'mimetype' => $p['mimetype'], 'recursive' => true], $depth + 1);
            $p['structure'] = $inner['structure'];
            $p['mimetype'] = $inner['mimetype'];
            if (($ist = $this->status[$id] ?? null) !== null && $ist->signature !== null && $ist->signature->cryptoValid()) {
                $st->unauthenticated = false; // integrity protected by the inner signature
            }
            return $p;
        }

        if ($type === CmsInspector::OID_SIGNED_DATA) {
            try {
                $check = $this->cms->verifyOpaque($der);
                $content = $check->content ?? $this->cms->extractOpaqueContent($der);
                if ($this->verifier !== null) {
                    [$from, $sender, $badFrom] = $this->senderAddresses($struct, $msg);
                    $st->signature = $this->verifier->evaluate($check, $from, $sender, !$root, null, $badFrom);
                    $st->partial = !$root;
                } elseif (!$check->valid) {
                    $st->signatureError = 'sig_modified';
                }
            } catch (MimeShieldException $e) {
                $st->signatureError = $e->getUserLabel();
                return $p;
            }
            if ($content === null || $content === '') {
                $st->signatureError ??= 'sig_malformed';
                return $p;
            }
            if (!$root && strtolower((string) $struct->mimetype) !== 'message/rfc822') {
                return $p;
            }
            // signed (not encrypted) content: shown also for forwarded messages, labelled partial;
            // the origin is carried along so that unwrapped forwarded content never becomes a root
            $p = $this->inject($p, $content, $root);
            $inner = $this->partStructure(['object' => $msg, 'structure' => $p['structure'], 'mimetype' => $p['mimetype'], 'recursive' => true], $depth + 1);
            $p['structure'] = $inner['structure'];
            $p['mimetype'] = $inner['mimetype'];
            return $p;
        }

        if ($type === CmsInspector::OID_COMPRESSED_DATA) {
            throw new ValidationException('unsupportedcompressed', 'compressed-data not supported');
        }

        // certs-only or unknown: leave it to Roundcube (shown as attachment)
        return $p;
    }

    /**
     * Verify a clear-signed (multipart/signed) entity. The structure is left as is (Roundcube shows
     * the first part); the smime.p7s part is hidden from the attachment list.
     */
    /**
     * @param array<string, mixed> $p
     */
    private function handleSigned(array $p, \rcube_message_part $struct, \rcube_message $msg): void
    {
        $id = (string) $struct->mime_id;
        $st = $this->statusOf($id);
        // a signed forwarded message (message/rfc822) is a separate origin: never "covers" the message
        $root = $this->isRoot($p, $struct);
        if (isset($struct->parts[1])) {
            $this->hidden[(string) $struct->parts[1]->mime_id] = true;
        }
        if ($this->verifier === null) {
            return; // verification only on show/preview/print
        }
        if ($st->signature !== null) {
            return;
        }

        $boundary = (string) ($struct->ctype_parameters['boundary'] ?? '');
        $body = $this->multipartBody($struct, $msg);
        if ($body === null) {
            $st->signatureError = 'sig_notverifiable';
            $st->partial = true;
            return;
        }
        if ($boundary === '' && preg_match('/^--([^\s]{1,200})[ \t]*\r?$/m', $body, $bm)) {
            // e.g. forwarded message/rfc822: parameters of the embedded entity are not exposed
            $boundary = $bm[1];
        }
        [$content, $sigPart] = self::splitSigned($body, $boundary);
        $sigDer = self::decodeSignaturePart($sigPart);
        $check = $this->cms->verifyDetached($content, $sigDer);
        [$from, $sender, $badFrom] = $this->senderAddresses($struct, $msg);
        $st->partial = !$root;
        $st->signature = $this->verifier->evaluate($check, $from, $sender, !$root, null, $badFrom);
    }

    /**
     * signed(enveloped(...)) - e.g. ESS triple wrapping: when the signed content of a root
     * multipart/signed is itself application/pkcs7-mime, process it as a direct inner S/MIME layer and
     * replace the signed container by the decrypted/unwrapped tree. The outer signature status stays
     * on the container id, the inner status on the inner part id.
     *
     * @param array<string, mixed> $p
     *
     * @return array<string, mixed>
     */
    private function unwrapSignedEnvelope(array $p, \rcube_message_part $struct, \rcube_message $msg, int $depth): array
    {
        $first = $struct->parts[0] ?? null;
        if (!$first instanceof \rcube_message_part || !$this->isRoot($p, $struct)) {
            return $p;
        }
        $ftype = strtolower((string) $first->mimetype);
        if (!in_array($ftype, self::MIME_TYPES, true) && !$this->isP7mOctetStream($first, $ftype)) {
            return $p;
        }
        $this->outerChildren[(string) $first->mime_id] = true;
        $inner = $this->partStructure(['object' => $msg, 'structure' => $first, 'mimetype' => $ftype, 'recursive' => true], $depth + 1);
        if ($inner['structure'] !== $first) {
            $p['structure'] = $inner['structure'];
            $p['mimetype'] = $inner['mimetype'];
        }
        return $p;
    }

    /**
     * Raw body (between the header block and the end) of a multipart/signed part, byte-exact.
     */
    private function multipartBody(\rcube_message_part $struct, \rcube_message $msg): ?string
    {
        $id = (string) $struct->mime_id;
        if (isset($this->raw[$id])) {
            $pos = strpos($this->raw[$id], "\r\n\r\n");
            return $pos === false ? null : substr($this->raw[$id], $pos + 4);
        }
        if ($this->isDecryptedPart($id)) {
            return null; // nested deeper inside decrypted content: raw bytes not available
        }
        // IMAP reports size 0 for multipart nodes: bound the fetch by the message size
        if ((int) $struct->size > $this->maxSize || (int) ($msg->headers->size ?? 0) > $this->maxSize) {
            throw new ValidationException('messagetoolarge', 'signed part too large');
        }
        $storage = $this->storage();
        $storage->set_folder($msg->folder);
        if ($struct === ($msg->headers->structure ?? null) || $id === '0' || $id === '') {
            $section = 'TEXT';
        } elseif (strtolower((string) $struct->mimetype) === 'message/rfc822') {
            $section = $id . '.TEXT';
        } else {
            $section = $id;
        }
        $raw = $storage->get_raw_body($msg->uid, null, $section);
        return is_string($raw) ? $raw : null;
    }

    /**
     * Split the body of a multipart/signed entity (RFC 1847/2046) into the signed content (first
     * part including its MIME headers, without the CRLF preceding the delimiter) and the raw
     * signature part.
     *
     * @return array{0: string, 1: string}
     */
    public static function splitSigned(string $body, string $boundary): array
    {
        if ($boundary === '' || strlen($boundary) > 200) {
            throw new ValidationException('malformed', 'multipart/signed without boundary');
        }
        $delim = '--' . $boundary;
        $q = preg_quote($delim, '/');
        // first delimiter: at the very beginning or after CRLF; transport padding allowed
        if (!preg_match('/(?:^|\r\n)' . $q . '[ \t]*\r\n/', $body, $m, PREG_OFFSET_CAPTURE)) {
            throw new ValidationException('malformed', 'first boundary not found');
        }
        $start = $m[0][1] + strlen($m[0][0]);
        if (!preg_match('/\r\n' . $q . '[ \t]*\r\n/', $body, $m2, PREG_OFFSET_CAPTURE, $start)) {
            throw new ValidationException('malformed', 'second boundary not found');
        }
        $content = substr($body, $start, $m2[0][1] - $start);
        $sigStart = $m2[0][1] + strlen($m2[0][0]);
        if (!preg_match('/\r\n' . $q . '--/', $body, $m3, PREG_OFFSET_CAPTURE, $sigStart)) {
            throw new ValidationException('malformed', 'closing boundary not found');
        }
        $sig = substr($body, $sigStart, $m3[0][1] - $sigStart);
        return [$content, $sig];
    }

    /**
     * Decode the application/pkcs7-signature part into DER.
     */
    public static function decodeSignaturePart(string $part): string
    {
        $pos = strpos($part, "\r\n\r\n");
        $headers = $pos === false ? '' : substr($part, 0, $pos);
        $body = $pos === false ? $part : substr($part, $pos + 4);
        if (preg_match('/^content-transfer-encoding:\s*base64/im', $headers) || !preg_match('/[^A-Za-z0-9+\/=\s]/', $body)) {
            $der = base64_decode((string) preg_replace('/\s+/', '', $body), true);
            if ($der === false || $der === '') {
                throw new ValidationException('malformed', 'bad base64 signature');
            }
            return $der;
        }
        return $body;
    }

    /**
     * Decoded body of a (possibly injected) part.
     */
    private function partBytes(\rcube_message_part $struct, \rcube_message $msg): string
    {
        if (is_string($struct->body) && !empty($struct->body_modified)) {
            return $struct->body; // injected by us: already transfer-decoded
        }
        $storage = $this->storage();
        $storage->set_folder($msg->folder);
        $data = $storage->get_message_part($msg->uid, (string) $struct->mime_id, $struct, null, null, true, 0, false);
        return is_string($data) ? $data : '';
    }

    /**
     * Transfer-decoded body of the S/MIME entity inside a forwarded message/rfc822 part.
     */
    private function embeddedMessageBody(\rcube_message_part $struct, \rcube_message $msg): string
    {
        $storage = $this->storage();
        $storage->set_folder($msg->folder);
        $raw = $storage->get_raw_body($msg->uid, null, (string) $struct->mime_id);
        if (!is_string($raw) || $raw === '' || strlen($raw) > $this->maxSize) {
            return '';
        }
        $part = \rcube_mime::parse_message(EntityBuilder::canonicalizeLineEndings($raw));
        return $part instanceof \rcube_message_part && is_string($part->body) ? $part->body : '';
    }

    private function decrypt(string $der): string
    {
        $candidates = $this->keys->decryptionCandidates($der);
        if ($candidates === []) {
            throw new CryptoException('decrypt_nokeys', 'user has no private keys');
        }
        foreach ($candidates as $rec) {
            try {
                $key = $this->keys->privateKey($rec);
            } catch (CryptoException $e) {
                Log::error('decrypt', 'cannot unwrap private key', ['key_id' => $rec->id()]);
                continue;
            }
            try {
                $plain = $this->cms->decrypt($der, $rec->certificate(), $key);
            } finally {
                KeyVault::wipe($key);
            }
            if ($plain !== null) {
                Log::debug('decrypt', 'message decrypted', ['key_id' => $rec->id()]);
                return $plain;
            }
        }
        throw new CryptoException('decrypt_nokey', 'no matching private key');
    }

    /**
     * Replace the S/MIME part by the parsed (decrypted / unwrapped) entity.
     *
     * @param array<string, mixed> $p
     *
     * @return array<string, mixed>
     */
    private function inject(array $p, string $entity, bool $fromRoot): array
    {
        $entity = EntityBuilder::canonicalizeLineEndings($entity);
        if (strlen($entity) > $this->maxSize) {
            throw new ValidationException('messagetoolarge', 'decrypted content too large');
        }
        $msg = $p['object'];
        $oldStruct = $p['structure'];
        $oldId = (string) $oldStruct->mime_id;

        $new = \rcube_mime::parse_message($entity);
        if (!$new instanceof \rcube_message_part) {
            throw new ValidationException('malformed', 'decrypted content is not MIME');
        }

        foreach (array_keys($msg->mime_parts) as $idx) {
            $idx = (string) $idx;
            if ($oldId === '' || $idx === $oldId || str_starts_with($idx, $oldId . '.')) {
                unset($msg->mime_parts[$idx]);
            }
        }

        $new->size = strlen($entity);
        $this->renumber($new, $msg, $oldId);
        $this->raw[$oldId] = $entity;
        if ($fromRoot) {
            $this->rootIds[$oldId] = true;
        }
        $this->decryptedIds[$oldId] = true;

        $p['structure'] = $new;
        $p['mimetype'] = $new->mimetype;
        return $p;
    }

    private function renumber(\rcube_message_part $part, \rcube_message $msg, string $oldId): void
    {
        $part->mime_id = !$part->mime_id ? $oldId : ($oldId === '' ? $part->mime_id : $oldId . '.' . $part->mime_id);
        $part->body_modified = true;
        $part->encoding = 'stream';
        if (!empty($part->parts)) {
            // containers have no body of their own; never let Roundcube fetch a fake IMAP section
            if ($part->body === null) {
                $part->body = '';
            }
        }
        $msg->mime_parts[$part->mime_id] = $part;
        foreach ($part->parts as $child) {
            $this->renumber($child, $msg, $oldId);
        }
    }

    /**
     * From and Sender addresses for the message (or nested message) containing $struct.
     *
     * @return array{0: list<string>, 1: list<string>, 2: list<string>} from, sender, invalid From entries
     */
    private function senderAddresses(\rcube_message_part $struct, \rcube_message $msg): array
    {
        if (strtolower((string) $struct->mimetype) === 'message/rfc822') {
            $from = (string) ($struct->headers['from'] ?? '');
            $sender = (string) ($struct->headers['sender'] ?? '');
        } else {
            $from = (string) $msg->headers->get('from', false);
            $sender = (string) $msg->headers->get('sender', false);
        }
        // parse exactly as Roundcube displays it (header charset) AND without a charset: any
        // difference between the two readings is treated as an unverifiable sender
        $charset = (string) ($msg->headers->charset ?? '');
        $a = AddressMatcher::parseListStrict($from, true, $charset !== '' ? $charset : null);
        $b = AddressMatcher::parseListStrict($from, true, null);
        $valid = array_values(array_intersect($a['valid'], $b['valid']));
        $invalid = array_values(array_unique(array_merge(
            $a['invalid'], $b['invalid'], array_diff($a['valid'], $b['valid']), array_diff($b['valid'], $a['valid'])
        )));
        return [$valid, AddressMatcher::parseList($sender, true), $invalid];
    }

    private function storage(): \rcube_storage
    {
        return ($this->storageFactory)();
    }

    /**
     * Result for the "save sender certificate" action.
     */
    public function rootSignature(): ?VerificationResult
    {
        foreach (['0', '1'] as $id) {
            if (isset($this->status[$id]) && $this->status[$id]->signature !== null && !$this->status[$id]->partial) {
                return $this->status[$id]->signature;
            }
        }
        return null;
    }
}
