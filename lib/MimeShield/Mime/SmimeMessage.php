<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Mime;

/**
 * Immutable-body Mail_mime replacement returned from the message_ready hook.
 *
 * Roundcube calls get() more than once (SMTP, then the Sent/Drafts copy) and Mail_mime would
 * re-encode the message each time with NEW random nested boundaries, which would break any
 * signature. This class serialises the S/MIME body ONCE (in the constructor) and get() always
 * returns exactly those bytes. Top-level content headers come from contentHeaders().
 *
 * delay_file_io is forced off so Roundcube uses Net_SMTP's string path (its file path corrupts
 * data at 8 KB chunk borders).
 */
class SmimeMessage extends \Mail_mime
{
    private string $smimeBody;

    /** @var array<string, string> */
    private array $smimeContentHeaders;

    /** @var list<array{address: string, body: string}> */
    private array $bccEnvelopes = [];

    /**
     * @param array<string, string> $contentHeaders Top-level Content-* headers
     */
    public function __construct(
        \Mail_mime $original,
        array $contentHeaders,
        string $body,
        private readonly bool $signed,
        private readonly bool $encrypted,
        private readonly bool $draft = false,
    ) {
        parent::__construct(['eol' => "\r\n"]);
        foreach (array_keys($this->build_params) as $p) {
            // copy default build params only (NOT 'boundary' / 'ctype')
            $this->build_params[$p] = $original->getParam($p);
        }
        $this->build_params['eol'] = "\r\n";
        $this->build_params['delay_file_io'] = false;
        $this->headers = self::rawHeaders($original);
        unset($this->headers['Content-Type'], $this->headers['Content-Transfer-Encoding'], $this->headers['Content-Disposition']);
        $this->smimeContentHeaders = $contentHeaders;
        $this->smimeBody = $body;
    }

    /**
     * Raw (unencoded) headers of any Mail_mime object.
     *
     * @return array<string, mixed>
     */
    public static function rawHeaders(\Mail_mime $message): array
    {
        return $message->headers;
    }

    /**
     * Replace 8-bit message/rfc822 attachments of $message by base64 application/octet-stream
     * ".eml" attachments. RFC 2045 6.4 forbids QP/base64 for message/*, and 8-bit data inside a
     * clear-signed entity would be altered by relays that downgrade 8bit (Roundcube never declares
     * 8BITMIME). Returns the number of converted parts.
     */
    public static function convert8bitMessageParts(\Mail_mime $message): int
    {
        $n = 0;
        foreach ($message->parts as $i => $part) {
            if (!is_array($part) || strtolower((string) ($part['c_type'] ?? '')) !== 'message/rfc822') {
                continue;
            }
            $data = $part['body'];
            if ($data === null && !empty($part['body_file']) && is_file($part['body_file'])) {
                $data = (string) file_get_contents($part['body_file']);
            }
            if (!is_string($data) || !preg_match('/[\x80-\xFF]/', $data)) {
                continue;
            }
            $name = (string) ($part['name'] ?? 'message.eml');
            if (!preg_match('/\.eml$/iD', $name)) {
                $name .= '.eml';
            }
            $message->parts[$i]['body'] = $data;
            $message->parts[$i]['body_file'] = null;
            $message->parts[$i]['c_type'] = 'application/octet-stream';
            $message->parts[$i]['encoding'] = 'base64';
            $message->parts[$i]['name'] = $name;
            $n++;
        }
        return $n;
    }

    /**
     * Drop (possibly stale) top-level content headers before re-serialising $message.
     */
    public static function resetContentHeaders(\Mail_mime $message): void
    {
        unset($message->headers['Content-Type'], $message->headers['Content-Transfer-Encoding'], $message->headers['Content-Disposition']);
    }

    /**
     * Raw build parameters of any Mail_mime object.
     */
    public static function buildParam(\Mail_mime $message, string $name): mixed
    {
        return $message->build_params[$name] ?? null;
    }

    /**
     * @param null|array<string, mixed> $params
     * @param null|resource|string      $filename
     * @param bool                      $skip_head
     *
     * @return null|string|\PEAR_Error
     */
    #[\Override]
    public function get($params = null, $filename = null, $skip_head = false)
    {
        if ($filename) {
            $fh = is_resource($filename) ? $filename : @fopen($filename, 'ab');
            if (!$fh || fwrite($fh, $this->smimeBody) === false) {
                return self::raiseError('Could not write S/MIME body');
            }
            if (!is_resource($filename)) {
                fclose($fh);
            }
            return null;
        }
        return $this->smimeBody;
    }

    /**
     * @return array<string, string>
     */
    #[\Override]
    protected function contentHeaders()
    {
        return $this->smimeContentHeaders;
    }

    #[\Override]
    public function isMultipart()
    {
        return true;
    }

    #[\Override]
    public function setParam($name, $value)
    {
        if ($name === 'delay_file_io' || $name === 'eol') {
            return; // must stay fixed (see class doc)
        }
        parent::setParam($name, $value);
    }

    public function isSigned(): bool
    {
        return $this->signed;
    }

    public function isEncrypted(): bool
    {
        return $this->encrypted;
    }

    public function isDraft(): bool
    {
        return $this->draft;
    }

    public function body(): string
    {
        return $this->smimeBody;
    }

    /**
     * Separately encrypted copies for Bcc recipients (one envelope per recipient).
     *
     * @param list<array{address: string, body: string}> $envelopes
     */
    public function setBccEnvelopes(array $envelopes): void
    {
        $this->bccEnvelopes = $envelopes;
    }

    /**
     * @return list<array{address: string, body: string}>
     */
    public function bccEnvelopes(): array
    {
        return $this->bccEnvelopes;
    }

    /**
     * A copy of this message without the Bcc header and with another body (Bcc envelopes, main
     * SMTP delivery without Bcc recipients).
     */
    public function variant(?string $body = null): self
    {
        $copy = clone $this;
        if ($body !== null) {
            $copy->smimeBody = $body;
        }
        $copy->bccEnvelopes = [];
        unset($copy->headers['Bcc']);
        return $copy;
    }

    /**
     * Insert $n bytes into the multipart/signed preamble (outside the signed content). Used to move
     * Net_SMTP chunk borders away from mid-line dots. Only valid for clear-signed messages.
     */
    public function padPreamble(int $n): void
    {
        if (!$this->signed || $this->encrypted || $n <= 0) {
            return;
        }
        $this->smimeBody = str_repeat(' ', $n) . $this->smimeBody;
    }
}
