<?php

declare(strict_types=1);

namespace MimeShield\Tests\Integration;

use MimeShield\Crypto\CmsInspector;
use MimeShield\Crypto\CmsService;
use MimeShield\Mime\EntityBuilder;
use MimeShield\Mime\SmimeMessage;
use MimeShield\Tests\TestPki;
use PHPUnit\Framework\TestCase;

/**
 * EntityBuilder + SmimeMessage on real Roundcube Mail_mime objects (built the way rcmail_sendmail does).
 */
final class EntityBuilderTest extends TestCase
{
    private const OPENSSL = '/usr/bin/openssl';

    private const TEXT = "Zażółć gęślą jaźń. \r\nFrom the start of a line\r\n.leading dot\r\nmid.dot and price=5\r\n>From quoted\r\nFrom: not a header\r\n";

    private const HTML = "<html><body><p>Zażółć <img src=\"cid:img1@example.test\"></p>\r\nFrom html line\r\n.dot</body></html>\r\n";

    private const RFC822_8BIT = "From: Inner <inner@example.test>\r\nSubject: inner \xC5\xBC\r\n\r\nFrom the inner body \xC5\xBC.\r\n";

    private string $base;

    private string $work;

    protected function setUp(): void
    {
        if (!MIMESHIELD_RC_LOADED) {
            self::markTestSkipped('needs Roundcube (MIMESHIELD_RC)');
        }
        $this->base = TestPki::tempDir();
        $this->work = TestPki::tempDir();
    }

    protected function tearDown(): void
    {
        if (isset($this->base)) {
            self::rmTree($this->base);
            self::rmTree($this->work);
        }
    }

    /**
     * Mail_mime as created by rcmail_sendmail::create_message() + add_attachments() (HTML compose).
     */
    private static function roundcubeMessage(string $text = self::TEXT, bool $html = true, bool $rfc822 = true): \Mail_mime
    {
        $m = new \Mail_mime("\r\n");
        if ($html) {
            $m->setHTMLBody(self::HTML);
            $m->setTXTBody($text);
            $m->addHTMLImage("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR-binary\n", 'image/png', 'pixel.png', false, 'img1@example.test');
        } else {
            $m->setTXTBody($text, false, true);
        }
        $m->addAttachment("binary\x00\xFF\r\n\n\r.", 'application/octet-stream', 'data.bin', false, 'base64', 'attachment', null, '', '', null, null, '', 'UTF-8');
        if ($rfc822) {
            $m->addAttachment(self::RFC822_8BIT, 'message/rfc822', 'Forwarded message', false, '8bit', 'attachment', null, '', '', null, null, '', 'UTF-8');
        }
        // set_message_encoding(): non-ASCII text => 8bit, format=flowed
        $m->setParam('text_encoding', '8bit');
        $m->setParam('html_encoding', 'quoted-printable');
        $m->setParam('head_encoding', 'quoted-printable');
        $m->setParam('head_charset', 'UTF-8');
        $m->setParam('html_charset', 'UTF-8');
        $m->setParam('text_charset', "UTF-8;\r\n format=flowed");
        $m->headers([
            'Date' => 'Fri, 02 Oct 2026 10:00:00 +0200',
            'From' => 'Alice Żółć <alice@example.test>',
            'To' => 'Bob Łoś <bob@example.test>',
            'Cc' => 'carol@example.test',
            'Bcc' => 'hidden@example.test',
            'Subject' => 'Zażółć gęślą jaźń – test',
            'Message-ID' => '<entity-test@example.test>',
            'User-Agent' => 'Roundcube Webmail/1.7.4',
        ]);
        return $m;
    }

    // ------------------------------------------------------------------ inner entity

    public function testInnerEntityIsCanonicalAndSevenBit(): void
    {
        $m = self::roundcubeMessage();
        EntityBuilder::prepareOriginal($m, true);
        $e = EntityBuilder::innerEntity($m);

        self::assertStringStartsWith('Content-Type: multipart/mixed;', $e);
        self::assertDoesNotMatchRegularExpression('/(?<!\r)\n/', $e, 'bare LF');
        self::assertDoesNotMatchRegularExpression('/\r(?!\n)/', $e, 'bare CR');
        self::assertDoesNotMatchRegularExpression('/[\x80-\xFF]/', $e, '8-bit byte');
        self::assertDoesNotMatchRegularExpression('/[\x00]/', $e, 'NUL byte');
        foreach (explode("\r\n", $e) as $line) {
            self::assertLessThanOrEqual(998, strlen($line));
        }

        $leaves = self::leaves($e);
        $types = array_map(static fn (array $l) => $l['type'], $leaves);
        self::assertSame(['text/plain', 'text/html', 'image/png', 'application/octet-stream', 'application/octet-stream'], $types);

        foreach ($leaves as $leaf) {
            if (str_starts_with($leaf['type'], 'text/')) {
                self::assertSame('quoted-printable', $leaf['cte'], $leaf['type']);
            } else {
                self::assertSame('base64', $leaf['cte'], $leaf['type']);
            }
        }

        // text/plain keeps charset + format=flowed and decodes to the original text
        $plain = $leaves[0];
        self::assertMatchesRegularExpression('/charset=UTF-8;\s+format=flowed/', $plain['headers']);
        self::assertSame(self::TEXT, quoted_printable_decode($plain['body']));
        self::assertSame(self::HTML, quoted_printable_decode($leaves[1]['body']));
        self::assertSame("binary\x00\xFF\r\n\n\r.", base64_decode($leaves[3]['body'], true));

        // Roundcube's own parser accepts it
        $parsed = \rcube_mime::parse_message($e);
        self::assertSame('multipart/mixed', $parsed->mimetype);
        self::assertCount(3, $parsed->parts);
        self::assertSame('multipart/alternative', $parsed->parts[0]->mimetype);
    }

    public function testFromEscapedOnlyInQuotedPrintableParts(): void
    {
        $m = self::roundcubeMessage();
        // a 7bit text attachment with a "From " line: not QP, must stay untouched
        $m->addAttachment("From the attachment\r\nline\r\n", 'text/plain', 'notes.txt', false, '7bit', 'attachment', 'US-ASCII');
        EntityBuilder::prepareOriginal($m, false); // not clear-signed: message/rfc822 stays 8bit
        $e = EntityBuilder::innerEntity($m);

        $leaves = self::leaves($e);
        $seenQp = 0;
        foreach ($leaves as $leaf) {
            $lines = explode("\r\n", $leaf['body']);
            if ($leaf['cte'] === 'quoted-printable') {
                $seenQp++;
                foreach ($lines as $line) {
                    self::assertStringStartsNotWith('From ', $line, $leaf['type']);
                }
                self::assertStringContainsString("\r\n=46rom ", "\r\n" . $leaf['body']);
            }
        }
        self::assertSame(2, $seenQp);

        $byType = [];
        foreach ($leaves as $leaf) {
            $byType[$leaf['type']][] = $leaf;
        }
        // "From:" (with colon) and ">From" lines are not touched
        self::assertStringContainsString("\r\nFrom: not a header", "\r\n" . $byType['text/plain'][0]['body']);
        self::assertStringContainsString("\r\n>From quoted", "\r\n" . $byType['text/plain'][0]['body']);
        // non-QP parts keep their "From " lines
        self::assertStringStartsWith('From the attachment', $byType['text/plain'][1]['body']);
        self::assertSame('7bit', $byType['text/plain'][1]['cte']);
        self::assertSame('8bit', $byType['message/rfc822'][0]['cte']);
        self::assertStringContainsString("\r\nFrom the inner body", $byType['message/rfc822'][0]['body']);
        self::assertStringNotContainsString('=46rom the inner', $e);
        self::assertStringNotContainsString('=46rom the attachment', $e);
    }

    /**
     * Roundcube signatures start with "-- " (QP: "--=20"). The escaper treats every line starting with
     * "--" as a boundary, so "From " lines of a signature block stay unescaped in a QP part.
     */
    public function testFromEscapedAfterSignatureSeparatorInQpPart(): void
    {
        $text = "Hello\r\n-- \r\nFrom Warsaw with love\r\nAlice\r\n";
        $m = self::roundcubeMessage($text, false, false);
        EntityBuilder::prepareOriginal($m, true);
        $e = EntityBuilder::innerEntity($m);
        $plain = self::leaves($e)[0];
        self::assertSame('quoted-printable', $plain['cte']);
        self::assertSame($text, quoted_printable_decode($plain['body']));
        self::assertStringNotContainsString("\r\nFrom Warsaw", "\r\n" . $plain['body'], '"From " line in a QP part left unescaped');
    }

    public function testEightBitRfc822ConvertedToBase64EmlForClearSigning(): void
    {
        $m = self::roundcubeMessage();
        // ASCII-only message/rfc822 is left alone
        $ascii = "From: a@example.test\r\nSubject: ascii\r\n\r\nplain body\r\n";
        $m->addAttachment($ascii, 'message/rfc822', 'ascii.eml', false, '8bit', 'attachment', null, '', '', null, null, '', 'UTF-8');
        EntityBuilder::prepareOriginal($m, true);
        $e = EntityBuilder::innerEntity($m);

        $leaves = self::leaves($e);
        self::assertCount(6, $leaves);
        $converted = $leaves[4];
        self::assertSame('application/octet-stream', $converted['type']);
        self::assertSame('base64', $converted['cte']);
        self::assertMatchesRegularExpression('/filename="?Forwarded message\.eml"?/', $converted['headers']);
        self::assertSame(self::RFC822_8BIT, base64_decode($converted['body'], true));

        self::assertSame('message/rfc822', $leaves[5]['type']);
        self::assertSame('8bit', $leaves[5]['cte']);
        self::assertSame($ascii, $leaves[5]['body']);
        self::assertDoesNotMatchRegularExpression('/[\x80-\xFF]/', $e);

        // not for clear signing (will be encrypted): 8-bit message/rfc822 is kept as is
        $m2 = self::roundcubeMessage();
        EntityBuilder::prepareOriginal($m2, false);
        $e2 = EntityBuilder::innerEntity($m2);
        $l2 = self::leaves($e2);
        self::assertSame('message/rfc822', $l2[4]['type']);
        self::assertStringContainsString("\xC5\xBC", $l2[4]['body']);
    }

    public function testConvert8bitMessagePartsCountAndExistingEmlName(): void
    {
        $m = new \Mail_mime("\r\n");
        $m->setTXTBody('x');
        $m->addAttachment(self::RFC822_8BIT, 'message/rfc822', 'already.EML', false, '8bit');
        $m->addAttachment(self::RFC822_8BIT, 'Message/RFC822', 'second', false, '8bit');
        self::assertSame(2, SmimeMessage::convert8bitMessageParts($m));
        self::assertSame(0, SmimeMessage::convert8bitMessageParts($m));
        $e = EntityBuilder::innerEntity($m);
        self::assertStringContainsString('already.EML', $e);
        self::assertStringNotContainsString('already.EML.eml', $e);
        self::assertStringContainsString('second.eml', $e);
    }

    public function testRepeatedInnerEntityOnFreshCopyIsValid(): void
    {
        $orig = self::roundcubeMessage();
        // Roundcube (or another plugin) may already have serialised the message with 8bit text
        $first = $orig->getMessage();
        self::assertIsString($first);
        self::assertStringContainsString('Content-Transfer-Encoding: 8bit', $first);

        $copy = clone $orig;
        EntityBuilder::prepareOriginal($copy, true);
        $e1 = EntityBuilder::innerEntity($copy);
        $e2 = EntityBuilder::innerEntity($copy);

        foreach ([$e1, $e2] as $e) {
            self::assertDoesNotMatchRegularExpression('/(?<!\r)\n|\r(?!\n)|[\x80-\xFF]/', $e);
            self::assertStringNotContainsString('Content-Transfer-Encoding: 8bit', $e);
            self::assertSame(1, preg_match('/^Content-Type: multipart\/mixed;\r\n boundary="([^"]+)"\r\n\r\n/', $e, $mm));
            // the top-level boundary of the header is the one used in the body
            self::assertStringContainsString("\r\n--" . $mm[1] . "\r\n", $e);
            self::assertStringEndsWith("\r\n--" . $mm[1] . "--\r\n", $e);
            $leaves = self::leaves($e);
            self::assertCount(5, $leaves);
            self::assertSame(self::TEXT, quoted_printable_decode($leaves[0]['body']));
            self::assertSame(self::RFC822_8BIT, base64_decode($leaves[4]['body'], true));
        }
        self::assertSame(substr_count($e1, "\r\n"), substr_count($e2, "\r\n"));
        // the original object was not changed by working on the copy
        self::assertSame('8bit', $orig->getParam('text_encoding'));
    }

    public function testCanonicalizeLineEndings(): void
    {
        self::assertSame("a\r\nb\r\nc\r\n\r\nd\r\n", EntityBuilder::canonicalizeLineEndings("a\nb\rc\r\n\nd\r\n"));
        self::assertSame('', EntityBuilder::canonicalizeLineEndings(''));
    }

    public function testBoundaryHasNoDot(): void
    {
        $seen = [];
        for ($i = 0; $i < 20; $i++) {
            $b = EntityBuilder::boundary();
            self::assertMatchesRegularExpression('/^----MS[0-9a-f]{28}$/', $b);
            $seen[$b] = true;
        }
        self::assertCount(20, $seen);
    }

    // ------------------------------------------------------------------ clear-signed

    public function testClearSignedParsesAndVerifies(): void
    {
        $m = self::roundcubeMessage();
        EntityBuilder::prepareOriginal($m, true);
        $inner = EntityBuilder::innerEntity($m);
        $der = (new CmsService($this->base))->signDetached($inner, TestPki::cert('alice'), TestPki::key('alice'), [TestPki::read('int.crt')]);
        $micalg = CmsInspector::micalg(CmsInspector::signedData($der)['digests'][0]);
        self::assertSame('sha-256', $micalg);

        $s = EntityBuilder::clearSigned($inner, $der, $micalg);
        self::assertSame(1, preg_match('/^multipart\/signed; protocol="application\/pkcs7-signature"; micalg=sha-256; boundary="([^"]+)"$/', $s['contentType'], $mm));
        $b = $mm[1];
        self::assertStringStartsWith(EntityBuilder::PREAMBLE_SIGNED . "\r\n--" . $b . "\r\n", $s['body']);
        self::assertStringEndsWith("\r\n--" . $b . "--\r\n", $s['body']);
        self::assertDoesNotMatchRegularExpression('/(?<!\r)\n|\r(?!\n)|[\x80-\xFF]/', $s['body']);

        // the signed content between the boundaries is the inner entity, byte for byte
        $start = strpos($s['body'], '--' . $b . "\r\n") + strlen('--' . $b . "\r\n");
        $end = strpos($s['body'], "\r\n--" . $b . "\r\n", $start);
        $signedPart = substr($s['body'], $start, $end - $start);
        self::assertSame($inner, $signedPart);
        // ... and the CLI verifies the signature over exactly those bytes (binary, no canonicalisation)
        $partFile = $this->work . '/signed-part.bin';
        $sigFile = $this->work . '/signed-part.p7s';
        file_put_contents($partFile, $signedPart);
        file_put_contents($sigFile, base64_decode(substr($s['body'], (int) strpos($s['body'], "\r\n\r\n", $end) + 4), false));
        $p = proc_open([self::OPENSSL, 'cms', '-verify', '-binary', '-inform', 'DER', '-in', $sigFile, '-content', $partFile,
            '-CAfile', TestPki::path('root.crt'), '-out', '/dev/null'], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($p);
        stream_get_contents($pipes[1]);
        $perr = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        self::assertSame(0, proc_close($p), $perr);

        $full = "MIME-Version: 1.0\r\nFrom: alice@example.test\r\nTo: bob@example.test\r\nSubject: t\r\n"
            . 'Content-Type: ' . EntityBuilder::fold($s['contentType']) . "\r\n\r\n" . $s['body'];

        $parsed = \rcube_mime::parse_message($full);
        self::assertSame('multipart/signed', $parsed->mimetype);
        self::assertSame('application/pkcs7-signature', $parsed->ctype_parameters['protocol']);
        self::assertSame('sha-256', $parsed->ctype_parameters['micalg']);
        self::assertSame($b, $parsed->ctype_parameters['boundary']);
        self::assertCount(2, $parsed->parts);
        self::assertSame('multipart/mixed', $parsed->parts[0]->mimetype);
        self::assertSame('application/pkcs7-signature', $parsed->parts[1]->mimetype);
        self::assertSame($der, $parsed->parts[1]->body);

        // independent verification of the complete message (chain to the test root)
        [$rc, $out, $err] = $this->opensslVerify($full);
        self::assertSame(0, $rc, $err);
        self::assertSame(self::lf($inner), self::lf($out));

        // any change in the signed part breaks it
        $tampered = str_replace('=46rom the start', '=46rom the Start', $full);
        self::assertNotSame($full, $tampered);
        [$rc2] = $this->opensslVerify($tampered);
        self::assertNotSame(0, $rc2);

        // and our own verifier agrees
        $check = (new CmsService($this->base))->verifyDetached($inner, $der);
        self::assertTrue($check->valid);
        self::assertFalse($check->canonicalized);
    }

    public function testClearSignedEntityForEnvelope(): void
    {
        $inner = "Content-Type: text/plain; charset=US-ASCII\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nhi\r\n";
        $der = (new CmsService($this->base))->signDetached($inner, TestPki::cert('bob'), TestPki::key('bob'));
        $entity = EntityBuilder::clearSignedEntity($inner, $der, 'sha-256');
        self::assertMatchesRegularExpression('/^Content-Type: multipart\/signed;\r\n protocol="application\/pkcs7-signature";\r\n micalg=sha-256;\r\n boundary="----MS[0-9a-f]{28}"\r\n\r\n' . preg_quote(EntityBuilder::PREAMBLE_SIGNED, '/') . '\r\n/', $entity);
        $parsed = \rcube_mime::parse_message($entity);
        self::assertSame('multipart/signed', $parsed->mimetype);
        self::assertSame("hi\r\n", $parsed->parts[0]->body);
        [$rc, $out, $err] = $this->opensslVerify("MIME-Version: 1.0\r\n" . $entity);
        self::assertSame(0, $rc, $err);
        self::assertSame(self::lf($inner), self::lf($out));
    }

    public function testEnvelopedHeadersAndBody(): void
    {
        $der = random_bytes(500);
        $env = EntityBuilder::enveloped($der, false);
        self::assertSame([
            'Content-Type' => 'application/pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"',
            'Content-Transfer-Encoding' => 'base64',
            'Content-Disposition' => 'attachment; filename="smime.p7m"',
            'Content-Description' => 'S/MIME Encrypted Message',
        ], $env['headers']);
        self::assertStringEndsWith("\r\n", $env['body']);
        self::assertStringEndsNotWith("\r\n\r\n", $env['body']);
        foreach (explode("\r\n", rtrim($env['body'], "\r\n")) as $line) {
            self::assertMatchesRegularExpression('/^[A-Za-z0-9+\/=]{1,76}$/', $line);
        }
        self::assertSame($der, base64_decode($env['body'], true));

        $auth = EntityBuilder::enveloped($der, true);
        self::assertSame('application/pkcs7-mime; smime-type=authEnveloped-data; name="smime.p7m"', $auth['headers']['Content-Type']);
        self::assertSame($env['body'], $auth['body']);
    }

    // ------------------------------------------------------------------ SmimeMessage

    /**
     * @return array{0: SmimeMessage, 1: string} message + inner entity
     */
    private function signedMessage(): array
    {
        $m = self::roundcubeMessage();
        EntityBuilder::prepareOriginal($m, true);
        $inner = EntityBuilder::innerEntity($m);
        $der = (new CmsService($this->base))->signDetached($inner, TestPki::cert('alice'), TestPki::key('alice'), [TestPki::read('int.crt')]);
        $s = EntityBuilder::clearSigned($inner, $der, 'sha-256');
        return [new SmimeMessage($m, ['Content-Type' => $s['contentType']], $s['body'], true, false), $inner];
    }

    public function testSmimeMessageGetIsPure(): void
    {
        [$msg] = $this->signedMessage();
        $a = $msg->get();
        $b = $msg->get();
        self::assertIsString($a);
        self::assertSame($a, $b);
        self::assertSame($msg->body(), $a);
        self::assertSame($a, $msg->getMessageBody());
        $msg->headers();
        self::assertSame($a, $msg->get());
        self::assertTrue($msg->isSigned());
        self::assertFalse($msg->isEncrypted());
        self::assertFalse($msg->isDraft());
        self::assertTrue($msg->isMultipart());
    }

    public function testSmimeMessageHeaders(): void
    {
        [$msg] = $this->signedMessage();
        $h = $msg->headers();
        self::assertArrayHasKey('Content-Type', $h);
        $ct = (string) preg_replace('/\r\n\s+/', ' ', $h['Content-Type']);
        self::assertMatchesRegularExpression('/^multipart\/signed;\s*protocol="application\/pkcs7-signature";\s*micalg=sha-256;\s*boundary="----MS[0-9a-f]{28}"$/', $ct);
        self::assertArrayNotHasKey('Content-Transfer-Encoding', $h);
        self::assertSame('1.0', $h['MIME-Version']);
        self::assertArrayHasKey('Bcc', $h);
        self::assertStringContainsString('hidden@example.test', $h['Bcc']);

        $txt = $msg->txtHeaders();
        self::assertSame(1, preg_match_all('/^Content-Type:/mi', $txt));
        self::assertMatchesRegularExpression('/^Content-Type: multipart\/signed;/m', $txt);
        self::assertStringContainsString('protocol="application/pkcs7-signature"', $txt);
        self::assertMatchesRegularExpression('/^Subject: =\?UTF-8\?Q\?/m', $txt);
        self::assertMatchesRegularExpression('/^From: =\?UTF-8\?Q\?.*<alice@example\.test>/m', $txt);
        self::assertMatchesRegularExpression('/^Bcc: hidden@example\.test/m', $txt);
        self::assertDoesNotMatchRegularExpression('/[\x80-\xFF]/', $txt);
        self::assertDoesNotMatchRegularExpression('/^Content-Transfer-Encoding:/mi', $txt);
        // the boundary in the header matches the body
        preg_match('/boundary="([^"]+)"/', $txt, $mm);
        self::assertStringContainsString("\r\n--" . $mm[1] . "--\r\n", $msg->get());
    }

    public function testBccRemovedOnCloneOnlyAndByVariant(): void
    {
        [$msg] = $this->signedMessage();
        $smtp = (clone $msg)->txtHeaders(['Bcc' => null], true);
        self::assertDoesNotMatchRegularExpression('/^Bcc:/mi', $smtp);
        self::assertStringNotContainsString('hidden@example.test', $smtp);
        self::assertMatchesRegularExpression('/^Content-Type: multipart\/signed;/m', $smtp);
        // the original still has Bcc (Sent copy)
        self::assertMatchesRegularExpression('/^Bcc: hidden@example\.test/m', $msg->txtHeaders());

        $msg->setBccEnvelopes([['address' => 'hidden@example.test', 'body' => 'x']]);
        $v = $msg->variant();
        self::assertInstanceOf(SmimeMessage::class, $v);
        self::assertArrayNotHasKey('Bcc', $v->headers());
        self::assertSame([], $v->bccEnvelopes());
        self::assertSame($msg->get(), $v->get());
        self::assertArrayHasKey('Bcc', $msg->headers());
        self::assertCount(1, $msg->bccEnvelopes());

        $v2 = $msg->variant("other body\r\n");
        self::assertSame("other body\r\n", $v2->get());
        self::assertNotSame("other body\r\n", $msg->get());
    }

    public function testFullWireMessageVerifiesAndPadPreambleKeepsItValid(): void
    {
        [$msg, $inner] = $this->signedMessage();
        $wire = (clone $msg)->txtHeaders(['Bcc' => null], true) . "\r\n" . $msg->get();
        [$rc, $out, $err] = $this->opensslVerify($wire);
        self::assertSame(0, $rc, $err);
        self::assertSame(self::lf($inner), self::lf($out));

        // Sent copy (getMessage = txtHeaders . CRLF . get) verifies too
        $sent = $msg->getMessage();
        self::assertIsString($sent);
        self::assertStringEndsWith($msg->get(), $sent);
        [$rcS, , $errS] = $this->opensslVerify($sent);
        self::assertSame(0, $rcS, $errS);

        $before = $msg->get();
        $msg->padPreamble(7);
        $after = $msg->get();
        self::assertSame(str_repeat(' ', 7) . $before, $after);
        $wire2 = (clone $msg)->txtHeaders(['Bcc' => null], true) . "\r\n" . $after;
        [$rc2, $out2, $err2] = $this->opensslVerify($wire2);
        self::assertSame(0, $rc2, $err2);
        self::assertSame(self::lf($inner), self::lf($out2));
        $parsed = \rcube_mime::parse_message($wire2);
        self::assertSame('multipart/signed', $parsed->mimetype);
        self::assertCount(2, $parsed->parts);

        $msg->padPreamble(0);
        $msg->padPreamble(-3);
        self::assertSame($after, $msg->get());
    }

    public function testPadPreambleIgnoredForEncrypted(): void
    {
        $m = self::roundcubeMessage();
        EntityBuilder::prepareOriginal($m, false);
        $inner = EntityBuilder::innerEntity($m);
        $cms = new CmsService($this->base);
        $der = $cms->encrypt($inner, [TestPki::cert('bob')]);
        $env = EntityBuilder::enveloped($der, false);
        $msg = new SmimeMessage($m, $env['headers'], $env['body'], true, true);
        $msg->padPreamble(5);
        self::assertSame($env['body'], $msg->get());
        self::assertTrue($msg->isEncrypted());

        $txt = $msg->txtHeaders();
        self::assertMatchesRegularExpression('/^Content-Type: application\/pkcs7-mime;\s+smime-type=enveloped-data;\s+name="?smime\.p7m"?/m', $txt);
        self::assertMatchesRegularExpression('/^Content-Transfer-Encoding: base64\r?$/m', $txt);
        self::assertMatchesRegularExpression('/^Content-Disposition: attachment;\s+filename="?smime\.p7m"?/m', $txt);

        $parsed = \rcube_mime::parse_message($msg->getMessage());
        self::assertSame('application/pkcs7-mime', $parsed->mimetype);
        self::assertSame($der, $parsed->body);
        self::assertSame($inner, $cms->decrypt($der, TestPki::cert('bob'), TestPki::key('bob')));
    }

    public function testDelayFileIoAndEolCannotBeEnabled(): void
    {
        [$msg] = $this->signedMessage();
        self::assertFalse($msg->getParam('delay_file_io'));
        $msg->setParam('delay_file_io', true);
        self::assertFalse($msg->getParam('delay_file_io'));
        $msg->setParam('eol', "\n");
        self::assertSame("\r\n", $msg->getParam('eol'));
        $msg->setParam('head_charset', 'ISO-8859-2');
        self::assertSame('ISO-8859-2', $msg->getParam('head_charset'));
        self::assertFalse(SmimeMessage::buildParam($msg, 'delay_file_io'));

        // even when the original had delay_file_io enabled
        $orig = self::roundcubeMessage();
        $orig->setParam('delay_file_io', true);
        $copy = new SmimeMessage($orig, ['Content-Type' => 'text/plain'], "x\r\n", true, false);
        self::assertFalse($copy->getParam('delay_file_io'));
    }

    public function testGetWithFilenameWritesSameBytes(): void
    {
        [$msg] = $this->signedMessage();
        $file = $this->work . '/body.eml';
        self::assertNull($msg->get(null, $file));
        self::assertSame($msg->get(), file_get_contents($file));

        // appends like Mail_mime (saveMessageBody opens with 'ab')
        file_put_contents($file, "HEAD\r\n");
        self::assertNull($msg->get(null, $file, true));
        self::assertSame("HEAD\r\n" . $msg->get(), file_get_contents($file));

        // resource
        $fh = fopen($this->work . '/res.eml', 'w+b');
        self::assertIsResource($fh);
        self::assertNull($msg->get(null, $fh));
        rewind($fh);
        self::assertSame($msg->get(), stream_get_contents($fh));
        fclose($fh);

        // saveMessageBody() (Roundcube delay_file_io path) writes the same bytes
        $file2 = $this->work . '/saved.eml';
        touch($file2);
        $r = $msg->saveMessageBody($file2);
        self::assertNotInstanceOf(\PEAR_Error::class, $r);
        self::assertSame($msg->get(), file_get_contents($file2));
    }

    // ------------------------------------------------------------------ helpers

    /**
     * Leaf parts of a MIME entity: [type, cte, headers (unfolded), raw body].
     *
     * @return list<array{type: string, cte: string, headers: string, body: string}>
     */
    private static function leaves(string $entity): array
    {
        $pos = strpos($entity, "\r\n\r\n");
        self::assertIsInt($pos, 'no header/body separator');
        $headers = (string) preg_replace('/\r\n[ \t]+/', ' ', substr($entity, 0, $pos));
        $body = substr($entity, $pos + 4);
        self::assertSame(1, preg_match('/^Content-Type:\s*([^;\r\n]+)/mi', $headers, $m), 'no Content-Type: ' . $headers);
        $type = strtolower(trim($m[1]));
        $cte = preg_match('/^Content-Transfer-Encoding:\s*(\S+)/mi', $headers, $c) ? strtolower($c[1]) : '7bit';
        if (!str_starts_with($type, 'multipart/')) {
            return [['type' => $type, 'cte' => $cte, 'headers' => $headers, 'body' => $body]];
        }
        self::assertSame(1, preg_match('/boundary="?([^";\r\n]+)"?/i', $headers, $b), 'no boundary');
        $delim = '--' . $b[1];
        self::assertStringContainsString("\r\n" . $delim . '--', "\r\n" . $body, 'no close delimiter');
        $body = substr("\r\n" . $body, 0, (int) strpos("\r\n" . $body, "\r\n" . $delim . '--'));
        $chunks = explode("\r\n" . $delim . "\r\n", $body);
        array_shift($chunks); // preamble
        self::assertNotEmpty($chunks, 'multipart without parts');
        $out = [];
        foreach ($chunks as $chunk) {
            array_push($out, ...self::leaves($chunk));
        }
        return $out;
    }

    /**
     * @return array{0: int, 1: string, 2: string} exit code, verified content, stderr
     */
    private function opensslVerify(string $message): array
    {
        $in = $this->work . '/msg-' . bin2hex(random_bytes(4)) . '.eml';
        file_put_contents($in, $message);
        $out = $in . '.out';
        // no -binary: the CLI's MIME parser keeps a stray CR before the boundary of CRLF messages in
        // binary mode (it fails on its own -crlfeol output too); the text-mode canonicalisation is a
        // no-op for canonical CRLF content. Byte exactness is checked separately.
        $p = proc_open([self::OPENSSL, 'cms', '-verify', '-in', $in, '-CAfile', TestPki::path('root.crt'),
            '-certfile', TestPki::path('int.crt'), '-purpose', 'smimesign', '-out', $out], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($p);
        fclose($pipes[0]);
        stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $rc = proc_close($p);
        return [$rc, is_file($out) ? (string) file_get_contents($out) : '', $err];
    }

    private static function lf(string $s): string
    {
        return str_replace("\r\n", "\n", $s);
    }

    private static function rmTree(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach ((array) scandir($dir) as $f) {
            if ($f === '.' || $f === '..') {
                continue;
            }
            $p = $dir . '/' . $f;
            is_dir($p) && !is_link($p) ? self::rmTree($p) : @unlink($p);
        }
        @rmdir($dir);
    }
}
