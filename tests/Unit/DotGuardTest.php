<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Crypto\CmsService;
use MimeShield\Mime\DotGuard;
use MimeShield\Mime\EntityBuilder;
use MimeShield\Mime\SmimeMessage;
use MimeShield\Tests\TestPki;
use PHPUnit\Framework\TestCase;

/**
 * DotGuard against the REAL Net_SMTP 1.12.x string-path DATA chunking (Roundcube vendor tree) and an
 * RFC 5321 4.5.2 receiver (dot-unstuffing).
 */
final class DotGuardTest extends TestCase
{
    private const LINE = 77; // 75 chars + CRLF

    /** Lines of 75 'A' + CRLF; 512000 % 77 = 27, so offset 512000 is mid-line. */
    private static function lines(int $bytes): string
    {
        $line = str_repeat('A', self::LINE - 2) . "\r\n";
        return str_repeat($line, intdiv($bytes, self::LINE) + 1);
    }

    public function testChunkSizeMatchesNetSmtp(): void
    {
        self::assertSame(512000, DotGuard::CHUNK);
        $src = (string) file_get_contents(self::netSmtpFile());
        self::assertStringContainsString('$end = $offset + 512000;', $src);
    }

    public function testMidLineDotAtChunkStartIsRisky(): void
    {
        $d = self::lines(600000);
        self::assertNotSame("\n", $d[511999]);
        $d[512000] = '.';
        self::assertSame([512000], DotGuard::riskyOffsets($d));

        // and it really is corrupted by Net_SMTP + receiver
        self::assertNotSame($d, self::transmit($d));
    }

    public function testDotAtSecondChunkStart(): void
    {
        $d = self::lines(1100000);
        $d[512000] = '.';
        $d[1024000] = '.';
        self::assertSame([512000, 1024000], DotGuard::riskyOffsets($d));
        self::assertNotSame($d, self::transmit($d));

        $d2 = self::lines(1100000);
        $d2[1024000] = '.';
        self::assertSame([1024000], DotGuard::riskyOffsets($d2));
        self::assertNotSame($d2, self::transmit($d2));
    }

    public function testDotAtLineStartAtChunkStartIsSafe(): void
    {
        // a line ends exactly before offset 512000
        $d = str_repeat('X', 512000 - 2) . "\r\n" . ".leading dot line\r\n" . self::lines(1000);
        self::assertSame('.', $d[512000]);
        self::assertSame([], DotGuard::riskyOffsets($d));
        self::assertSame($d, self::transmit($d));
    }

    public function testChunkStartMovedPastLineFeedIsSafe(): void
    {
        // CR at 511999, LF at 512000: Net_SMTP moves the chunk start past the LF, the dot then
        // starts a line and is stuffed correctly
        $d = str_repeat('X', 511999) . "\r\n" . ".after lf\r\n" . self::lines(1000);
        self::assertSame("\n", $d[512000]);
        self::assertSame('.', $d[512001]);
        self::assertSame([], DotGuard::riskyOffsets($d));
        self::assertSame($d, self::transmit($d));
    }

    public function testDotOneByteAfterExactChunkSize(): void
    {
        $d = str_repeat('A', 512000) . ".\r\n";
        self::assertSame([512000], DotGuard::riskyOffsets($d));
        self::assertNotSame($d, self::transmit($d));

        // exactly one chunk: no border at all
        $one = str_repeat('A', 511998) . "\r\n";
        self::assertSame(512000, strlen($one));
        self::assertSame([], DotGuard::riskyOffsets($one));
        self::assertSame($one, self::transmit($one));
    }

    public function testSmallDataNeverRisky(): void
    {
        self::assertSame([], DotGuard::riskyOffsets(''));
        self::assertSame([], DotGuard::riskyOffsets(str_repeat("a.b.c\r\n.x\r\n", 1000)));
    }

    public function testBase64NeverRisky(): void
    {
        $b64 = rtrim(chunk_split(base64_encode(str_repeat(random_bytes(1024), 1500)), 76, "\r\n"), "\r\n") . "\r\n";
        self::assertGreaterThan(2 * 512000, strlen($b64));
        self::assertStringNotContainsString('.', $b64);
        self::assertSame([], DotGuard::riskyOffsets($b64));
        self::assertSame($b64, self::transmit($b64));
    }

    public function testDotsElsewhereDoNotMatter(): void
    {
        $d = self::lines(1100000);
        // dots everywhere except exactly at the two chunk starts
        for ($i = 5; $i < strlen($d); $i += 997) {
            if ($d[$i] === 'A' && $i !== 512000 && $i !== 1024000) {
                $d[$i] = '.';
            }
        }
        self::assertSame([], DotGuard::riskyOffsets($d));
        self::assertSame($d, self::transmit($d));
    }

    /**
     * End to end: a clear-signed SmimeMessage whose wire form has a mid-line '.' at the chunk border is
     * corrupted on the way; padding the preamble until riskyOffsets() is empty makes the transfer
     * byte-exact and the signature valid.
     */
    public function testPadPreambleRemovesCorruptionOfSignedMessage(): void
    {
        if (!MIMESHIELD_RC_LOADED) {
            self::markTestSkipped('needs Roundcube (MIMESHIELD_RC)');
        }
        $base = TestPki::tempDir();
        $work = TestPki::tempDir();
        try {
            $m = new \Mail_mime("\r\n");
            $text = '';
            for ($i = 0; strlen($text) < 640000; $i++) {
                $text .= sprintf("Line %05d: version 1.5 costs 2.50, see example.test/a.b please\r\n", $i);
            }
            $m->setTXTBody($text, false, true);
            $m->setParam('text_encoding', '7bit');
            $m->setParam('text_charset', "US-ASCII;\r\n format=flowed");
            $m->headers([
                'From' => 'Alice <alice@example.test>',
                'To' => 'bob@example.test',
                'Bcc' => 'hidden@example.test',
                'Subject' => 'Big signed message',
                'Message-ID' => '<dotguard@example.test>',
            ]);
            EntityBuilder::prepareOriginal($m, true);
            $inner = EntityBuilder::innerEntity($m);
            $der = (new CmsService($base))->signDetached($inner, TestPki::cert('alice'), TestPki::key('alice'), [TestPki::read('int.crt')]);
            $s = EntityBuilder::clearSigned($inner, $der, 'sha-256');
            $msg = new SmimeMessage($m, ['Content-Type' => $s['contentType']], $s['body'], true, false);

            // what rcube::deliver_message hands to rcube_smtp / Net_SMTP (string path)
            $wire = static fn (): string => (clone $msg)->txtHeaders(['Bcc' => null], true) . "\r\n" . $msg->get();

            // move the last mid-line dot before 512000 exactly onto the chunk border
            $w = $wire();
            self::assertGreaterThan(512000, strlen($w));
            $p = strrpos(substr($w, 0, 512000), '.');
            self::assertIsInt($p);
            self::assertGreaterThan(strpos($w, $inner), $p, 'dot must be inside the signed content');
            self::assertNotSame("\n", $w[$p - 1]);
            $msg->padPreamble(512000 - $p);

            $w = $wire();
            self::assertSame('.', $w[512000]);
            self::assertSame([512000], DotGuard::riskyOffsets($w));
            self::assertStringContainsString($inner, $w);

            $received = self::transmit($w);
            self::assertNotSame($w, $received, 'Net_SMTP chunking must corrupt the unguarded message');
            self::assertStringNotContainsString($inner, $received);
            [$rc, $err] = self::verifyCli($work, $received);
            self::assertNotSame(0, $rc, 'corrupted message must not verify: ' . $err);

            // the guard: pad the preamble one byte at a time until no border is risky
            $pads = 0;
            while (DotGuard::riskyOffsets($w) !== []) {
                $msg->padPreamble(1);
                $w = $wire();
                self::assertLessThan(100, ++$pads);
            }
            self::assertGreaterThan(0, $pads);

            $received = self::transmit($w);
            self::assertSame($w, $received, 'transfer must be byte-exact after padding');
            self::assertStringContainsString($inner, $received);
            [$rc2, $err2] = self::verifyCli($work, $received);
            self::assertSame(0, $rc2, $err2);
            self::assertStringNotContainsString('hidden@example.test', $received);
        } finally {
            self::rmTree($base);
            self::rmTree($work);
        }
    }

    // ------------------------------------------------------------------ helpers

    private static function netSmtpFile(): string
    {
        $rc = getenv('MIMESHIELD_RC');
        $rc = is_string($rc) && $rc !== '' ? rtrim($rc, '/') : '/opt/rcrun/1.7.4';
        $f = $rc . '/vendor/pear/net_smtp/Net/SMTP.php';
        if (!is_file($f)) {
            self::markTestSkipped('Net_SMTP not found at ' . $f);
        }
        return $f;
    }

    private static function loadNetSmtp(): void
    {
        if (class_exists('Net_SMTP', true)) {
            return;
        }
        $vendor = dirname(self::netSmtpFile(), 3);
        set_include_path(implode(PATH_SEPARATOR, [
            $vendor . '/pear-core-minimal/src', $vendor . '/net_socket', $vendor . '/net_smtp', $vendor . '/pear_exception', get_include_path(),
        ]));
        require_once self::netSmtpFile();
    }

    /**
     * Send $data through the real Net_SMTP::data() (string path, as rcube_smtp::send_mail does with a
     * string body) and return what an RFC 5321 receiver stores.
     */
    private static function transmit(string $data): string
    {
        self::loadNetSmtp();
        $smtp = new class ('localhost') extends \Net_SMTP {
            public string $wire = '';

            protected function send($data)
            {
                $this->wire .= $data;
                return strlen($data);
            }

            protected function put($command, $args = '')
            {
                return true;
            }

            protected function parseResponse($valid, $later = false)
            {
                return true;
            }
        };
        $r = $smtp->data($data);
        self::assertTrue($r === true, 'Net_SMTP::data failed');
        $wire = $smtp->wire;

        // receiver: data ends at CRLF.CRLF, a leading dot of every line is removed (RFC 5321 4.5.2)
        self::assertStringEndsWith("\r\n.\r\n", $wire);
        $wire = substr($wire, 0, -3);
        $lines = explode("\r\n", $wire);
        foreach ($lines as $i => $line) {
            if ($line !== '' && $line[0] === '.') {
                $lines[$i] = substr($line, 1);
            }
        }
        return implode("\r\n", $lines);
    }

    /**
     * @return array{0: int, 1: string}
     */
    private static function verifyCli(string $dir, string $message): array
    {
        $f = $dir . '/msg-' . bin2hex(random_bytes(4)) . '.eml';
        file_put_contents($f, $message);
        $p = proc_open(['/usr/bin/openssl', 'cms', '-verify', '-in', $f, '-CAfile', TestPki::path('root.crt'), '-purpose', 'smimesign',
            '-out', '/dev/null'], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($p);
        stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        return [proc_close($p), $err];
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
