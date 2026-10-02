<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Log;
use MimeShield\Tests\TestPki;
use PHPUnit\Framework\TestCase;

final class LogTest extends TestCase
{
    /** @var list<string> */
    private array $lines = [];

    protected function setUp(): void
    {
        $this->lines = [];
        Log::setSink(function (string $line): void {
            $this->lines[] = $line;
        });
        Log::setDebug(false);
    }

    protected function tearDown(): void
    {
        Log::setDebug(false);
        // restore the bootstrap sink
        Log::setSink(static function (string $line): void {
            $GLOBALS['mimeshield_test_log'][] = $line;
        });
        if (MIMESHIELD_RC_LOADED) {
            \rcube::get_instance()->user = null;
        }
    }

    public function testScalars(): void
    {
        self::assertSame('true', Log::sanitize(true));
        self::assertSame('false', Log::sanitize(false));
        self::assertSame('null', Log::sanitize(null));
        self::assertSame('42', Log::sanitize(42));
        self::assertSame('1.5', Log::sanitize(1.5));
        self::assertSame('plain text', Log::sanitize('plain text'));
        self::assertSame('Zażółć gęślą jaźń', Log::sanitize('Zażółć gęślą jaźń'));
        self::assertSame('stdClass', Log::sanitize(new \stdClass()));
    }

    public function testRedactsPrivateKeyPem(): void
    {
        foreach (['alice.key', 'carol.key', 'alice-bundle-enc.pem', 'alice-bundle.pem'] as $f) {
            $pem = TestPki::read($f);
            self::assertStringContainsString('-----BEGIN', $pem);
            $out = Log::sanitize('key was: ' . $pem . ' end');
            self::assertStringStartsWith('key was: [PEM-REDACTED]', $out, $f);
            self::assertStringNotContainsString('BEGIN', $out);
            self::assertStringNotContainsString('PRIVATE', $out);
            // no line of the base64 body survives
            foreach (preg_split('/\r?\n/', $pem) ?: [] as $line) {
                if (strlen($line) > 20 && !str_starts_with($line, '-----')) {
                    self::assertStringNotContainsString($line, $out, $f);
                }
            }
        }
    }

    public function testRedactsCertificateAndOtherPemBlocks(): void
    {
        $cert = TestPki::read('alice.crt');
        $out = Log::sanitize("a\n" . $cert . "\nb\n" . TestPki::read('int.crl.pem') . 'c');
        self::assertSame('a [PEM-REDACTED]  b [PEM-REDACTED] c', $out); // PEM files end with a newline

        $cms = "-----BEGIN PKCS7-----\nMIIBAAAA\n-----END PKCS7-----";
        self::assertSame('x [PEM-REDACTED] y', Log::sanitize("x $cms y"));
    }

    public function testRedactsUnterminatedPem(): void
    {
        $pem = TestPki::key('alice');
        $half = substr($pem, 0, (int) (strlen($pem) / 2));
        self::assertSame('oops [PEM-REDACTED]', Log::sanitize('oops ' . $half));
    }

    public function testRedactsLongBase64(): void
    {
        $b64 = base64_encode(random_bytes(300));
        $out = Log::sanitize('blob: ' . $b64 . ' tail');
        self::assertSame('blob: [BLOB-REDACTED] tail', $out);

        $hex = bin2hex(random_bytes(80));
        self::assertSame('[BLOB-REDACTED]', Log::sanitize($hex));

        $p12 = base64_encode(TestPki::read('alice.p12'));
        self::assertSame('[BLOB-REDACTED]', Log::sanitize($p12));

        // short tokens (fingerprints, ids) are kept
        $fp = hash('sha256', 'x');
        self::assertSame('fp=' . $fp, Log::sanitize('fp=' . $fp));
    }

    /**
     * Base64 wrapped at 64/76 characters (MIME bodies, PEM bodies without armor, base64 -w76 output)
     * consists of runs shorter than 120 characters separated by line breaks; it should be redacted
     * as well. Today every line survives because the blob regex runs before CR/LF are handled and
     * no single run reaches 120 characters.
     */
    public function testRedactsLineWrappedBase64(): void
    {
        $secret = random_bytes(2048);
        $wrapped = chunk_split(base64_encode($secret), 76, "\r\n");
        $out = Log::sanitize('pkcs12: ' . $wrapped);
        $firstLine = substr($wrapped, 0, 76);
        self::assertStringNotContainsString($firstLine, $out);
        self::assertStringNotContainsString(substr($firstLine, 0, 40), $out);
    }

    public function testRedactsBinary(): void
    {
        self::assertSame('[BINARY-REDACTED]', Log::sanitize("\xff\xfe\x00raw"));
        self::assertSame('[BINARY-REDACTED]', Log::sanitize(TestPki::read('bob.der')));
        $out = Log::sanitize(random_bytes(64) . "\xc3");
        self::assertSame('[BINARY-REDACTED]', $out);
    }

    public function testControlCharactersReplaced(): void
    {
        $out = Log::sanitize("a\rb\nc\td\x1b[31me\x00f\x7fg");
        self::assertSame('a b c d [31me f g', $out);
        self::assertDoesNotMatchRegularExpression('/[\x00-\x1F\x7F]/', $out);
    }

    public function testLogInjectionStaysOneLine(): void
    {
        Log::error("decrypt\nINFO forged", "failed\nERROR keystore: FAKE ENTRY\r\nmore", [
            "ke\ny" => "va\r\nlue\nFAKE ENTRY",
            'user' => 7,
        ]);
        self::assertCount(1, $this->lines);
        $line = $this->lines[0];
        self::assertStringNotContainsString("\n", $line);
        self::assertStringNotContainsString("\r", $line);
        self::assertSame('ERROR decrypt INFO forged: failed ERROR keystore: FAKE ENTRY  more ke y=va  lue FAKE ENTRY user=7', $line);
    }

    public function testTruncation(): void
    {
        $long = str_repeat('word ', 200); // 1000 chars, not base64-like (spaces)
        $out = Log::sanitize($long);
        self::assertSame(303, mb_strlen($out));
        self::assertStringEndsWith('...', $out);
        self::assertSame(substr($long, 0, 300) . '...', $out);

        // multibyte: counted in characters, never cut inside a UTF-8 sequence
        $mb = str_repeat('ż ', 400);
        $out = Log::sanitize($mb);
        self::assertSame(303, mb_strlen($out));
        self::assertTrue(mb_check_encoding($out, 'UTF-8'));

        $exact = str_repeat('ab ', 100);
        self::assertSame($exact, Log::sanitize($exact), 'exactly 300 chars kept');
    }

    public function testArrays(): void
    {
        self::assertSame('[]', Log::sanitize([]));
        self::assertSame('[a, b]', Log::sanitize(['a', 'b']));
        self::assertSame('[k=v, n=1, t=true, z=null]', Log::sanitize(['k' => 'v', 'n' => 1, 't' => true, 'z' => null]));
        self::assertSame('[nested=array, obj=stdClass]', Log::sanitize(['nested' => ['secret' => 'x'], 'obj' => new \stdClass()]));

        $out = Log::sanitize(["ke\ny" => "line\nbreak", 'pem' => trim(TestPki::key('alice'))]);
        self::assertSame('[ke y=line break, pem=[PEM-REDACTED]]', $out);

        $many = Log::sanitize(range(1, 50));
        self::assertSame('[' . implode(', ', range(1, 20)) . ', ...]', $many);
    }

    public function testErrorWritesThroughSinkWithContext(): void
    {
        Log::error('sign', 'signing failed', ['user' => 12, 'fp' => 'ab:cd', 'ok' => false]);
        Log::warning('verify', 'weak digest');
        Log::info('import', 'imported', ['count' => 3]);
        self::assertSame([
            'ERROR sign: signing failed user=12 fp=ab:cd ok=false',
            'WARN verify: weak digest',
            'INFO import: imported count=3',
        ], $this->lines);
    }

    public function testUserContextAddedFromRoundcube(): void
    {
        if (!MIMESHIELD_RC_LOADED) {
            self::markTestSkipped('needs Roundcube (MIMESHIELD_RC)');
        }
        $rc = \rcube::get_instance();
        $user = new \stdClass();
        $user->ID = 42;
        $rc->user = $user;

        Log::error('decrypt', 'failed', ['fp' => 'x']);
        Log::error('decrypt', 'explicit', ['user' => 7]);
        self::assertSame('ERROR decrypt: failed user=42 fp=x', $this->lines[0]);
        self::assertSame('ERROR decrypt: explicit user=7', $this->lines[1], 'explicit user wins, no duplicate');

        $rc->user = null;
        Log::error('decrypt', 'anonymous');
        self::assertSame('ERROR decrypt: anonymous', $this->lines[2]);
    }

    public function testContextValuesAreSanitized(): void
    {
        Log::error('import', 'bad file', ['data' => TestPki::read('alice.p12'), 'key' => trim(TestPki::key('bob'))]);
        self::assertSame('ERROR import: bad file data=[BINARY-REDACTED] key=[PEM-REDACTED]', $this->lines[0]);
    }

    public function testDebugOnlyWhenEnabled(): void
    {
        Log::debug('cms', 'hidden');
        self::assertSame([], $this->lines);
        Log::setDebug(true);
        Log::debug('cms', 'shown', ['n' => 1]);
        self::assertSame(['DEBUG cms: shown n=1'], $this->lines);
        Log::setDebug(false);
        Log::debug('cms', 'hidden again');
        self::assertCount(1, $this->lines);
    }

    public function testSinkNullFallsBackWithoutCrashingCaller(): void
    {
        // with the sink removed, the line goes to Roundcube's log / error_log; redirect error_log to a temp file
        $dir = TestPki::tempDir();
        $logFile = $dir . '/php-error.log';
        $oldLog = ini_set('error_log', $logFile);
        $logDir = null;
        if (MIMESHIELD_RC_LOADED) {
            $cfg = \rcube::get_instance()->config;
            $logDir = [$cfg->get('log_driver'), $cfg->get('log_dir')];
            $cfg->set('log_driver', 'file');
            $cfg->set('log_dir', $dir);
        }
        try {
            Log::setSink(null);
            Log::error('op', "fallback\nline");
        } finally {
            ini_set('error_log', $oldLog === false ? '' : $oldLog);
            if ($logDir !== null) {
                $cfg = \rcube::get_instance()->config;
                $cfg->set('log_driver', $logDir[0]);
                $cfg->set('log_dir', $logDir[1]);
            }
        }
        $written = '';
        foreach (glob($dir . '/*') ?: [] as $f) {
            $written .= (string) file_get_contents($f);
            unlink($f);
        }
        rmdir($dir);
        self::assertStringContainsString('ERROR op: fallback line', $written);
        self::assertStringNotContainsString("fallback\nline", $written);
    }
}
