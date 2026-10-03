<?php

declare(strict_types=1);

namespace MimeShield\Tests\Integration;

use MimeShield\Cert\Certificate;
use MimeShield\Cert\KeyImporter;
use MimeShield\Cert\PublicCertImporter;
use MimeShield\Crypto\CmsInspector;
use MimeShield\Crypto\CmsService;
use MimeShield\Exception\MimeShieldException;
use MimeShield\Exception\MissingCertificatesException;
use MimeShield\Exception\StorageException;
use MimeShield\Exception\ValidationException;
use MimeShield\KeyStore\KeyVault;
use MimeShield\KeyStore\MasterKeyProvider;
use MimeShield\Mime\DotGuard;
use MimeShield\Mime\SmimeMessage;
use MimeShield\Service\CertificateService;
use MimeShield\Service\KeyService;
use MimeShield\Service\OutgoingService;
use MimeShield\Storage\CertRepository;
use MimeShield\Storage\Database;
use MimeShield\Storage\KeyRepository;
use MimeShield\Tests\TestPki;
use MimeShield\Trust\ChainValidator;
use MimeShield\Trust\RevocationChecker;
use MimeShield\Trust\TrustStore;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Outgoing pipeline end to end, without a web request:
 *
 *   real service graph (rcube_db on SQLite, KeyVault, repositories, KeyService, CertificateService,
 *   CmsService, OutgoingService)
 *   -> Mail_mime built exactly like rcmail_sendmail::create_message()/set_message_encoding() and
 *      send.php add_attachments()
 *   -> OutgoingService::process()
 *   -> delivery emulated like rcube::deliver_message() + rcube_smtp (string path) + the real Net_SMTP
 *      1.12 DATA chunking/quoting + MTA dot-unstuffing, and the Sent copy like
 *      rcmail_sendmail::save_message() + IMAP APPEND line-ending normalisation
 *   -> independent verification with the openssl CLI (cms -verify / cms -decrypt).
 */
final class OutgoingPipelineTest extends TestCase
{
    private const OPENSSL = '/usr/bin/openssl';

    private const ALICE = 1;
    private const BOB = 2;

    private const ID_ALICE = 1;     // alice@example.test
    private const ID_EXPIRED = 2;   // expired@example.test (user alice)
    private const ID_ALIAS = 3;     // alias@example.test   (user alice, no certificate)
    private const ID_BOB = 10;      // bob@example.test

    private string $dir;
    private string $dbFile;
    private \rcube_db $rcdb;
    private Database $db;
    private KeyVault $vault;
    private TrustStore $trust;
    private CmsService $cms;
    private KeyService $aliceKeys;
    private CertificateService $aliceCerts;
    private KeyService $bobKeys;
    private CertificateService $bobCerts;
    private int $aliceKeyId;
    private int $bobKeyId;

    /** @var list<string> */
    private array $tmpFiles = [];

    public static function setUpBeforeClass(): void
    {
        if (!MIMESHIELD_RC_LOADED) {
            self::markTestSkipped('needs MIMESHIELD_RC (Roundcube installation)');
        }
        if (!class_exists('Net_SMTP', false)) {
            require_once RCUBE_INSTALL_PATH . 'vendor/pear/net_smtp/Net/SMTP.php';
        }
    }

    protected function setUp(): void
    {
        $this->dir = TestPki::tempDir();
        $this->dbFile = $this->dir . '/rc.db';

        // the sqlite driver initialises an EMPTY file with the core schema itself
        $this->rcdb = \rcube_db::factory('sqlite:///' . $this->dbFile . '?mode=0600');
        $this->rcdb->set_debug(false);
        $this->rcdb->db_connect('w');
        self::assertNull($this->rcdb->is_error(), 'sqlite connect');
        self::assertTrue((bool) $this->rcdb->exec_script((string) file_get_contents(__DIR__ . '/../../SQL/sqlite.initial.sql')), 'plugin schema');
        $this->db = new Database($this->rcdb);
        self::assertTrue($this->db->isSchemaCurrent());

        $now = Database::now();
        $this->db->query('INSERT INTO ' . $this->db->table('users') . ' (`user_id`, `username`, `mail_host`, `created`) VALUES (?, ?, ?, ?)', self::ALICE, 'alice', 'localhost', $now);
        $this->db->query('INSERT INTO ' . $this->db->table('users') . ' (`user_id`, `username`, `mail_host`, `created`) VALUES (?, ?, ?, ?)', self::BOB, 'bob', 'localhost', $now);
        foreach ([
            [self::ID_ALICE, self::ALICE, 'Alicja Żółć', 'alice@example.test', 1],
            [self::ID_EXPIRED, self::ALICE, 'Expired', 'expired@example.test', 0],
            [self::ID_ALIAS, self::ALICE, 'Alias', 'alias@example.test', 0],
            [self::ID_BOB, self::BOB, 'Bob', 'bob@example.test', 1],
        ] as [$iid, $uid, $name, $email, $std]) {
            $this->db->query(
                'INSERT INTO ' . $this->db->table('identities') . ' (`identity_id`, `user_id`, `changed`, `del`, `standard`, `name`, `email`) VALUES (?, ?, ?, 0, ?, ?, ?)',
                $iid, $uid, $now, $std, $name, $email
            );
        }

        $keyFile = $this->dir . '/master.key';
        file_put_contents($keyFile, "# test master key\n" . MasterKeyProvider::generateLine('k1') . "\n");
        chmod($keyFile, 0400);
        $this->vault = new KeyVault(new MasterKeyProvider($keyFile, ''));
        $this->trust = new TrustStore([TestPki::path('root.crt')], false);
        $this->cms = new CmsService($this->dir);

        [$this->aliceKeys, $this->aliceCerts] = $this->servicesFor(self::ALICE);
        [$this->bobKeys, $this->bobCerts] = $this->servicesFor(self::BOB);

        $r = $this->aliceKeys->import(TestPki::read('alice.p12'), TestPki::PASSWORD, $this->identities(self::ALICE));
        self::assertSame([self::ID_ALICE], $r['bound']);
        $this->aliceKeyId = $r['id'];
        $r = $this->bobKeys->import(TestPki::read('bob.p12'), TestPki::PASSWORD, $this->identities(self::BOB));
        self::assertSame([self::ID_BOB], $r['bound']);
        $this->bobKeyId = $r['id'];

        // alice's correspondents
        foreach (['bob', 'carol', 'mallory'] as $n) {
            $res = $this->aliceCerts->importFile(TestPki::read($n . '.crt') . TestPki::read('int.crt'), false);
            self::assertCount(1, $res['imported'], $n);
            self::assertSame(CertRepository::TRUST_VERIFIED, $res['imported'][0]['trust'], $n);
        }
        // bob's correspondents
        $res = $this->bobCerts->importFile(TestPki::read('alice.crt') . TestPki::read('int.crt'), false);
        self::assertCount(1, $res['imported']);
    }

    protected function tearDown(): void
    {
        if (isset($this->rcdb)) {
            $this->rcdb->closeConnection();
        }
        foreach ($this->tmpFiles as $f) {
            @unlink($f);
        }
        self::rmTree($this->dir);
        $GLOBALS['mimeshield_test_log'] = [];
    }

    // ================================================================== tests: full pipeline

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function pipelineCases(): iterable
    {
        foreach (['plain', 'longlines', 'html', 'related', 'attachments', 'rfc822'] as $s) {
            foreach (['sign', 'encrypt', 'signencrypt'] as $mode) {
                yield $s . '/' . $mode => [$s, $mode];
            }
        }
    }

    #[DataProvider('pipelineCases')]
    public function testPipelineSurvivesSmtpAndSentCopy(string $scenario, string $mode): void
    {
        [$m, $expected] = $this->scenario($scenario);
        $sign = $mode !== 'encrypt';
        $encrypt = $mode !== 'sign';

        $msg = $this->outgoing($this->aliceKeys, $this->aliceCerts)->process($m, $this->aliceIdentity(), $sign, $encrypt, false);
        self::assertInstanceOf(SmimeMessage::class, $msg);
        self::assertSame($sign, $msg->isSigned());
        self::assertSame($encrypt, $msg->isEncrypted());
        self::assertFalse($msg->isDraft());

        // get() is pure: Roundcube calls it for SMTP and again for the Sent copy
        $first = $msg->get();
        self::assertIsString($first);
        self::assertSame($first, $msg->get());
        self::assertSame($first, $msg->get());
        self::assertStringNotContainsString("\r\r", $first);
        self::assertSame(0, preg_match('/(?<!\r)\n|\r(?!\n)/', $first), 'only CRLF line endings in the body');

        $d = $this->deliver($msg);

        // Bcc: never on the wire, kept in the Sent copy
        self::assertNull(self::header($d['wire'], 'Bcc'));
        self::assertSame('mallory@example.test', self::header($d['sent'], 'Bcc'));
        // same body bytes; same header fields (Mail_mime may emit Content-Description at another position
        // in the copy rendered from the SmimeMessage::variant() clone - header order is not significant)
        $sentNoBcc = self::withoutHeader($d['sent'], 'Bcc');
        self::assertSame(self::bodyOf($d['wire']), self::bodyOf($sentNoBcc), 'wire body == Sent body');
        self::assertSame(self::headerLines($d['wire']), self::headerLines($sentNoBcc), 'wire headers == Sent headers minus Bcc');
        if ($mode === 'sign') {
            self::assertSame($d['wire'], $sentNoBcc, 'clear-signed: wire copy == Sent copy minus Bcc, byte for byte');
        }
        self::assertStringContainsString('bob@example.test', (string) self::header($d['wire'], 'To'));
        self::assertStringContainsString('carol@example.test', (string) self::header($d['wire'], 'Cc'));
        self::assertSame('1.0', self::header($d['wire'], 'MIME-Version'));
        self::assertSame('Zażółć gęślą jaźń – test', \rcube_mime::decode_header((string) self::header($d['wire'], 'Subject'), 'UTF-8'));

        if ($mode === 'sign') {
            self::assertStringStartsWith('multipart/signed', (string) self::header($d['wire'], 'Content-Type'));
            self::assertStringContainsString('protocol="application/pkcs7-signature"', (string) self::header($d['wire'], 'Content-Type'));
            // Roundcube never declares 8BITMIME: a clear-signed message must be 7-bit clean
            self::assertSame(0, preg_match('/[\x80-\xFF]/', $d['wire']), 'clear-signed wire copy is 7-bit');
            self::assertSame([], $d['bcc'], 'no Bcc envelopes without encryption');
            foreach (['wire', 'sent'] as $copy) {
                $content = $this->opensslVerify($d[$copy]);
                self::assertNotNull($content, $copy . ' copy must verify with openssl cms -verify');
                $this->assertPayload($content, $expected, true);
            }
            self::assertSame('alice@example.test', $this->signerEmail($d['wire']));
            return;
        }

        $ct = (string) self::header($d['wire'], 'Content-Type');
        self::assertStringStartsWith('application/pkcs7-mime', $ct);
        self::assertStringContainsString('smime-type=enveloped-data', $ct);
        self::assertSame('base64', self::header($d['wire'], 'Content-Transfer-Encoding'));

        // main envelope: To + Cc + sender, never the (separate) Bcc recipient
        $serials = self::recipientSerials($d['wire']);
        sort($serials);
        $exp = [TestPki::cert('alice')->serialHex, TestPki::cert('bob')->serialHex, TestPki::cert('carol')->serialHex];
        sort($exp);
        self::assertSame($exp, $serials);
        self::assertNotContains(TestPki::cert('mallory')->serialHex, $serials);

        foreach (['bob' => 'wire', 'carol' => 'wire', 'alice' => 'sent'] as $who => $copy) {
            $inner = $this->opensslDecrypt($d[$copy], $who);
            self::assertNotNull($inner, $who . ' must decrypt the ' . $copy . ' copy');
            $this->assertInner($inner, $sign, $expected);
        }
        self::assertNull($this->opensslDecrypt($d['wire'], 'mallory'), 'Bcc recipient is not in the main envelope');
        self::assertNotNull($this->opensslDecrypt($d['wire'], 'alice'), 'encrypt-to-self also on the wire copy');

        // separate Bcc envelope for mallory
        self::assertSame(['mallory@example.test'], array_keys($d['bcc']));
        $bccWire = $d['bcc']['mallory@example.test'];
        self::assertNull(self::header($bccWire, 'Bcc'));
        self::assertSame(self::header($d['wire'], 'To'), self::header($bccWire, 'To'));
        $bserials = self::recipientSerials($bccWire);
        sort($bserials);
        $bexp = [TestPki::cert('alice')->serialHex, TestPki::cert('mallory')->serialHex];
        sort($bexp);
        self::assertSame($bexp, $bserials);
        $inner = $this->opensslDecrypt($bccWire, 'mallory');
        self::assertNotNull($inner, 'mallory decrypts her own Bcc envelope');
        $this->assertInner($inner, $sign, $expected);
        self::assertNull($this->opensslDecrypt($bccWire, 'bob'));
        self::assertNull($this->opensslDecrypt($bccWire, 'carol'));
    }

    public function testRealNetSmtpMatchesCopiedChunkingLoop(): void
    {
        // dot at a chunk start in the middle of a line, CRLF exactly around the border, bare LF/CR
        $data = str_repeat('x', 511999) . "\r\n" . '.leading' . "\r\n" . str_repeat('y', 511990) . '.mid' . "\nbare\rcr\r\n";
        self::assertSame(self::netSmtpDataReal($data), self::netSmtpDataCopy($data));
        $data2 = str_repeat('a', 512000) . '.dot-mid-line' . "\r\n";
        self::assertSame(self::netSmtpDataReal($data2), self::netSmtpDataCopy($data2));
        // and the MTA side really corrupts a mid-line dot at the chunk border (why DotGuard exists)
        self::assertNotSame($data2, self::mtaReceive(self::netSmtpDataCopy($data2)));
        self::assertSame([512000], DotGuard::riskyOffsets($data2));
    }

    public function testLargeClearSignedMessageWithDotsSurvivesNetSmtpChunkingWithDotGuard(): void
    {
        // > 512000 bytes of QP text full of mid-line dots: a Net_SMTP chunk border lands on a dot
        $line = rtrim(str_repeat('a.', 34)) . "\r\n";
        $text = 'Kropki/dots: zażółć.' . "\r\n" . str_repeat($line, 9500);

        $found = null;
        for ($attempt = 0; $attempt < 40 && $found === null; $attempt++) {
            $m = $this->buildMessage($this->headers(['Subject' => 'dots ' . str_repeat('x', $attempt), 'Bcc' => null]), $text, false);
            $msg = $this->outgoing($this->aliceKeys, $this->aliceCerts)->process($m, $this->aliceIdentity(), true, false, false);
            self::assertInstanceOf(SmimeMessage::class, $msg);
            $data = (clone $msg)->txtHeaders(['Bcc' => null], true) . "\r\n" . $msg->body();
            if (DotGuard::riskyOffsets($data) !== []) {
                $found = $msg;
            }
        }
        self::assertNotNull($found, 'could not produce a message with a dot at a chunk border');
        $msg = $found;

        // without the guard the signature really breaks on the wire
        $unguarded = self::mtaReceive(self::netSmtpDataCopy((clone $msg)->txtHeaders(['Bcc' => null], true) . "\r\n" . $msg->body()));
        self::assertNull($this->opensslVerify($unguarded), 'unguarded message must be corrupted by Net_SMTP chunking');

        // the real mimeshield::message_before_send hook pads the message (audit F-11: the hook itself,
        // not a copy of its loop)
        $hooked = self::messageBeforeSend($msg);
        self::assertArrayNotHasKey('abort', $hooked);
        self::assertSame($msg, $hooked['message']);
        self::assertSame([], DotGuard::riskyOffsets(self::smtpString($msg)));

        // with the plugin's message_before_send guard it verifies (wire and Sent copy)
        $d = $this->deliver($msg);
        self::assertSame([], DotGuard::riskyOffsets(self::smtpString($msg)));
        foreach (['wire', 'sent'] as $copy) {
            $content = $this->opensslVerify($d[$copy]);
            self::assertNotNull($content, $copy);
            $leaves = self::leaves(self::crlf($content));
            self::assertSame(rtrim($m->getTXTBody(), "\r\n"), rtrim($leaves[0]['data'], "\r\n"));
        }
    }

    /**
     * Audit F-11: when padding cannot move the chunk border off a dot, the real
     * mimeshield::message_before_send hook refuses to send (fail closed) instead of letting Net_SMTP
     * change the signed bytes.
     */
    public function testMessageBeforeSendHookBlocksAPayloadThatCannotBeMadeTransportSafe(): void
    {
        $line = rtrim(str_repeat('a.', 34)) . "\r\n";
        $text = 'Kropki/dots: zażółć.' . "\r\n" . str_repeat($line, 9500);
        $found = null;
        for ($attempt = 0; $attempt < 40 && $found === null; $attempt++) {
            $m = $this->buildMessage($this->headers(['Subject' => 'dots ' . str_repeat('x', $attempt), 'Bcc' => null]), $text, false);
            $msg = $this->outgoing($this->aliceKeys, $this->aliceCerts)->process($m, $this->aliceIdentity(), true, false, false);
            self::assertInstanceOf(SmimeMessage::class, $msg);
            if (DotGuard::riskyOffsets(self::smtpString($msg)) !== []) {
                $found = [$m, $msg];
            }
        }
        self::assertNotNull($found, 'could not produce a message with a dot at a chunk border');
        [$m, $msg] = $found;
        $contentHeaders = (new \ReflectionProperty(SmimeMessage::class, 'smimeContentHeaders'))->getValue($msg);
        // the same signed message, but padding has no effect (stands for a payload no padding fixes)
        $stuck = new class ($m, $contentHeaders, $msg->body(), true, false) extends SmimeMessage {
            public function padPreamble(int $n): void
            {
            }
        };
        self::assertNotSame([], DotGuard::riskyOffsets(self::smtpString($stuck)));

        $hooked = self::messageBeforeSend($stuck);

        self::assertTrue($hooked['abort'] ?? false, 'unsafe signed payload must not be sent');
        self::assertFalse($hooked['result']);
        self::assertSame('mimeshield.internalerror', $hooked['error']['label'] ?? null);
    }

    /**
     * I-07 (Stage 6 pass 05): when the Bcc envelopes were delivered and the main delivery then fails,
     * the real message_send_error hook replaces the generic SMTP error with a message telling the user
     * that the Bcc recipients already have the message; without delivered envelopes nothing changes.
     */
    public function testMainDeliveryFailureAfterBccEnvelopesIsReported(): void
    {
        [$m] = $this->scenario('plain');
        $msg = $this->outgoing($this->aliceKeys, $this->aliceCerts)->process($m, $this->aliceIdentity(), false, true, false);
        self::assertInstanceOf(SmimeMessage::class, $msg);
        self::assertNotSame([], $msg->bccEnvelopes());

        require_once dirname(__DIR__, 2) . '/mimeshield.php';
        $rc = (new \ReflectionClass(\rcmail::class))->newInstanceWithoutConstructor();
        $rc->smtp = new class () {
            /** @var list<string> */
            public array $to = [];

            public function send_mail(string $from, array $to, string $headers, string $body, array $options = []): bool
            {
                array_push($this->to, ...$to);
                return true;
            }
        };
        $plugin = (new \ReflectionClass(\mimeshield::class))->newInstanceWithoutConstructor();
        (new \ReflectionProperty(\mimeshield::class, 'rc'))->setValue($plugin, $rc);
        (new \ReflectionProperty(\mimeshield::class, 'expect'))->setValue($plugin, ['sign' => false, 'encrypt' => true]);
        $smtpError = ['error' => ['label' => 'smtperror', 'vars' => ['msg' => 'x']]];

        // nothing delivered yet: the core error is kept
        self::assertSame($smtpError['error'], $plugin->message_send_error($smtpError)['error']);

        $p = $plugin->message_before_send(['message' => $msg, 'from' => 'alice@example.test', 'mailto' => ['bob@example.test']]);
        self::assertEmpty($p['abort'] ?? false, 'main delivery is left to Roundcube');
        self::assertSame(array_column($msg->bccEnvelopes(), 'address'), $rc->smtp->to, 'only the Bcc envelopes went out');

        $before = count($GLOBALS['mimeshield_test_log'] ?? []);   // bootstrap log sink
        $error = $plugin->message_send_error($smtpError + ['message' => $p['message']])['error'];
        self::assertSame(['label' => 'mimeshield.bccmainsendfailed', 'vars' => []], $error);
        self::assertStringContainsString('main delivery failed after the Bcc envelopes', (string) end($GLOBALS['mimeshield_test_log']));
        self::assertSame($before + 1, count($GLOBALS['mimeshield_test_log']));
    }

    /**
     * Run the real mimeshield::message_before_send hook for a clear-signed send (no Bcc envelopes).
     *
     * @return array<string, mixed>
     */
    private static function messageBeforeSend(SmimeMessage $msg): array
    {
        require_once dirname(__DIR__, 2) . '/mimeshield.php';
        $plugin = (new \ReflectionClass(\mimeshield::class))->newInstanceWithoutConstructor();
        (new \ReflectionProperty(\mimeshield::class, 'expect'))->setValue($plugin, ['sign' => true, 'encrypt' => false]);
        self::assertSame([], $msg->bccEnvelopes());
        return $plugin->message_before_send(['message' => $msg, 'from' => 'alice@example.test', 'mailto' => ['bob@example.test']]);
    }

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function ciphers(): iterable
    {
        foreach (CmsService::supportedCiphers() as $c) {
            yield $c => [$c];
        }
    }

    #[DataProvider('ciphers')]
    public function testEveryCipherDecryptsWithOpenssl(string $cipher): void
    {
        [$m, $expected] = $this->scenario('html');
        $msg = $this->outgoing($this->aliceKeys, $this->aliceCerts, 'separate', true, true, $cipher)
            ->process($m, $this->aliceIdentity(), true, true, false);
        self::assertInstanceOf(SmimeMessage::class, $msg);
        $d = $this->deliver($msg);
        $ct = (string) self::header($d['wire'], 'Content-Type');
        $gcm = str_contains($cipher, 'gcm');
        self::assertStringContainsString('smime-type=' . ($gcm ? 'authEnveloped-data' : 'enveloped-data'), $ct);
        $der = self::envelopeDer($d['wire']);
        self::assertSame($cipher, CmsInspector::envelopedData($der)['cipher']);
        $inner = $this->opensslDecrypt($d['wire'], 'bob');
        self::assertNotNull($inner);
        $this->assertInner($inner, true, $expected);
    }

    // ================================================================== Bcc handling

    public function testSeparateBccEnvelopesAreIsolated(): void
    {
        $m = $this->buildMessage($this->headers(['Cc' => null, 'Bcc' => 'Carol <carol@example.test>, mallory@example.test']), "Tajne.\r\n", false);
        $msg = $this->outgoing($this->aliceKeys, $this->aliceCerts, 'separate')->process($m, $this->aliceIdentity(), true, true, false);
        self::assertInstanceOf(SmimeMessage::class, $msg);

        $main = self::recipientSerials($msg->body());
        sort($main);
        $exp = [TestPki::cert('alice')->serialHex, TestPki::cert('bob')->serialHex];
        sort($exp);
        self::assertSame($exp, $main, 'main envelope: To + sender only');

        $d = $this->deliver($msg);
        self::assertSame(['carol@example.test', 'mallory@example.test'], array_keys($d['bcc']));
        self::assertSame('Carol <carol@example.test>, mallory@example.test', self::header($d['sent'], 'Bcc'));
        self::assertNull(self::header($d['wire'], 'Bcc'));
        self::assertNull($d['mainHeaders']['Bcc'] ?? null, 'main SMTP delivery has no Bcc recipients');

        $all = ['alice', 'bob', 'carol', 'mallory'];
        $can = [
            'main' => ['alice', 'bob'],
            'carol@example.test' => ['alice', 'carol'],
            'mallory@example.test' => ['alice', 'mallory'],
        ];
        foreach ($can as $which => $allowed) {
            $wire = $which === 'main' ? $d['wire'] : $d['bcc'][$which];
            self::assertNull(self::header($wire, 'Bcc'));
            foreach ($all as $who) {
                $inner = $this->opensslDecrypt($wire, $who);
                if (in_array($who, $allowed, true)) {
                    self::assertNotNull($inner, "$who must decrypt envelope $which");
                    $content = $this->opensslVerify(self::crlf($inner));
                    self::assertNotNull($content);
                    self::assertStringContainsString('Tajne.', $content);
                } else {
                    self::assertNull($inner, "$who must NOT decrypt envelope $which");
                }
            }
        }
        // the Sent copy is the main envelope: decryptable by the sender
        self::assertNotNull($this->opensslDecrypt($d['sent'], 'alice'));
        self::assertNull($this->opensslDecrypt($d['sent'], 'mallory'));
    }

    /**
     * Audit MS-10: the total size of all separate envelopes is checked before any encryption.
     */
    public function testTotalSizeOfSeparateBccEnvelopesIsBounded(): void
    {
        $body = str_repeat("Lorem ipsum dolor sit amet 0123456789.\r\n", 3000);   // ~120 kB
        $headers = $this->headers(['Cc' => null, 'Bcc' => 'Carol <carol@example.test>, mallory@example.test']);
        $limited = new OutgoingService($this->aliceKeys, $this->aliceCerts, $this->cms, CmsService::CIPHER_AES_256_CBC, true, true, 'separate', 50 * 1024 * 1024, 100, 400 * 1024);
        try {
            $limited->process($this->buildMessage($headers, $body, false), $this->aliceIdentity(), false, true, false);
            self::fail('expected messagetoolarge');
        } catch (ValidationException $e) {
            self::assertSame('messagetoolarge', $e->getUserLabel());
            self::assertStringContainsString('3 copies', $e->getMessage());
        }
        // the same message without Bcc (one copy) fits the budget
        $msg = $limited->process($this->buildMessage($this->headers(['Cc' => null]), $body, false), $this->aliceIdentity(), false, true, false);
        self::assertInstanceOf(SmimeMessage::class, $msg);
    }

    public function testSingleBccModePutsEveryoneInOneEnvelope(): void
    {
        $m = $this->buildMessage($this->headers(['Cc' => null, 'Bcc' => 'mallory@example.test']), "Jedna koperta.\r\n", false);
        $msg = $this->outgoing($this->aliceKeys, $this->aliceCerts, 'single')->process($m, $this->aliceIdentity(), false, true, false);
        self::assertInstanceOf(SmimeMessage::class, $msg);
        self::assertSame([], $msg->bccEnvelopes());
        $serials = self::recipientSerials($msg->body());
        sort($serials);
        $exp = [TestPki::cert('alice')->serialHex, TestPki::cert('bob')->serialHex, TestPki::cert('mallory')->serialHex];
        sort($exp);
        self::assertSame($exp, $serials);

        $d = $this->deliver($msg);
        self::assertSame([], $d['bcc']);
        self::assertNull(self::header($d['wire'], 'Bcc'));
        self::assertSame('mallory@example.test', self::header($d['sent'], 'Bcc'));
        foreach (['alice', 'bob', 'mallory'] as $who) {
            $inner = $this->opensslDecrypt($d['wire'], $who);
            self::assertNotNull($inner, $who);
            self::assertStringContainsString('Jedna koperta.', self::leaves(self::crlf($inner))[0]['data']);
        }
        self::assertNull($this->opensslDecrypt($d['wire'], 'carol'));
    }

    public function testEncryptToSelfDisabledLeavesSenderOut(): void
    {
        $m = $this->buildMessage($this->headers(['Cc' => null, 'Bcc' => null]), "Bez kopii.\r\n", false);
        $msg = $this->outgoing($this->aliceKeys, $this->aliceCerts, 'separate', false)->process($m, $this->aliceIdentity(), false, true, false);
        self::assertInstanceOf(SmimeMessage::class, $msg);
        self::assertSame([TestPki::cert('bob')->serialHex], self::recipientSerials($msg->body()));
        $d = $this->deliver($msg);
        self::assertNull($this->opensslDecrypt($d['sent'], 'alice'));
        self::assertNotNull($this->opensslDecrypt($d['wire'], 'bob'));
    }

    // ================================================================== refusals (fail closed)

    public function testMissingRecipientCertificatesAreListedExactly(): void
    {
        $this->aliceCerts->importFile(TestPki::read('expired.crt') . TestPki::read('int.crt'), false);
        $m = $this->buildMessage($this->headers([
            'To' => 'Bob <bob@example.test>, Dave <dave@example.test>',
            'Cc' => 'carol@example.test, expired@example.test',
            'Bcc' => 'eve@example.test, mallory@example.test',
        ]), "Zażółć.\r\n", false);
        $before = $m->getParam('text_encoding');
        self::assertSame('8bit', $before);

        try {
            $this->outgoing($this->aliceKeys, $this->aliceCerts)->process($m, $this->aliceIdentity(), true, true, false);
            self::fail('expected MissingCertificatesException');
        } catch (MissingCertificatesException $e) {
            $r = $e->recipients();
            ksort($r);
            self::assertSame(['dave@example.test', 'eve@example.test', 'expired@example.test'], array_keys($r));
            self::assertSame('missing', $r['dave@example.test']);
            self::assertSame('missing', $r['eve@example.test']);
            self::assertStringStartsWith('expired', $r['expired@example.test']);
            self::assertSame('encryptmissingcerts', $e->getUserLabel());
        }
        // nothing was prepared or signed: the original message is untouched
        self::assertSame('8bit', $m->getParam('text_encoding'));
        self::assertNotInstanceOf(SmimeMessage::class, $m);
    }

    public function testSigningWithCertificateForAnotherAddressIsRefused(): void
    {
        $r = $this->aliceKeys->import(TestPki::read('wrongmail.p12'), TestPki::PASSWORD, $this->identities(self::ALICE));
        self::assertSame([], $r['bound']);
        $this->aliceKeys->repository()->bind(self::ID_ALICE, $r['id']);

        $m = $this->buildMessage($this->headers(), "x\r\n", false);
        $this->assertLabel('signaddressmismatch', fn () => $this->outgoing($this->aliceKeys, $this->aliceCerts)->process($m, $this->aliceIdentity(), true, false, false));

        // an alias identity bound to alice's certificate is refused as well
        $this->aliceKeys->repository()->bind(self::ID_ALIAS, $this->aliceKeyId);
        $m2 = $this->buildMessage($this->headers(['From' => 'Alias <alias@example.test>']), "x\r\n", false);
        $this->assertLabel('signaddressmismatch', fn () => $this->outgoing($this->aliceKeys, $this->aliceCerts)->process($m2, ['identity_id' => self::ID_ALIAS, 'email' => 'alias@example.test'], true, false, false));
    }

    public function testExpiredOwnCertificateIsRefused(): void
    {
        $r = $this->aliceKeys->import(TestPki::read('expired.p12'), TestPki::PASSWORD, $this->identities(self::ALICE));
        self::assertContains('warn_expired', $r['warnings']);
        self::assertSame([], $r['bound'], 'an expired certificate is never auto-bound');
        $this->aliceKeys->repository()->bind(self::ID_EXPIRED, $r['id']);

        $m = $this->buildMessage($this->headers(['From' => 'Expired <expired@example.test>']), "x\r\n", false);
        $this->assertLabel('signcertexpired', fn () => $this->outgoing($this->aliceKeys, $this->aliceCerts)->process($m, ['identity_id' => self::ID_EXPIRED, 'email' => 'expired@example.test'], true, false, false));
    }

    public function testNoBoundCertificateIsRefused(): void
    {
        $m = $this->buildMessage($this->headers(['From' => 'alias@example.test']), "x\r\n", false);
        $this->assertLabel('signnocert', fn () => $this->outgoing($this->aliceKeys, $this->aliceCerts)->process($m, ['identity_id' => self::ID_ALIAS, 'email' => 'alias@example.test'], true, false, false));
    }

    public function testFromHeaderMustMatchIdentity(): void
    {
        foreach (['Mallory <mallory@example.test>', 'Alice <alice@example.test>, mallory@example.test', ''] as $from) {
            $m = $this->buildMessage($this->headers(['From' => $from === '' ? null : $from]), "x\r\n", false);
            foreach ([[true, false], [false, true], [true, true]] as [$s, $e]) {
                $this->assertLabel('fromidentitymismatch', fn () => $this->outgoing($this->aliceKeys, $this->aliceCerts)->process($m, $this->aliceIdentity(), $s, $e, false));
            }
        }
        // case differences are fine
        $m = $this->buildMessage($this->headers(['From' => 'ALICE <Alice@Example.TEST>']), "x\r\n", false);
        self::assertInstanceOf(SmimeMessage::class, $this->outgoing($this->aliceKeys, $this->aliceCerts)->process($m, $this->aliceIdentity(), true, false, false));
    }

    public function testAlreadyProcessedMessageIsRefused(): void
    {
        $m = $this->buildMessage($this->headers(), "x\r\n", false);
        $svc = $this->outgoing($this->aliceKeys, $this->aliceCerts);
        $msg = $svc->process($m, $this->aliceIdentity(), true, false, false);
        self::assertInstanceOf(SmimeMessage::class, $msg);
        $this->assertLabel('conflictotherplugin', fn () => $svc->process($msg, $this->aliceIdentity(), true, false, false));
        $this->assertLabel('conflictotherplugin', fn () => $svc->process($msg, $this->aliceIdentity(), false, true, true));

        // a message already wrapped by another plugin (e.g. Mailvelope PGP/MIME)
        $pgp = $this->buildMessage($this->headers(), "x\r\n", false);
        $pgp->setContentType('multipart/encrypted', ['protocol' => 'application/pgp-encrypted']);
        $this->assertLabel('conflictotherplugin', fn () => $svc->process($pgp, $this->aliceIdentity(), true, true, false));
    }

    public function testNothingRequestedReturnsNull(): void
    {
        $m = $this->buildMessage($this->headers(), "x\r\n", false);
        self::assertNull($this->outgoing($this->aliceKeys, $this->aliceCerts)->process($m, $this->aliceIdentity(), false, false, false));
    }

    // ================================================================== drafts

    public function testEncryptedDraftIsEncryptedToSelfOnlyAndNeverSigned(): void
    {
        [$m, $expected] = $this->scenario('attachments');
        $msg = $this->outgoing($this->aliceKeys, $this->aliceCerts)->process($m, $this->aliceIdentity(), true, true, true);
        self::assertInstanceOf(SmimeMessage::class, $msg);
        self::assertTrue($msg->isDraft());
        self::assertTrue($msg->isEncrypted());
        self::assertFalse($msg->isSigned());
        self::assertSame([], $msg->bccEnvelopes());
        self::assertSame([TestPki::cert('alice')->serialHex], self::recipientSerials($msg->body()));

        // drafts are only saved (IMAP APPEND), never sent
        $draft = self::imapAppend($msg->getMessage());
        self::assertSame('sign=1; encrypt=1', self::header($draft, OutgoingService::DRAFT_HEADER));
        self::assertSame('mallory@example.test', self::header($draft, 'Bcc'), 'drafts keep Bcc');
        self::assertNull($this->opensslDecrypt($draft, 'bob'));
        self::assertNull($this->opensslDecrypt($draft, 'mallory'));
        $inner = $this->opensslDecrypt($draft, 'alice');
        self::assertNotNull($inner);
        self::assertStringNotContainsString('multipart/signed', $inner);
        self::assertStringNotContainsString('pkcs7-signature', $inner);
        $this->assertPayload(self::crlf($inner), $expected, false);
    }

    public function testDraftWithoutEncryptionKeepsOptionsHeaderOnly(): void
    {
        $m = $this->buildMessage($this->headers(), "x\r\n", false);
        self::assertNull($this->outgoing($this->aliceKeys, $this->aliceCerts)->process($m, $this->aliceIdentity(), true, false, true));
        $raw = self::imapAppend($m->getMessage());
        self::assertSame('sign=1; encrypt=0', self::header($raw, OutgoingService::DRAFT_HEADER));
        self::assertStringStartsWith('text/plain', (string) self::header($raw, 'Content-Type'));
    }

    public function testDraftEncryptionDisabledByAdminStoresPlainDraft(): void
    {
        $m = $this->buildMessage($this->headers(), "x\r\n", false);
        $svc = $this->outgoing($this->aliceKeys, $this->aliceCerts, 'separate', true, false);
        self::assertNull($svc->process($m, $this->aliceIdentity(), true, true, true));
        self::assertSame('sign=1; encrypt=1', self::header(self::imapAppend($m->getMessage()), OutgoingService::DRAFT_HEADER));
    }

    public function testDraftWithoutOwnCertificateIsRefused(): void
    {
        $m = $this->buildMessage($this->headers(['From' => 'alias@example.test']), "x\r\n", false);
        $this->assertLabel('draftnoselfcert', fn () => $this->outgoing($this->aliceKeys, $this->aliceCerts)->process($m, ['identity_id' => self::ID_ALIAS, 'email' => 'alias@example.test'], false, true, true));
    }

    // ================================================================== identity bindings

    public function testImportBindsMatchingIdentityAndTheBindingIsStored(): void
    {
        // setUp imported alice.p12: the matching identity is bound by the import itself (no Save step),
        // the identities with other addresses are not
        self::assertSame([self::ID_ALICE => $this->aliceKeyId], $this->aliceKeys->repository()->bindings());

        // read back through a NEW database connection (e.g. after logging out and in again)
        $rcdb = \rcube_db::factory('sqlite:///' . $this->dbFile . '?mode=0600');
        $rcdb->set_debug(false);
        $rcdb->db_connect('r');
        try {
            $repo = new KeyRepository(new Database($rcdb), self::ALICE);
            self::assertSame([self::ID_ALICE => $this->aliceKeyId], $repo->bindings());
            self::assertSame($this->aliceKeyId, $repo->bindingFor(self::ID_ALICE));
            self::assertNull($repo->bindingFor(self::ID_EXPIRED));
            self::assertNull($repo->bindingFor(self::ID_ALIAS));
        } finally {
            $rcdb->closeConnection();
        }
        self::assertSame(TestPki::cert('alice')->fingerprint, $this->aliceKeys->signerFor($this->aliceIdentity())->fingerprint());
    }

    public function testCertificateForAnotherAddressIsNeitherBoundByImportNorEligible(): void
    {
        $r = $this->aliceKeys->import(TestPki::read('wrongmail.p12'), TestPki::PASSWORD, $this->identities(self::ALICE));
        self::assertSame([], $r['bound'], 'no identity of alice has the certificate address');
        self::assertSame([self::ID_ALICE => $this->aliceKeyId], $this->aliceKeys->repository()->bindings());
        $rec = $this->aliceKeys->repository()->get($r['id']);
        self::assertNotNull($rec);
        // the check the bind action applies before storing a requested binding
        foreach (['alice@example.test', 'expired@example.test', 'alias@example.test'] as $email) {
            self::assertFalse($this->aliceKeys->isUsableForSigning($rec, $email), $email);
        }
        $alice = $this->aliceKeys->repository()->get($this->aliceKeyId);
        self::assertNotNull($alice);
        self::assertTrue($this->aliceKeys->isUsableForSigning($alice, 'alice@example.test'));
        self::assertFalse($this->aliceKeys->isUsableForSigning($alice, 'alias@example.test'));
    }

    // ================================================================== key rotation

    public function testAlice2WithIdenticalValidityDoesNotStealTheBinding(): void
    {
        // alice2.crt has exactly the same notAfter as alice.crt: rotation only switches to a key that
        // expires LATER, so the existing binding stays (documented in KeyService::store)
        self::assertSame(TestPki::cert('alice')->notAfter, TestPki::cert('alice2')->notAfter);
        $r = $this->aliceKeys->import(TestPki::read('alice2.p12'), TestPki::PASSWORD, $this->identities(self::ALICE));
        self::assertSame([], $r['bound']);
        self::assertSame($this->aliceKeyId, $this->aliceKeys->repository()->bindingFor(self::ID_ALICE));
        self::assertSame(TestPki::cert('alice')->fingerprint, $this->aliceKeys->signerFor($this->aliceIdentity())->fingerprint());
    }

    public function testRotationSwitchesSigningKeyAndOldKeyStillDecrypts(): void
    {
        // a message encrypted to alice's CURRENT (old) certificate, before rotation
        $oldDer = $this->cms->encrypt("Content-Type: text/plain\r\n\r\nstara wiadomość\r\n", [TestPki::cert('alice')]);

        $newer = $this->issueNewerAliceCert();
        $r = $this->aliceKeys->import($newer['p12'], 'rot-pass', $this->identities(self::ALICE));
        self::assertSame([self::ID_ALICE], $r['bound'], 'a later-expiring valid certificate takes over the binding');
        $newId = $r['id'];
        self::assertSame($newId, $this->aliceKeys->repository()->bindingFor(self::ID_ALICE));
        self::assertSame($newer['cert']->fingerprint, $this->aliceKeys->signerFor($this->aliceIdentity())->fingerprint());

        // also the fixture alice2 can be imported next to them (third key for the same address)
        $this->aliceKeys->import(TestPki::read('alice2.p12'), TestPki::PASSWORD, $this->identities(self::ALICE));
        self::assertSame($newId, $this->aliceKeys->repository()->bindingFor(self::ID_ALICE));
        self::assertSame(3, $this->aliceKeys->repository()->count());

        // new messages are signed with the new key and encrypted to the new self certificate
        $m = $this->buildMessage($this->headers(['Cc' => null, 'Bcc' => null]), "po rotacji\r\n", false);
        $msg = $this->outgoing($this->aliceKeys, $this->aliceCerts)->process($m, $this->aliceIdentity(), true, false, false);
        self::assertInstanceOf(SmimeMessage::class, $msg);
        $d = $this->deliver($msg);
        self::assertNotNull($this->opensslVerify($d['wire']));
        self::assertSame($newer['cert']->fingerprint, $this->signerFingerprint($d['wire']));

        $m2 = $this->buildMessage($this->headers(['Cc' => null, 'Bcc' => null]), "po rotacji\r\n", false);
        $enc = $this->outgoing($this->aliceKeys, $this->aliceCerts)->process($m2, $this->aliceIdentity(), false, true, false);
        self::assertInstanceOf(SmimeMessage::class, $enc);
        $serials = self::recipientSerials($enc->body());
        self::assertContains($newer['cert']->serialHex, $serials);
        self::assertNotContains(TestPki::cert('alice')->serialHex, $serials);

        // the old message still decrypts through the candidates (only the RecipientInfo match, audit I-18)
        $cands = $this->aliceKeys->decryptionCandidates($oldDer);
        self::assertCount(1, $cands);
        self::assertSame($this->aliceKeyId, $cands[0]->id());
        $plain = null;
        foreach ($cands as $rec) {
            $key = $this->aliceKeys->privateKey($rec);
            try {
                $plain = $this->cms->decrypt($oldDer, $rec->certificate(), $key);
            } finally {
                KeyVault::wipe($key);
            }
            if ($plain !== null) {
                self::assertSame($this->aliceKeyId, $rec->id());
                break;
            }
        }
        self::assertSame("Content-Type: text/plain\r\n\r\nstara wiadomość\r\n", $plain);

        // and a message encrypted to the NEW certificate selects the new key first
        $newDer = $this->cms->encrypt("Content-Type: text/plain\r\n\r\nnowa\r\n", [$newer['cert']]);
        self::assertSame($newId, $this->aliceKeys->decryptionCandidates($newDer)[0]->id());
    }

    /**
     * Imports unrelated fixture keys into bob's store (none of them is a recipient of alice's messages).
     *
     * @return int number of keys bob holds afterwards
     */
    private function giveBobManyKeys(): int
    {
        foreach (['carol', 'mallory', 'evil', 'signonly', 'untrusted', 'selfsigned', 'wrongmail', 'legacyemail', 'notyet', 'revoked'] as $n) {
            try {
                $this->bobKeys->import(TestPki::read($n . '.p12'), TestPki::PASSWORD, $this->identities(self::BOB));
            } catch (MimeShieldException) {
                // a fixture the importer refuses is irrelevant here
            }
        }
        return $this->bobKeys->repository()->count();
    }

    public function testDecryptionCandidatesAreOnlyTheMatchingKeysWhenOneMatches(): void
    {
        self::assertGreaterThan(6, $this->giveBobManyKeys());
        // audit I-18: with a RecipientInfo match, unmatched keys are never unwrapped for the message
        $der = $this->cms->encrypt("Content-Type: text/plain\r\n\r\nx\r\n", [TestPki::cert('bob'), TestPki::cert('alice')]);
        self::assertSame([$this->bobKeyId], array_map(static fn ($r) => $r->id(), $this->bobKeys->decryptionCandidates($der)));
    }

    public function testDecryptionCandidatesWithoutAnyMatchAreBoundedToFive(): void
    {
        self::assertGreaterThan(6, $this->giveBobManyKeys());
        // audit I-18: no own key matches (message for alice) - at most 5 blind attempts
        $der = $this->cms->encrypt("Content-Type: text/plain\r\n\r\nx\r\n", [TestPki::cert('alice')]);
        self::assertCount(5, $this->bobKeys->decryptionCandidates($der));
        self::assertCount(2, $this->bobKeys->decryptionCandidates($der, 2), 'the caller limit still applies');
    }

    // ================================================================== user isolation

    public function testUserIsolation(): void
    {
        $bobRepo = $this->bobKeys->repository();
        self::assertNull($bobRepo->get($this->aliceKeyId));
        self::assertNull($bobRepo->findByFingerprint(TestPki::cert('alice')->fingerprint));
        self::assertSame([$this->bobKeyId], array_map(static fn ($r) => $r->id(), $bobRepo->all()));
        self::assertNull($bobRepo->bindingFor(self::ID_ALICE));

        try {
            $bobRepo->bind(self::ID_BOB, $this->aliceKeyId);
            self::fail('binding a foreign key must fail');
        } catch (StorageException $e) {
            self::assertSame('notfound', $e->getUserLabel());
        }
        self::assertSame($this->bobKeyId, $bobRepo->bindingFor(self::ID_BOB));

        // a record read through alice's repository cannot be unwrapped through bob's service
        $aliceRecord = $this->aliceKeys->repository()->get($this->aliceKeyId);
        self::assertNotNull($aliceRecord);
        $this->assertLabel('notfound', fn () => $this->bobKeys->privateKey($aliceRecord));

        // bob's delete of alice's key id is a no-op
        self::assertFalse($this->bobKeys->delete($this->aliceKeyId));
        self::assertNotNull($this->aliceKeys->repository()->get($this->aliceKeyId));

        // correspondent stores
        $bobCertRepo = $this->bobCerts->repository();
        $bobFps = array_map(static fn ($r) => $r->fingerprint(), $bobCertRepo->all());
        self::assertSame([TestPki::cert('alice')->fingerprint], $bobFps);
        foreach (['bob', 'carol', 'mallory'] as $n) {
            self::assertNull($bobCertRepo->findByFingerprint(TestPki::cert($n)->fingerprint), $n);
        }
        foreach ($this->aliceCerts->repository()->all() as $rec) {
            self::assertNull($bobCertRepo->get($rec->id()));
        }
        self::assertSame(CertificateService::R_MISSING, $this->bobCerts->resolveOne('carol@example.test')['status']);
        self::assertSame(CertificateService::R_OK, $this->aliceCerts->resolveOne('carol@example.test')['status']);

        // decryption candidates of bob never contain alice's key
        $der = $this->cms->encrypt("Content-Type: text/plain\r\n\r\nx\r\n", [TestPki::cert('alice')]);
        self::assertSame([$this->bobKeyId], array_map(static fn ($r) => $r->id(), $this->bobKeys->decryptionCandidates($der)));

        // bob cannot sign as alice even when he forges From + identity id
        $m = $this->buildMessage($this->headers(), "x\r\n", false);
        $this->assertLabel('signnocert', fn () => $this->outgoing($this->bobKeys, $this->bobCerts)->process($m, $this->aliceIdentity(), true, false, false));

        // the key blob is bound to its user: copying alice's blob into bob's row fails authentication
        $this->db->query('UPDATE ' . $this->db->table('mimeshield_keys') . ' SET `key_blob` = ? WHERE `key_id` = ?', $aliceRecord->blob(), $this->bobKeyId);
        $bobRec = $bobRepo->get($this->bobKeyId);
        self::assertNotNull($bobRec);
        $this->assertLabel('keystorecorrupt', fn () => $this->bobKeys->privateKey($bobRec));
    }

    // ================================================================== audit MS-09: own key records

    public function testSwappedCertificateInOwnKeyRecordIsRejected(): void
    {
        // database write: replace the certificate of alice's key record by bob's
        $this->db->query('UPDATE ' . $this->db->table('mimeshield_keys') . ' SET `cert_pem` = ? WHERE `key_id` = ?', TestPki::read('bob.crt'), $this->aliceKeyId);
        [$keys] = $this->servicesFor(self::ALICE);
        $rec = (new KeyRepository($this->db, self::ALICE))->get($this->aliceKeyId);
        self::assertNotNull($rec);
        $this->assertLabel('keyinvalid', fn () => $rec->certificate());
        self::assertNull($keys->encryptionCertFor('bob@example.test'));
    }

    public function testInsertedOwnKeyRecordIsNotUsedForEncryption(): void
    {
        // database write: a row with a consistent certificate/fingerprint but no valid key blob
        $evil = TestPki::cert('mallory');
        $alice = (new KeyRepository($this->db, self::ALICE))->get($this->aliceKeyId);
        self::assertNotNull($alice);
        (new KeyRepository($this->db, self::ALICE))->insert($evil, [], $alice->blob(), $alice->kid(), KeyVault::FORMAT_VERSION);
        [$keys] = $this->servicesFor(self::ALICE);
        self::assertNull($keys->encryptionCertFor('mallory@example.test'), 'blob does not authenticate for this fingerprint');
        self::assertNotNull($keys->encryptionCertFor('alice@example.test'), 'genuine record still used');
    }

    public function testOwnStatusOnlyForIdentityAddresses(): void
    {
        $certsWith = fn (array $identities) => new CertificateService(
            new CertRepository($this->db, self::ALICE),
            new PublicCertImporter(),
            new ChainValidator($this->trust, $this->dir),
            new RevocationChecker(RevocationChecker::MODE_OFF, null, $this->dir . '/crl'),
            $this->aliceKeys,
            100,
            'block',
            true,
            $this->trust,
            'warn',
            static fn () => $identities,
        );
        self::assertSame('own', $certsWith(['Alice@Example.test'])->resolveOne('alice@example.test')['detail']);
        // the own certificate covers the address, but it is not an identity of the user: no "own"
        // shortcut (no correspondent certificate either -> missing)
        $r = $certsWith(['alias@example.test'])->resolveOne('alice@example.test');
        self::assertNotSame('own', $r['detail']);
        self::assertSame(CertificateService::R_MISSING, $r['status']);
    }

    // ================================================================== audit MS-04: recipient revocation

    /**
     * Correspondent certificate service with CRL checking on, the intermediate configured by the
     * administrator (not stored with the record) and a pre-seeded CRL cache (no network).
     */
    private function revocationCerts(string $unknownPolicy, bool $seedCrl): CertificateService
    {
        $cacheDir = $this->dir . '/rev-' . bin2hex(random_bytes(4));
        if ($seedCrl) {
            mkdir($cacheDir . '/crl', 0700, true);
            $file = $cacheDir . '/crl/' . hash('sha256', 'http://crl.example.test/int.crl') . '.crl';
            file_put_contents($file, TestPki::read('int.crl'));
        }
        $trust = new TrustStore([TestPki::path('root.crt')], false, [TestPki::path('int.crt')]);
        // the CRL host is denied: without a cached CRL the status is "unknown", never a network request
        $http = new \MimeShield\Trust\SafeHttpClient(1, 1, [80, 443], [], ['crl.example.test']);
        return new CertificateService(
            new CertRepository($this->db, self::ALICE),
            new PublicCertImporter(),
            new ChainValidator($trust, $this->dir),
            new RevocationChecker(RevocationChecker::MODE_CRL, $http, $cacheDir),
            $this->aliceKeys,
            100,
            'block',
            true,
            $trust,
            $unknownPolicy,
        );
    }

    public function testRevokedRecipientImportedWithoutChainIsBlocked(): void
    {
        $certs = $this->revocationCerts('warn', true);
        $res = $certs->importFile(TestPki::read('revoked.crt'), false);   // end entity only, no chain
        self::assertCount(1, $res['imported']);

        $r = $certs->resolveOne('revoked@example.test');
        self::assertSame(CertificateService::R_INVALID, $r['status']);
        self::assertSame('revoked', $r['detail']);

        // a certificate that is not on the CRL stays usable; the TEST intermediate has no CRL
        // distribution point, so the path status is undetermined (audit F-04/F-06) - signalled
        // under the 'warn' policy
        $r = $certs->resolveOne('bob@example.test');
        self::assertSame(CertificateService::R_OK, $r['status']);
        self::assertSame(CertificateService::D_REVOCATION_UNKNOWN, $r['detail']);
        $block = $this->revocationCerts('block', true);
        $block->importFile(TestPki::read('bob.crt'), false);
        self::assertSame(CertificateService::R_INVALID, $block->resolveOne('bob@example.test')['status']);
    }

    public function testUnknownRecipientRevocationIsSignalledOrBlockedByPolicy(): void
    {
        $warn = $this->revocationCerts('warn', false);
        $r = $warn->resolveOne('bob@example.test');
        self::assertSame(CertificateService::R_OK, $r['status']);
        self::assertSame(CertificateService::D_REVOCATION_UNKNOWN, $r['detail']);

        $block = $this->revocationCerts('block', false);
        $r = $block->resolveOne('bob@example.test');
        self::assertSame(CertificateService::R_INVALID, $r['status']);
        self::assertSame('revocationunknown', $r['detail']);
    }

    // ================================================================== audit F-15: certificate saved from a message

    private function untrustedSignerResult(): \MimeShield\Trust\VerificationResult
    {
        $content = "Content-Type: text/plain\r\n\r\nhello\r\n";
        $sig = $this->cms->signDetached($content, TestPki::cert('untrusted'), TestPki::key('untrusted'), []);
        $verifier = new \MimeShield\Service\SignatureVerifier(new ChainValidator($this->trust, $this->dir), $this->trust,
            new RevocationChecker(RevocationChecker::MODE_OFF, null, ''));
        $r = $verifier->evaluate($this->cms->verifyDetached($content, $sig), ['alice@example.test'], []);
        self::assertTrue($r->cryptoValid());
        self::assertFalse($r->chain?->isTrusted());
        return $r;
    }

    private function certsWithPolicy(string $untrustedPolicy): CertificateService
    {
        return new CertificateService(new CertRepository($this->db, self::ALICE), new PublicCertImporter(),
            new ChainValidator($this->trust, $this->dir), new RevocationChecker(RevocationChecker::MODE_OFF, null, ''),
            $this->aliceKeys, 100, $untrustedPolicy);
    }

    public function testUntrustedCertificateFromMessageNeedsConfirmationUnderWarnPolicy(): void
    {
        $result = $this->untrustedSignerResult();
        $certs = $this->certsWithPolicy('warn');

        $r = $certs->saveFromMessage($result, false);
        self::assertSame(0, $r['id']);
        self::assertSame([['email' => 'alice@example.test', 'old' => [], 'new' => TestPki::cert('untrusted')->fingerprint, 'untrusted' => true]], $r['confirm']);
        self::assertNull($certs->repository()->findByFingerprint(TestPki::cert('untrusted')->fingerprint), 'nothing stored without confirmation');

        $r = $certs->saveFromMessage($result, true);
        self::assertGreaterThan(0, $r['id']);
        self::assertSame(CertRepository::TRUST_OBSERVED, $r['trust']);
    }

    public function testUntrustedCertificateFromMessageUnderBlockPolicyIsStoredButNeverUsable(): void
    {
        $certs = $this->certsWithPolicy('block');
        $r = $certs->saveFromMessage($this->untrustedSignerResult(), false);
        self::assertSame([], $r['confirm']);
        self::assertSame(CertRepository::TRUST_OBSERVED, $r['trust']);
    }

    // ================================================================== service graph

    /**
     * @return array{0: KeyService, 1: CertificateService}
     */
    private function servicesFor(int $userId): array
    {
        $keys = new KeyService(new KeyRepository($this->db, $userId), $this->vault, new KeyImporter(), null, 20);
        $certs = new CertificateService(
            new CertRepository($this->db, $userId),
            new PublicCertImporter(),
            new ChainValidator($this->trust, $this->dir),
            new RevocationChecker(RevocationChecker::MODE_OFF, null, $this->dir . '/crl'),
            $keys,
            100,
        );
        return [$keys, $certs];
    }

    private function outgoing(KeyService $keys, CertificateService $certs, string $bccMode = 'separate', bool $toSelf = true, bool $encDrafts = true, string $cipher = CmsService::CIPHER_AES_256_CBC): OutgoingService
    {
        return new OutgoingService($keys, $certs, $this->cms, $cipher, $toSelf, $encDrafts, $bccMode, 50 * 1024 * 1024, 100);
    }

    /**
     * @return list<array{identity_id: int, email: string}>
     */
    private function identities(int $userId): array
    {
        $rows = $this->db->fetchAll('SELECT `identity_id`, `email` FROM ' . $this->db->table('identities') . ' WHERE `user_id` = ? AND `del` = 0', $userId);
        return array_map(static fn ($r) => ['identity_id' => (int) $r['identity_id'], 'email' => (string) $r['email']], $rows);
    }

    /**
     * @return array{identity_id: int, email: string}
     */
    private function aliceIdentity(): array
    {
        return ['identity_id' => self::ID_ALICE, 'email' => 'alice@example.test'];
    }

    // ================================================================== Roundcube message building

    /**
     * Headers as rcmail_sendmail::headers_input() produces them (null removes a header).
     *
     * @param array<string, ?string> $over
     *
     * @return array<string, string>
     */
    private function headers(array $over = []): array
    {
        $h = array_merge([
            'Received' => null,
            'Date' => 'Fri, 02 Oct 2026 10:00:00 +0200',
            'From' => 'Alicja Żółć <alice@example.test>',
            'To' => 'Bob Bąk <bob@example.test>',
            'Cc' => 'carol@example.test',
            'Bcc' => 'mallory@example.test',
            'Subject' => 'Zażółć gęślą jaźń – test',
            'Message-ID' => '<' . bin2hex(random_bytes(8)) . '@example.test>',
            'X-Sender' => 'alice@example.test',
            'User-Agent' => 'Roundcube Webmail/1.7.4',
        ], $over);
        return array_filter($h, static fn ($v) => $v !== null);
    }

    /**
     * rcmail_sendmail::create_message() + set_message_encoding() (charset UTF-8, send_format_flowed
     * default on, line_length 72, force_7bit off) + send.php add_attachments().
     *
     * @param array<string, string> $headers
     * @param list<array{data: string, ctype: string, name: string}> $attachments
     * @param list<array{data: string, ctype: string, name: string, cid: string}> $inline
     */
    private function buildMessage(array $headers, string $body, bool $isHtml, array $attachments = [], array $inline = []): \Mail_mime
    {
        $flowed = true;
        $m = new \Mail_mime("\r\n");
        if ($isHtml) {
            $m->setHTMLBody($body);
            $conv = new \rcube_html2text($body, false, \rcube_html2text::LINKS_DEFAULT, 0, 'UTF-8');
            $plain = self::formatPlainBody(rtrim($conv->get_text()), $flowed);
            if (trim($plain) !== '') {
                $m->setTXTBody($plain);
            }
        } else {
            $m->setTXTBody(self::formatPlainBody($body, $flowed), false, true);
        }

        // set_message_encoding()
        $textCharset = 'UTF-8';
        $te = '7bit';
        if (preg_match('/[^\x00-\x7F]/', (string) $m->getTXTBody())) {
            $te = '8bit';
        } else {
            $textCharset = 'US-ASCII';
        }
        if ($flowed) {
            $textCharset .= ";\r\n format=flowed";
        }
        $m->setParam('text_encoding', $te);
        $m->setParam('html_encoding', 'quoted-printable');
        $m->setParam('head_encoding', 'quoted-printable');
        $m->setParam('head_charset', 'UTF-8');
        $m->setParam('html_charset', 'UTF-8');
        $m->setParam('text_charset', $textCharset);
        $m->headers($headers);

        foreach ($inline as $img) {
            $m->addHTMLImage($img['data'], $img['ctype'], $img['name'], false, $img['cid']);
        }
        foreach ($attachments as $a) {
            $m->addAttachment($a['data'], $a['ctype'], $a['name'], false,
                $a['ctype'] === 'message/rfc822' ? '8bit' : 'base64', 'attachment', null, '', '', null, null, '', 'UTF-8');
        }
        return $m;
    }

    private static function formatPlainBody(string $body, bool $flowed): string
    {
        if ($flowed) {
            $body = \rcube_mime::format_flowed($body, min(72 + 2, 79), 'UTF-8');
        } else {
            $body = \rcube_mime::wordwrap($body, 72, "\r\n", false, 'UTF-8');
        }
        $body = wordwrap($body, 998, "\r\n", true);
        return (string) preg_replace('/\r?\n/', "\r\n", $body);
    }

    /**
     * @return array{0: \Mail_mime, 1: list<array{type: string, data: string, name?: string}>}
     */
    private function scenario(string $name): array
    {
        $polish = "Zażółć gęślą jaźń. ZAŻÓŁĆ GĘŚLĄ JAŹŃ.\r\n"
            . "From the beginning: a line starting with From\r\n"
            . ".a line starting with a dot\r\n"
            . "trailing spaces   \r\n"
            . "tab\tseparated\r\n"
            . "price=5 =3D not QP\r\n"
            . "> quoted line\r\n"
            . "\r\n-- \r\nAlicja\r\n";

        switch ($name) {
            case 'plain':
                $m = $this->buildMessage($this->headers(), $polish . str_repeat('Łódź kąpie się w słońcu, a żuraw śpiewa. ', 40) . "\r\n", false);
                return [$m, [['type' => 'text/plain', 'data' => (string) $m->getTXTBody()]]];

            case 'longlines':
                $body = str_repeat('ź', 3000) . "\r\n"                                 // one 6000-byte word
                    . str_repeat('abc.def ', 600) . "\r\n"                             // long line with dots
                    . str_repeat('x', 1500) . '.' . str_repeat('y', 1500) . "\r\n"
                    . $polish;
                $m = $this->buildMessage($this->headers(), $body, false);
                return [$m, [['type' => 'text/plain', 'data' => (string) $m->getTXTBody()]]];

            case 'html':
                $html = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body>'
                    . '<p>Zażółć <b>gęślą</b> jaźń &amp; &lt;tags&gt;</p>'
                    . '<p>' . str_repeat('Bardzo długi akapit z polskimi znakami ąęśćżźńół. ', 60) . '</p>'
                    . "<pre>.dot\r\nFrom here\r\n</pre>"
                    . '<p style="color:red">=3D</p></body></html>';
                $m = $this->buildMessage($this->headers(), $html, true);
                return [$m, [
                    ['type' => 'text/plain', 'data' => (string) $m->getTXTBody()],
                    ['type' => 'text/html', 'data' => (string) $m->getHTMLBody()],
                ]];

            case 'related':
                $png = "\x89PNG\r\n\x1a\n" . random_bytes(4000);
                $cid = 'img' . bin2hex(random_bytes(6)) . '@example.test';
                $html = '<html><body><p>Obrazek: <img src="cid:' . $cid . '"></p><p>Zażółć.</p></body></html>';
                $m = $this->buildMessage($this->headers(), $html, true, [['data' => "zał\x00ącznik", 'ctype' => 'application/octet-stream', 'name' => 'a.bin']],
                    [['data' => $png, 'ctype' => 'image/png', 'name' => 'obraz.png', 'cid' => $cid]]);
                return [$m, [
                    ['type' => 'text/plain', 'data' => (string) $m->getTXTBody()],
                    ['type' => 'text/html', 'data' => (string) $m->getHTMLBody()],
                    ['type' => 'image/png', 'data' => $png, 'name' => 'obraz.png'],
                    ['type' => 'application/octet-stream', 'data' => "zał\x00ącznik", 'name' => 'a.bin'],
                ]];

            case 'attachments':
                $bin = "\x00\x00\x00" . random_bytes(20000) . "\x00\r\n.\r\n\x00";
                $pdf = "%PDF-1.4\n%\xE2\xE3\xCF\xD3\n1 0 obj\n<< /Type /Catalog >>\nendobj\n" . random_bytes(3000) . "\n%%EOF\n";
                $big = random_bytes(1500000);
                $atts = [
                    ['data' => $bin, 'ctype' => 'application/octet-stream', 'name' => 'dane.bin'],
                    ['data' => $pdf, 'ctype' => 'application/pdf', 'name' => 'dokument.pdf'],
                    ['data' => $big, 'ctype' => 'application/octet-stream', 'name' => 'duzy.bin'],
                ];
                $m = $this->buildMessage($this->headers(), $polish, false, $atts);
                $exp = [['type' => 'text/plain', 'data' => (string) $m->getTXTBody()]];
                foreach ($atts as $a) {
                    $exp[] = ['type' => $a['ctype'], 'data' => $a['data'], 'name' => $a['name']];
                }
                return [$m, $exp];

            case 'rfc822':
                $eml = "From: Żaneta <z@example.test>\r\nTo: a@example.test\r\nSubject: =?UTF-8?Q?Za=C5=BC=C3=B3=C5=82=C4=87?=\r\n"
                    . "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
                    . "Treść 8-bitowa: zażółć gęślą jaźń.\r\n.kropka\r\nFrom nowhere\r\n";
                $m = $this->buildMessage($this->headers(), $polish, false, [['data' => $eml, 'ctype' => 'message/rfc822', 'name' => 'przekazana.eml']]);
                return [$m, [
                    ['type' => 'text/plain', 'data' => (string) $m->getTXTBody()],
                    // clear-signing converts 8-bit message/rfc822 to base64 application/octet-stream
                    ['type' => 'message/rfc822|application/octet-stream', 'data' => $eml, 'name' => 'przekazana.eml'],
                ]];
        }
        throw new \LogicException('unknown scenario ' . $name);
    }

    // ================================================================== delivery emulation

    /**
     * rcube_smtp string path: headers . CRLF . body
     */
    private static function smtpString(\Mail_mime $message): string
    {
        return (clone $message)->txtHeaders(['Bcc' => null], true) . "\r\n" . $message->get();
    }

    /**
     * Emulates mimeshield::message_before_send (DotGuard + Bcc envelopes), rcube::deliver_message()
     * (string path), Net_SMTP DATA + MTA, rcmail_sendmail::save_message() + IMAP APPEND.
     *
     * @return array{wire: string, sent: string, bcc: array<string, string>, mainHeaders: array<string, mixed>}
     */
    private function deliver(SmimeMessage $msg): array
    {
        // --- message_before_send (plugin; same DotGuard::makeSafe() call, the hook itself is run in
        // testMessageBeforeSendHook*) ---
        if ($msg->isSigned() && !$msg->isEncrypted()) {
            self::assertTrue(DotGuard::makeSafe(
                static fn (): string => (clone $msg)->txtHeaders(['Bcc' => null], true) . "\r\n" . $msg->body(),
                static fn () => $msg->padPreamble(1),
            ), 'the plugin would block this send (F-11)');
        }
        $toDeliver = $msg;
        $bcc = [];
        if ($msg->bccEnvelopes() !== []) {
            $bccHeaders = $msg->variant()->txtHeaders(['Bcc' => null], true);
            foreach ($msg->bccEnvelopes() as $env) {
                // rcube_smtp::send_mail string path
                $bcc[$env['address']] = self::mtaReceive(self::netSmtpDataCopy($bccHeaders . "\r\n" . $env['body']));
            }
            $toDeliver = $msg->variant();
        }

        // --- rcube::deliver_message ---
        $headers = $toDeliver->headers();
        $smtpHeaders = $toDeliver->txtHeaders(['Bcc' => null], true);
        self::assertFalse((bool) $toDeliver->getParam('delay_file_io'), 'Net_SMTP string path');
        $body = $toDeliver->get();
        self::assertIsString($body);
        $data = $smtpHeaders . "\r\n" . $body;
        // the task's shortcut form must give the same bytes
        self::assertSame(self::smtpString($toDeliver), $data);
        $wire = self::mtaReceive(self::netSmtpDataCopy($data));
        if (!empty($headers['Bcc'])) {
            $toDeliver->headers(['Bcc' => $headers['Bcc']], true);
        }

        // --- rcmail_sendmail::save_message (the object from message_ready) + IMAP APPEND ---
        $sent = self::imapAppend($msg->getMessage());

        return ['wire' => $wire, 'sent' => $sent, 'bcc' => $bcc, 'mainHeaders' => $headers];
    }

    /**
     * Net_SMTP 1.12 data() string path: 512000-byte chunks extended past "\n", each chunk quoted on
     * its own, then the terminator (copied from vendor/pear/net_smtp/Net/SMTP.php).
     */
    private static function netSmtpDataCopy(string $data): string
    {
        $out = '';
        $size = strlen($data);
        $chunk = '';
        for ($offset = 0; $offset < $size;) {
            $end = $offset + 512000;
            if ($end >= $size) {
                $end = $size;
            } else {
                for (; $end < $size; $end++) {
                    if ($data[$end] != "\n") {
                        break;
                    }
                }
            }
            $chunk = substr($data, $offset, $end - $offset);
            // Net_SMTP::quotedata()
            $chunk = (string) preg_replace('/^\./m', '..', $chunk);
            $chunk = (string) preg_replace('/(?:\r\n|\n|\r(?!\n))/', "\r\n", $chunk);
            $out .= $chunk;
            $offset = $end;
        }
        $out .= (substr($chunk, -2) == "\r\n" ? '' : "\r\n") . ".\r\n";
        return $out;
    }

    /**
     * The same through the real Net_SMTP::data() (socket I/O stubbed).
     */
    private static function netSmtpDataReal(string $data): string
    {
        $smtp = new class () extends \Net_SMTP {
            public string $captured = '';

            protected function send($data)
            {
                $this->captured .= $data;
                return true;
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
        self::assertTrue($r === true || $r === null || !($r instanceof \PEAR_Error), 'Net_SMTP::data');
        return $smtp->captured;
    }

    /**
     * Receiving MTA: strip the terminator, undo dot-stuffing.
     */
    private static function mtaReceive(string $dataStream): string
    {
        self::assertStringEndsWith("\r\n.\r\n", $dataStream);
        $d = substr($dataStream, 0, -3);
        $lines = explode("\r\n", $d);
        foreach ($lines as $i => $l) {
            if (str_starts_with($l, '.')) {
                $lines[$i] = substr($l, 1);
            }
        }
        return implode("\r\n", $lines);
    }

    /**
     * rcube_imap_generic APPEND (string, no BINARY): drop every CR, LF -> CRLF.
     */
    private static function imapAppend(string $msg): string
    {
        return str_replace("\n", "\r\n", str_replace("\r", '', $msg));
    }

    // ================================================================== openssl CLI

    /**
     * @param list<string> $args
     *
     * @return array{0: int, 1: string}
     */
    private function openssl(array $args): array
    {
        $p = proc_open(array_merge([self::OPENSSL], $args), [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($p);
        fclose($pipes[0]);
        $out = (string) stream_get_contents($pipes[1]);
        $err = (string) stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        return [proc_close($p), $out . $err];
    }

    private function tmp(string $data = ''): string
    {
        $f = $this->dir . '/t' . bin2hex(random_bytes(6));
        file_put_contents($f, $data);
        $this->tmpFiles[] = $f;
        return $f;
    }

    /**
     * Independent verification (chain to root.crt, S/MIME purpose). Returns the signed content or null.
     */
    private function opensslVerify(string $mime): ?string
    {
        $in = $this->tmp($mime);
        $out = $this->tmp();
        [$rc] = $this->openssl(['cms', '-verify', '-CAfile', TestPki::path('root.crt'), '-purpose', 'smimesign', '-in', $in, '-out', $out]);
        return $rc === 0 ? (string) file_get_contents($out) : null;
    }

    private function signerPem(string $mime): string
    {
        $in = $this->tmp($mime);
        $out = $this->tmp();
        $signer = $this->tmp();
        [$rc, $o] = $this->openssl(['cms', '-verify', '-CAfile', TestPki::path('root.crt'), '-in', $in, '-out', $out, '-signer', $signer]);
        self::assertSame(0, $rc, $o);
        return (string) file_get_contents($signer);
    }

    private function signerEmail(string $mime): string
    {
        return Certificate::fromString($this->signerPem($mime))->emails()[0] ?? '';
    }

    private function signerFingerprint(string $mime): string
    {
        return Certificate::fromString($this->signerPem($mime))->fingerprint;
    }

    /**
     * Decrypt as $who (fixture or runtime key). Returns the plaintext entity or null.
     */
    private function opensslDecrypt(string $mime, string $who): ?string
    {
        $in = $this->tmp($mime);
        $out = $this->tmp();
        [$rc] = $this->openssl(['cms', '-decrypt', '-recip', TestPki::path($who . '.crt'), '-inkey', TestPki::path($who . '.key'), '-in', $in, '-out', $out]);
        return $rc === 0 ? (string) file_get_contents($out) : null;
    }

    /**
     * Runtime-generated second certificate for alice that expires later than alice.crt.
     *
     * @return array{p12: string, cert: Certificate}
     */
    private function issueNewerAliceCert(): array
    {
        $d = $this->dir . '/rot';
        mkdir($d, 0700);
        file_put_contents($d . '/ext.cnf', "[e]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
            . "extendedKeyUsage=emailProtection\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\nsubjectAltName=email:alice@example.test\n");
        $na = gmdate('YmdHis', TestPki::cert('alice')->notAfter + 86400 * 30) . 'Z';
        $nb = gmdate('YmdHis', time() - 3600) . 'Z';
        foreach ([
            ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', $d . '/k.pem'],
            ['req', '-new', '-key', $d . '/k.pem', '-subj', '/C=PL/O=MIME Shield TEST ONLY/CN=alice rotated (TEST ONLY)', '-out', $d . '/r.csr'],
            ['x509', '-req', '-in', $d . '/r.csr', '-CA', TestPki::path('int.crt'), '-CAkey', TestPki::path('int.key'), '-set_serial', '0x' . bin2hex(random_bytes(8)),
                '-sha256', '-not_before', $nb, '-not_after', $na, '-extfile', $d . '/ext.cnf', '-extensions', 'e', '-out', $d . '/c.pem'],
            ['pkcs12', '-export', '-inkey', $d . '/k.pem', '-in', $d . '/c.pem', '-certfile', TestPki::path('int.crt'), '-passout', 'pass:rot-pass', '-out', $d . '/a.p12'],
        ] as $cmd) {
            [$rc, $o] = $this->openssl($cmd);
            self::assertSame(0, $rc, implode(' ', $cmd) . ': ' . $o);
        }
        return ['p12' => (string) file_get_contents($d . '/a.p12'), 'cert' => Certificate::fromString((string) file_get_contents($d . '/c.pem'))];
    }

    // ================================================================== MIME helpers

    private static function crlf(string $s): string
    {
        return (string) preg_replace('/\r\n|\r|\n/', "\r\n", $s);
    }

    /**
     * Unfolded value of a top-level header (first occurrence) or null.
     */
    private static function header(string $msg, string $name): ?string
    {
        $pos = strpos($msg, "\r\n\r\n");
        $head = $pos === false ? $msg : substr($msg, 0, $pos);
        $head = (string) preg_replace('/\r\n[ \t]+/', ' ', $head);
        foreach (explode("\r\n", $head) as $line) {
            $p = strpos($line, ':');
            if ($p !== false && strcasecmp(substr($line, 0, $p), $name) === 0) {
                return trim(substr($line, $p + 1));
            }
        }
        return null;
    }

    private static function bodyOf(string $msg): string
    {
        $pos = strpos($msg, "\r\n\r\n");
        self::assertNotFalse($pos);
        return substr($msg, $pos + 4);
    }

    /**
     * Unfolded header lines, sorted.
     *
     * @return list<string>
     */
    private static function headerLines(string $msg): array
    {
        $pos = (int) strpos($msg, "\r\n\r\n");
        $lines = explode("\r\n", (string) preg_replace('/\r\n[ \t]+/', ' ', substr($msg, 0, $pos)));
        sort($lines);
        return $lines;
    }

    private static function withoutHeader(string $msg, string $name): string
    {
        $pos = (int) strpos($msg, "\r\n\r\n");
        $head = substr($msg, 0, $pos);
        $head = (string) preg_replace('/^' . preg_quote($name, '/') . ':[^\r\n]*(\r\n[ \t][^\r\n]*)*(\r\n|$)/mi', '', $head);
        return rtrim($head, "\r\n") . substr($msg, $pos);
    }

    private static function envelopeDer(string $msgOrBody): string
    {
        $pos = strpos($msgOrBody, "\r\n\r\n");
        $body = ($pos !== false && preg_match('/^[\x21-\x39\x3B-\x7E]+:/', $msgOrBody)) ? substr($msgOrBody, $pos + 4) : $msgOrBody;
        $der = base64_decode((string) preg_replace('/\s+/', '', $body), true);
        self::assertIsString($der);
        return $der;
    }

    /**
     * @return list<string>
     */
    private static function recipientSerials(string $msgOrBody): array
    {
        $out = [];
        foreach (CmsInspector::envelopedData(self::envelopeDer($msgOrBody))['recipients'] as $ri) {
            self::assertArrayHasKey('serial', $ri, 'issuerAndSerialNumber recipient identifiers');
            $out[] = $ri['serial'];
        }
        return $out;
    }

    /**
     * Leaf parts of a MIME entity: [type, name, data(decoded), headers].
     *
     * @return list<array{type: string, name: string, data: string, cte: string}>
     */
    private static function leaves(string $entity): array
    {
        $pos = strpos($entity, "\r\n\r\n");
        if (str_starts_with($entity, "\r\n")) {
            $head = '';
            $body = substr($entity, 2);
        } else {
            self::assertNotFalse($pos, 'entity without header/body separator');
            $head = substr($entity, 0, $pos);
            $body = substr($entity, $pos + 4);
        }
        $ct = self::header($head . "\r\n\r\n", 'Content-Type') ?? 'text/plain';
        $cte = strtolower((string) (self::header($head . "\r\n\r\n", 'Content-Transfer-Encoding') ?? '7bit'));
        $cd = (string) self::header($head . "\r\n\r\n", 'Content-Disposition');
        $type = strtolower(trim(explode(';', $ct)[0]));

        if (str_starts_with($type, 'multipart/')) {
            self::assertSame(1, preg_match('/boundary="?([^";]+)"?/i', $ct, $bm), 'boundary in ' . $ct);
            $segments = explode("\r\n--" . $bm[1], "\r\n" . $body);
            $out = [];
            foreach (array_slice($segments, 1) as $seg) {
                if (str_starts_with($seg, '--')) {
                    break;
                }
                $nl = strpos($seg, "\r\n");
                self::assertNotFalse($nl);
                $out = array_merge($out, self::leaves(substr($seg, $nl + 2)));
            }
            return $out;
        }

        $data = match ($cte) {
            'base64' => (string) base64_decode((string) preg_replace('/\s+/', '', $body), true),
            'quoted-printable' => quoted_printable_decode($body),
            default => $body,
        };
        $name = '';
        if (preg_match('/filename\*?="?([^";]+)"?/i', $cd, $nm) || preg_match('/name\*?="?([^";]+)"?/i', $ct, $nm)) {
            $name = $nm[1];
        }
        return [['type' => $type, 'name' => $name, 'data' => $data, 'cte' => $cte]];
    }

    /**
     * Compare the decoded leaves of an inner entity with the expected payloads.
     *
     * @param list<array{type: string, data: string, name?: string}> $expected
     */
    private function assertPayload(string $entity, array $expected, bool $clearSigned): void
    {
        $leaves = self::leaves($entity);
        self::assertCount(count($expected), $leaves, 'number of leaf parts');
        foreach ($expected as $i => $exp) {
            $leaf = $leaves[$i];
            self::assertContains($leaf['type'], explode('|', $exp['type']), "part $i type");
            if (str_starts_with($leaf['type'], 'text/')) {
                self::assertSame('quoted-printable', $leaf['cte'], 'text parts are QP');
                self::assertSame(rtrim($exp['data'], "\r\n"), rtrim($leaf['data'], "\r\n"), "part $i text");
            } else {
                self::assertSame(strlen($exp['data']), strlen($leaf['data']), "part $i length");
                self::assertSame(hash('sha256', $exp['data']), hash('sha256', $leaf['data']), "part $i data");
            }
            if (isset($exp['name'])) {
                self::assertSame($exp['name'], $leaf['name'], "part $i name");
            }
            if ($exp['type'] === 'message/rfc822|application/octet-stream') {
                self::assertSame($clearSigned ? 'application/octet-stream' : 'message/rfc822', $leaf['type']);
                self::assertSame($clearSigned ? 'base64' : '8bit', $leaf['cte']);
            }
        }
        if ($clearSigned) {
            self::assertSame(0, preg_match('/[\x80-\xFF]/', $entity), 'signed content is 7-bit');
        }
    }

    /**
     * @param list<array{type: string, data: string, name?: string}> $expected
     */
    private function assertInner(string $inner, bool $signed, array $expected): void
    {
        $inner = self::crlf($inner);
        if ($signed) {
            self::assertStringStartsWith('multipart/signed', (string) self::header($inner, 'Content-Type'));
            $content = $this->opensslVerify($inner);
            self::assertNotNull($content, 'inner signature must verify');
            // signed inside encryption: never the triple wrap, 8-bit parts stay (protected by the envelope)
            $this->assertPayload(self::crlf($content), $expected, false);
        } else {
            self::assertStringNotContainsString('pkcs7-signature', $inner);
            $this->assertPayload($inner, $expected, false);
        }
    }

    private function assertLabel(string $label, callable $fn): void
    {
        try {
            $fn();
        } catch (ValidationException|StorageException|\MimeShield\Exception\CryptoException $e) {
            self::assertSame($label, $e->getUserLabel(), get_class($e) . ': ' . $e->getMessage());
            return;
        }
        self::fail('expected exception with label ' . $label);
    }

    private static function rmTree(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($it as $f) {
            if ($f->isDir() && !$f->isLink()) {
                @rmdir($f->getPathname());
            } else {
                @chmod($f->getPathname(), 0600);
                @unlink($f->getPathname());
            }
        }
        @rmdir($dir);
    }
}
