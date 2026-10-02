<?php

declare(strict_types=1);

namespace MimeShield\Tests\Integration;

use MimeShield\Cert\KeyImporter;
use MimeShield\Crypto\CmsService;
use MimeShield\KeyStore\KeyVault;
use MimeShield\KeyStore\MasterKeyProvider;
use MimeShield\Mime\EntityBuilder;
use MimeShield\Mime\IncomingProcessor;
use MimeShield\Mime\PartStatus;
use MimeShield\Service\KeyService;
use MimeShield\Service\SignatureVerifier;
use MimeShield\Storage\Database;
use MimeShield\Storage\KeyRepository;
use MimeShield\Tests\TestPki;
use MimeShield\Trust\ChainValidator;
use MimeShield\Trust\RevocationChecker;
use MimeShield\Trust\TrustStore;
use MimeShield\Trust\VerificationResult;
use PHPUnit\Framework\TestCase;

/**
 * IncomingProcessor::partStructure() on real Roundcube objects (rcube_message, rcube_message_part,
 * rcube_mime parser) without IMAP: the storage is a rcube_imap subclass that serves IMAP sections of
 * an in-memory raw message; keys come from a temporary SQLite database (real KeyService/KeyVault).
 */
final class IncomingProcessorTest extends TestCase
{
    private const OPENSSL = '/usr/bin/openssl';
    private const USER_ALICE = 1;
    private const USER_BOB = 2;
    private const UID = 4242;
    private const FOLDER = 'INBOX';
    private const MAX = 10485760;

    private const TEXT = "Content-Type: text/plain; charset=us-ascii\r\nContent-Transfer-Encoding: 7bit\r\n\r\nHello Bob, SECRET-PLAINTEXT-MARKER here.\r\nSecond line.\r\n";

    private static string $base = '';
    private static string $dbFile = '';
    private static string $envName = '';
    private static ?Database $db = null;
    private static ?KeyVault $vault = null;

    private string $tmp = '';

    /** @var list<array{0: string, 1: mixed}> storage calls of the current test */
    private array $calls = [];

    public static function setUpBeforeClass(): void
    {
        if (!MIMESHIELD_RC_LOADED) {
            return;
        }
        self::$base = TestPki::tempDir();
        self::$dbFile = self::$base . '/rc.sqlite';
        $rdb = \rcube_db::factory('sqlite:///' . self::$dbFile . '?mode=0600');
        $rdb->db_connect('w');
        $sql = (string) preg_replace('/^--.*$/m', '', (string) file_get_contents(__DIR__ . '/../../SQL/sqlite.initial.sql'));
        foreach (array_filter(array_map('trim', explode(';', $sql))) as $stmt) {
            $res = $rdb->query($stmt);
            if ($rdb->is_error($res)) {
                throw new \RuntimeException('schema: ' . $rdb->is_error($res));
            }
        }
        foreach ([self::USER_ALICE => 'alice', self::USER_BOB => 'bob'] as $id => $name) {
            $rdb->query('INSERT INTO users (user_id, username, mail_host, created) VALUES (?, ?, ?, ?)', $id, $name, 'localhost', Database::now());
        }
        self::$db = new Database($rdb);

        self::$envName = 'MIMESHIELD_TEST_MK_' . strtoupper(bin2hex(random_bytes(6)));
        putenv(self::$envName . '=k1:' . base64_encode(random_bytes(32)));
        self::$vault = new KeyVault(new MasterKeyProvider('', self::$envName, ''));

        self::keyService(self::USER_ALICE)->import(TestPki::read('alice.p12'), TestPki::PASSWORD, []);
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$envName !== '') {
            putenv(self::$envName);
        }
        self::$db = null;
        self::$vault = null;
        if (self::$base !== '') {
            self::rmTree(self::$base);
        }
    }

    protected function setUp(): void
    {
        if (!MIMESHIELD_RC_LOADED) {
            self::markTestSkipped('needs Roundcube (MIMESHIELD_RC)');
        }
        $this->tmp = TestPki::tempDir();
        $this->calls = [];
        $GLOBALS['mimeshield_test_log'] = [];
    }

    protected function tearDown(): void
    {
        if ($this->tmp !== '') {
            self::rmTree($this->tmp);
        }
    }

    // --- service graph -------------------------------------------------------------------------

    private static function keyService(int $userId): KeyService
    {
        return new KeyService(new KeyRepository(self::$db, $userId), self::$vault, new KeyImporter(1048576, 2048), null, 10);
    }

    private function cms(): CmsService
    {
        return new CmsService($this->tmp);
    }

    private function verifier(): SignatureVerifier
    {
        $store = new TrustStore([TestPki::path('root.crt')], false, []);
        return new SignatureVerifier(new ChainValidator($store, $this->tmp), $store, new RevocationChecker(RevocationChecker::MODE_OFF, null, ''));
    }

    private function processor(string $raw, int $userId = self::USER_ALICE, bool $verify = true, bool $allowDecrypt = true): IncomingProcessor
    {
        $storage = $this->storage($raw);
        return new IncomingProcessor(
            self::keyService($userId),
            $this->cms(),
            $verify ? $this->verifier() : null,
            static fn () => $storage,
            self::MAX,
            $allowDecrypt,
        );
    }

    /**
     * rcube_imap without a connection, serving IMAP sections of $raw.
     */
    private function storage(string $raw): \rcube_imap
    {
        $calls = &$this->calls;
        return new class ($raw, $calls) extends \rcube_imap {
            /** @var list<array{0: string, 1: mixed}> */
            private array $log;

            /**
             * @param list<array{0: string, 1: mixed}> $log
             */
            public function __construct(private readonly string $raw, array &$log)
            {
                // no parent constructor: never create an IMAP connection
                $this->log = &$log;
            }

            public function set_folder($folder)
            {
                $this->log[] = ['set_folder', $folder];
                $this->folder = $folder;
            }

            public function get_raw_body($uid, $fp = null, $part = null)
            {
                $this->log[] = ['get_raw_body', $part];
                if ((int) $uid !== IncomingProcessorTest::uid() || $this->folder !== 'INBOX') {
                    return false;
                }
                return MimeSections::section($this->raw, $part === null ? null : (string) $part);
            }

            public function get_message_part($uid, $part, $o_part = null, $print = null, $fp = null,
                $skip_charset_conv = false, $max_bytes = 0, $formatted = true)
            {
                $this->log[] = ['get_message_part', $part];
                if ((int) $uid !== IncomingProcessorTest::uid() || $this->folder !== 'INBOX') {
                    return false;
                }
                $data = MimeSections::section($this->raw, $part ? (string) $part : 'TEXT');
                if ($data === false) {
                    return false;
                }
                return match (strtolower((string) ($o_part->encoding ?? ''))) {
                    'base64' => (string) base64_decode($data),
                    'quoted-printable' => quoted_printable_decode($data),
                    default => $data,
                };
            }
        };
    }

    public static function uid(): int
    {
        return self::UID;
    }

    // --- message construction ------------------------------------------------------------------

    /**
     * rcube_message as Roundcube would build it from IMAP (structure without bodies, mime ids as
     * rcube_imap assigns them, mime_parts filled BY REFERENCE like rcube_message::get_mime_numbers()).
     */
    private static function message(string $raw): \rcube_message
    {
        $struct = \rcube_mime::parse_message($raw);
        self::assertInstanceOf(\rcube_message_part::class, $struct);
        self::imapify($struct);
        if (empty($struct->parts)) {
            $struct->mime_id = '1'; // rcube_imap: single-part message
        }

        $h = new \rcube_message_header();
        $h->uid = self::UID;
        $h->from = $struct->headers['from'] ?? null;
        $h->to = $struct->headers['to'] ?? null;
        $h->subject = $struct->headers['subject'] ?? null;
        if (isset($struct->headers['sender'])) {
            $h->others['sender'] = $struct->headers['sender'];
        }
        $h->structure = $struct;

        $msg = (new \ReflectionClass(\rcube_message::class))->newInstanceWithoutConstructor();
        $msg->uid = self::UID;
        $msg->folder = self::FOLDER;
        $msg->headers = $h;
        $msg->parts = [];
        $msg->attachments = [];
        $msg->mime_parts = [];
        $fill = static function (\rcube_message_part &$part) use (&$fill, $msg): void {
            if (strlen((string) $part->mime_id)) {
                $msg->mime_parts[$part->mime_id] = &$part;
            }
            for ($i = 0; $i < count($part->parts); $i++) {
                $fill($part->parts[$i]);
            }
        };
        $fill($msg->headers->structure);
        return $msg;
    }

    /**
     * Strip parsed bodies (IMAP structures carry none) and flatten message/rfc822 parts like rcube_imap.
     */
    private static function imapify(\rcube_message_part $part): void
    {
        if ($part->mimetype === 'message/rfc822' && is_string($part->body) && $part->body !== '') {
            $embedded = \rcube_mime::parse_message(EntityBuilder::canonicalizeLineEndings($part->body));
            self::assertInstanceOf(\rcube_message_part::class, $embedded);
            $id = (string) $part->mime_id;
            $part->real_mimetype = $embedded->mimetype;
            // rcube_message::parse_structure() fills these from the part body before the hook
            $part->headers = $embedded->headers;
            if (!empty($embedded->parts)) {
                $part->parts = $embedded->parts;
                foreach ($part->parts as $c) {
                    self::prefixIds($c, $id);
                }
            } else {
                $embedded->mime_id = $id . '.1';
                $part->parts = [$embedded];
            }
        }
        $part->body = null;
        foreach ($part->parts as $c) {
            self::imapify($c);
        }
    }

    private static function prefixIds(\rcube_message_part $part, string $prefix): void
    {
        $part->mime_id = $prefix . '.' . $part->mime_id;
        foreach ($part->parts as $c) {
            self::prefixIds($c, $prefix);
        }
    }

    private static function headers(string $from = 'Alice <alice@example.test>', ?string $sender = null, string $subject = 'test'): string
    {
        return 'From: ' . $from . "\r\n"
            . ($sender !== null ? 'Sender: ' . $sender . "\r\n" : '')
            . "To: Bob <bob@example.test>\r\n"
            . 'Subject: ' . $subject . "\r\n"
            . "Date: Fri, 02 Oct 2026 10:00:00 +0000\r\n"
            . 'Message-ID: <' . bin2hex(random_bytes(6)) . "@example.test>\r\n"
            . "MIME-Version: 1.0\r\n";
    }

    /**
     * Clear-signed entity (Content-Type header + body) signed by $signer.
     */
    private function clearSignedEntity(string $inner = self::TEXT, string $signer = 'alice'): string
    {
        $sig = $this->cms()->signDetached($inner, TestPki::cert($signer), TestPki::key($signer), [TestPki::read('int.crt')]);
        return EntityBuilder::clearSignedEntity($inner, $sig, 'sha-256');
    }

    private function clearSignedMessage(string $from = 'Alice <alice@example.test>', ?string $sender = null): string
    {
        return self::headers($from, $sender) . $this->clearSignedEntity();
    }

    /**
     * Opaque SignedData (DER) over $entity, created with the openssl CLI.
     */
    private function opaqueSign(string $entity, string $signer = 'alice'): string
    {
        $in = $this->tmp . '/op-' . bin2hex(random_bytes(4));
        file_put_contents($in, $entity);
        $chain = $in . '.chain';
        file_put_contents($chain, TestPki::read('int.crt'));
        self::sh([self::OPENSSL, 'cms', '-sign', '-nodetach', '-binary', '-md', 'sha256', '-in', $in,
            '-signer', TestPki::path($signer . '.crt'), '-inkey', TestPki::path($signer . '.key'),
            '-certfile', $chain, '-outform', 'DER', '-out', $in . '.der']);
        return (string) file_get_contents($in . '.der');
    }

    private static function pkcs7Entity(string $der, string $contentType): string
    {
        return 'Content-Type: ' . $contentType . "\r\n"
            . "Content-Transfer-Encoding: base64\r\n"
            . "Content-Disposition: attachment; filename=\"smime.p7m\"\r\n"
            . "\r\n"
            . rtrim(chunk_split(base64_encode($der), 76, "\r\n"), "\r\n") . "\r\n";
    }

    private function envelopedMessage(string $inner, array $recipients = ['alice'], string $from = 'Bob <bob@example.test>'): string
    {
        $der = $this->cms()->encrypt($inner, array_map(static fn (string $n) => TestPki::cert($n), $recipients), CmsService::CIPHER_AES_256_CBC);
        return self::headers($from) . self::envelopedEntity($der);
    }

    private static function envelopedEntity(string $der, bool $auth = false): string
    {
        $e = EntityBuilder::enveloped($der, $auth);
        $out = '';
        foreach ($e['headers'] as $k => $v) {
            $out .= $k . ': ' . $v . "\r\n";
        }
        return $out . "\r\n" . $e['body'];
    }

    // --- hook drivers --------------------------------------------------------------------------

    /**
     * One message_part_structure call with the arguments rcube_message::parse_structure() passes.
     *
     * @return array<string, mixed>
     */
    private static function hook(IncomingProcessor $proc, \rcube_message $msg, \rcube_message_part $struct, bool $recursive = false): array
    {
        $mimetype = $struct->mimetype === 'message/rfc822' && !empty($struct->real_mimetype) ? $struct->real_mimetype : $struct->mimetype;
        $p = ['object' => $msg, 'structure' => $struct, 'mimetype' => $mimetype, 'recursive' => $recursive];
        $res = $proc->partStructure($p);
        self::assertSame($msg, $res['object']);
        self::assertInstanceOf(\rcube_message_part::class, $res['structure']);
        self::assertIsString($res['mimetype']);
        return $res;
    }

    /**
     * Emulates where rcube_message::parse_structure() fires the hook: every node passed to
     * parse_structure (top, multipart and message/rfc822 children) and text leaves inside multiparts.
     * application/* leaves inside a multipart never reach the hook.
     *
     * @return array<string, mixed> result of the top-level call
     */
    private static function walk(IncomingProcessor $proc, \rcube_message $msg, ?\rcube_message_part $struct = null, bool $recursive = false): array
    {
        $res = self::hook($proc, $msg, $struct ?? $msg->headers->structure, $recursive);
        $node = $res['structure'];
        if (str_starts_with($res['mimetype'], 'multipart/') || $node->mimetype === 'message/rfc822') {
            foreach ($node->parts as $child) {
                if ($child->ctype_primary === 'multipart' || $child->mimetype === 'message/rfc822') {
                    self::walk($proc, $msg, $child, true);
                } elseif (in_array($child->mimetype, ['text/plain', 'text/html'], true) && $child->disposition !== 'attachment') {
                    self::hook($proc, $msg, $child, true);
                }
            }
        }
        return $res;
    }

    private function assertNoInternalError(IncomingProcessor $proc): void
    {
        foreach ($proc->statuses() as $st) {
            self::assertNotSame('internalerror', $st->signatureError, 'internal error for part ' . $st->partId);
        }
        foreach ($GLOBALS['mimeshield_test_log'] ?? [] as $line) {
            self::assertStringNotContainsString('unexpected error', (string) $line);
        }
    }

    private static function partStatus(IncomingProcessor $proc, string $id): PartStatus
    {
        $st = $proc->statuses()[$id] ?? null;
        self::assertInstanceOf(PartStatus::class, $st, 'no status for part ' . $id . ' (have: ' . implode(',', array_keys($proc->statuses())) . ')');
        return $st;
    }

    /**
     * @param array<array-key, mixed> $parts
     *
     * @return list<string>
     */
    private static function ids(array $parts): array
    {
        return array_map('strval', array_keys($parts));
    }

    /**
     * @return list<string>
     */
    private static function labels(VerificationResult $r): array
    {
        return array_map(static fn (array $l) => $l[0], $r->lines());
    }

    // --- clear-signed --------------------------------------------------------------------------

    public function testClearSignedTopLevelIsVerifiedAndSignaturePartHidden(): void
    {
        $raw = $this->clearSignedMessage();
        $msg = self::message($raw);
        $orig = $msg->headers->structure;
        self::assertSame('0', $orig->mime_id);
        $proc = $this->processor($raw);

        $res = self::hook($proc, $msg, $orig);

        // structure left as is: Roundcube displays the first part
        self::assertSame($orig, $res['structure']);
        self::assertSame('multipart/signed', $res['mimetype']);
        self::assertSame(['2'], self::ids(array_flip($proc->hiddenParts())));

        $st = self::partStatus($proc, '0');
        self::assertNull($st->decryption);
        self::assertNull($st->signatureError);
        self::assertFalse($st->partial);
        $sig = $st->signature;
        self::assertNotNull($sig);
        self::assertTrue($sig->cryptoValid());
        self::assertSame(VerificationResult::IDENTITY_MATCH, $sig->identity);
        self::assertSame(VerificationResult::LEVEL_OK, $sig->level());
        self::assertSame('status_sig_ok', $sig->headline());
        self::assertTrue($sig->chain?->isTrusted());
        self::assertSame(['alice@example.test'], $sig->fromAddresses);

        self::assertSame($sig, $proc->rootSignature());
        self::assertTrue($proc->hasSignature());
        self::assertFalse($proc->hasDecrypted());
        self::assertSame($st, $proc->statusFor('1'));
        self::assertSame($st, $proc->statusFor('2'));
        self::assertFalse($proc->isDecryptedPart('1'));

        // exact bytes came from BODY[TEXT]
        self::assertContains(['get_raw_body', 'TEXT'], $this->calls);
        self::assertContains(['set_folder', self::FOLDER], $this->calls);
        $this->assertNoInternalError($proc);
    }

    public function testHiddenSignaturePartIsRemovedByMessageLoadFilter(): void
    {
        $raw = $this->clearSignedMessage();
        $msg = self::message($raw);
        $proc = $this->processor($raw, self::USER_ALICE, false);
        self::hook($proc, $msg, $msg->headers->structure);
        // Roundcube lists smime.p7s (mime_id '2') as attachment
        $msg->attachments = [$msg->mime_parts['2']];

        // exact filter used by mimeshield::message_load()
        $hidden = $proc->hiddenParts();
        $left = array_values(array_filter($msg->attachments, static fn ($a) => !in_array((string) $a->mime_id, $hidden, true)));

        self::assertSame([], $left, 'smime.p7s of a top-level clear-signed message must be hidden');
        self::assertContainsOnly('string', $hidden, true, 'hiddenParts() is declared list<string>');
    }

    public function testTamperedClearSignedBodyIsReportedModified(): void
    {
        $raw = $this->clearSignedMessage();
        $tampered = str_replace('Second line.', 'Second lime.', $raw);
        self::assertNotSame($raw, $tampered);
        $msg = self::message($tampered);
        $proc = $this->processor($tampered);

        self::hook($proc, $msg, $msg->headers->structure);

        $sig = self::partStatus($proc, '0')->signature;
        self::assertNotNull($sig);
        self::assertFalse($sig->cryptoValid());
        self::assertSame('modified', $sig->check->failure);
        self::assertSame('sig_modified', $sig->lines()[0][0]);
        self::assertSame(VerificationResult::LEVEL_ERROR, $sig->level());
        self::assertSame('status_sig_invalid', $sig->headline());
        self::assertSame(['2'], self::ids(array_flip($proc->hiddenParts())));
        $this->assertNoInternalError($proc);
    }

    public function testXPkcs7SignatureAliasIsRecognised(): void
    {
        $raw = str_replace('application/pkcs7-signature', 'application/x-pkcs7-signature', $this->clearSignedMessage());
        self::assertStringNotContainsString('application/pkcs7-signature', $raw);
        $msg = self::message($raw);
        self::assertSame('application/x-pkcs7-signature', $msg->headers->structure->parts[1]->mimetype);
        $proc = $this->processor($raw);

        self::hook($proc, $msg, $msg->headers->structure);

        $sig = self::partStatus($proc, '0')->signature;
        self::assertNotNull($sig);
        self::assertTrue($sig->cryptoValid());
        self::assertSame(VerificationResult::LEVEL_OK, $sig->level());
        self::assertSame(['2'], self::ids(array_flip($proc->hiddenParts())));
    }

    public function testWithoutVerifierSignatureIsOnlyHidden(): void
    {
        $raw = $this->clearSignedMessage();
        $msg = self::message($raw);
        $proc = $this->processor($raw, self::USER_ALICE, false);

        self::hook($proc, $msg, $msg->headers->structure);

        self::assertSame(['2'], self::ids(array_flip($proc->hiddenParts())));
        self::assertNull(self::partStatus($proc, '0')->signature);
        self::assertSame([], $this->calls, 'no IMAP fetch when signatures are not verified');
    }

    public function testFromMismatchIsDetected(): void
    {
        $raw = $this->clearSignedMessage('Mallory <mallory@example.test>');
        $msg = self::message($raw);
        $proc = $this->processor($raw);

        self::hook($proc, $msg, $msg->headers->structure);

        $sig = self::partStatus($proc, '0')->signature;
        self::assertNotNull($sig);
        self::assertTrue($sig->cryptoValid());
        self::assertSame(VerificationResult::IDENTITY_MISMATCH, $sig->identity);
        self::assertSame(VerificationResult::LEVEL_ERROR, $sig->level());
        self::assertSame('status_sig_mismatch', $sig->headline());
        self::assertContains('identity_mismatch', self::labels($sig));
        self::assertSame(['mallory@example.test'], $sig->fromAddresses);
    }

    public function testSenderHeaderMatchIsAWarningNotAMatch(): void
    {
        $raw = $this->clearSignedMessage('List <list@lists.example.test>', 'Alice <alice@example.test>');
        $msg = self::message($raw);
        self::assertSame('Alice <alice@example.test>', $msg->headers->get('sender', false));
        $proc = $this->processor($raw);

        self::hook($proc, $msg, $msg->headers->structure);

        $sig = self::partStatus($proc, '0')->signature;
        self::assertNotNull($sig);
        self::assertSame(VerificationResult::IDENTITY_SENDER, $sig->identity);
        self::assertSame(VerificationResult::LEVEL_WARNING, $sig->level());
        self::assertContains('identity_senderonly', self::labels($sig));
    }

    public function testFromWithTwoAddressesOnlyOneCoveredIsMismatch(): void
    {
        $raw = $this->clearSignedMessage('Alice <alice@example.test>, Mallory <mallory@example.test>');
        $msg = self::message($raw);
        $proc = $this->processor($raw);

        self::hook($proc, $msg, $msg->headers->structure);

        $sig = self::partStatus($proc, '0')->signature;
        self::assertNotNull($sig);
        self::assertSame(VerificationResult::IDENTITY_MISMATCH, $sig->identity);
        self::assertSame(VerificationResult::LEVEL_ERROR, $sig->level());
    }

    public function testNestedSignedPartInMixedIsPartial(): void
    {
        // mailing list style: signed message + footer appended by the list
        $b = 'outer-' . bin2hex(random_bytes(4));
        $raw = self::headers('Alice <alice@example.test>', 'list@lists.example.test')
            . 'Content-Type: multipart/mixed; boundary="' . $b . "\"\r\n\r\n"
            . '--' . $b . "\r\n"
            . $this->clearSignedEntity() . "\r\n"
            . '--' . $b . "\r\n"
            . "Content-Type: text/plain; charset=us-ascii\r\n\r\n"
            . "-- \r\nlist footer, unsubscribe here\r\n"
            . '--' . $b . "--\r\n";
        $msg = self::message($raw);
        self::assertSame('multipart/signed', $msg->mime_parts['1']->mimetype);
        $proc = $this->processor($raw);

        self::walk($proc, $msg);

        self::assertArrayNotHasKey('0', $proc->statuses());
        $st = self::partStatus($proc, '1');
        self::assertTrue($st->partial);
        $sig = $st->signature;
        self::assertNotNull($sig);
        self::assertTrue($sig->cryptoValid());
        self::assertTrue($sig->partial);
        self::assertSame(VerificationResult::IDENTITY_MATCH, $sig->identity);
        self::assertSame(VerificationResult::LEVEL_WARNING, $sig->level());
        self::assertContains('sig_partial', self::labels($sig));
        self::assertSame(['1.2'], self::ids(array_flip($proc->hiddenParts())));
        // a partial signature never counts as the message signature ("save certificate")
        self::assertNull($proc->rootSignature());
        self::assertSame($st, $proc->statusFor('1.1'));
        self::assertContains(['get_raw_body', '1'], $this->calls);
        $this->assertNoInternalError($proc);
    }

    public function testStatusForUnrelatedSiblingIsNotCoveredByPartialSignature(): void
    {
        $b = 'outer-' . bin2hex(random_bytes(4));
        $raw = self::headers()
            . 'Content-Type: multipart/mixed; boundary="' . $b . "\"\r\n\r\n"
            . '--' . $b . "\r\n"
            . $this->clearSignedEntity() . "\r\n"
            . '--' . $b . "\r\n"
            . "Content-Type: text/plain; charset=us-ascii\r\n\r\nunsigned footer\r\n"
            . '--' . $b . "--\r\n";
        $msg = self::message($raw);
        $proc = $this->processor($raw);
        self::walk($proc, $msg);
        self::assertNotNull(self::partStatus($proc, '1')->signature);

        // part '2' (the unsigned footer) is not a descendant of the signed part '1'
        $st = $proc->statusFor('2');
        self::assertTrue($st === null, 'unsigned sibling part 2 must not inherit the status of signed part ' . ($st?->partId ?? ''));
    }

    public function testForwardedSignedMessageIsCheckedAgainstEmbeddedFrom(): void
    {
        $b = 'outer-' . bin2hex(random_bytes(4));
        $embedded = self::headers('Alice <alice@example.test>', null, 'original') . $this->clearSignedEntity();
        $raw = self::headers('Carol <carol@example.test>', null, 'Fwd: original')
            . 'Content-Type: multipart/mixed; boundary="' . $b . "\"\r\n\r\n"
            . '--' . $b . "\r\n"
            . "Content-Type: text/plain; charset=us-ascii\r\n\r\nsee below\r\n"
            . '--' . $b . "\r\n"
            . "Content-Type: message/rfc822\r\nContent-Disposition: inline\r\n\r\n"
            . $embedded . "\r\n"
            . '--' . $b . "--\r\n";
        $msg = self::message($raw);
        $rfc = $msg->mime_parts['2'];
        self::assertSame('message/rfc822', $rfc->mimetype);
        self::assertSame('multipart/signed', $rfc->real_mimetype);
        self::assertSame('2.2', $rfc->parts[1]->mime_id);
        $proc = $this->processor($raw);

        self::walk($proc, $msg);

        $sig = self::partStatus($proc, '2')->signature;
        self::assertNotNull($sig);
        self::assertTrue($sig->cryptoValid(), 'signature over the embedded message body (BODY[2.TEXT])');
        self::assertSame(['alice@example.test'], $sig->fromAddresses);
        self::assertSame(VerificationResult::IDENTITY_MATCH, $sig->identity);
        self::assertSame(['2.2'], self::ids(array_flip($proc->hiddenParts())));
        self::assertContains(['get_raw_body', '2.TEXT'], $this->calls);
        // the outer (unsigned) message has no message-level signature
        self::assertNull($proc->rootSignature());
        self::assertNull($proc->statusFor('1'));
    }

    // --- opaque signed-data --------------------------------------------------------------------

    /**
     * @return iterable<string, array{0: string}>
     */
    public static function opaqueTypes(): iterable
    {
        yield 'pkcs7-mime' => ['application/pkcs7-mime; smime-type=signed-data; name="smime.p7m"'];
        yield 'x-pkcs7-mime' => ['application/x-pkcs7-mime; smime-type=signed-data; name="smime.p7m"'];
        yield 'octet-stream p7m' => ['application/octet-stream; name="smime.p7m"'];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('opaqueTypes')]
    public function testOpaqueSignedTopLevelIsUnwrappedAndVerified(string $contentType): void
    {
        $raw = self::headers() . self::pkcs7Entity($this->opaqueSign(self::TEXT), $contentType);
        $msg = self::message($raw);
        $orig = $msg->headers->structure;
        self::assertSame('1', $orig->mime_id);
        $before = serialize($orig);
        $proc = $this->processor($raw);

        $res = self::hook($proc, $msg, $orig);

        $new = $res['structure'];
        self::assertNotSame($orig, $new);
        self::assertSame('text/plain', $res['mimetype']);
        self::assertSame('text/plain', $new->mimetype);
        self::assertSame('1', $new->mime_id);
        self::assertTrue($new->body_modified);
        self::assertSame('stream', $new->encoding);
        self::assertIsString($new->body);
        self::assertStringContainsString('SECRET-PLAINTEXT-MARKER', $new->body);
        self::assertSame($new, $msg->mime_parts['1']);
        self::assertSame($orig, $msg->headers->structure);
        self::assertSame($before, serialize($orig));

        $st = self::partStatus($proc, '1');
        self::assertNull($st->decryption);
        self::assertFalse($st->partial);
        $sig = $st->signature;
        self::assertNotNull($sig);
        self::assertTrue($sig->cryptoValid());
        self::assertSame(VerificationResult::LEVEL_OK, $sig->level());
        self::assertSame($sig, $proc->rootSignature());
        self::assertContains(['get_message_part', '1'], $this->calls);
        $this->assertNoInternalError($proc);
    }

    public function testOpaqueSignedMultipartContentIsRenumberedUnderOldId(): void
    {
        $b = 'in-' . bin2hex(random_bytes(4));
        $inner = 'Content-Type: multipart/mixed; boundary="' . $b . "\"\r\n\r\n"
            . '--' . $b . "\r\n" . "Content-Type: text/plain; charset=us-ascii\r\n\r\nbody text\r\n"
            . '--' . $b . "\r\n" . "Content-Type: application/pdf; name=\"doc.pdf\"\r\nContent-Disposition: attachment; filename=\"doc.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\n"
            . base64_encode('%PDF-1.4 fake') . "\r\n"
            . '--' . $b . "--\r\n";
        $raw = self::headers() . self::pkcs7Entity($this->opaqueSign($inner), 'application/pkcs7-mime; smime-type=signed-data; name="smime.p7m"');
        $msg = self::message($raw);
        $proc = $this->processor($raw);

        $res = self::hook($proc, $msg, $msg->headers->structure);

        $new = $res['structure'];
        self::assertSame('multipart/mixed', $res['mimetype']);
        self::assertSame('1', $new->mime_id);
        self::assertSame('', $new->body, 'container must have a non-null body (no fake IMAP section fetch)');
        self::assertSame(['1.1', '1.2'], array_map(static fn ($p) => $p->mime_id, $new->parts));
        self::assertSame(['1', '1.1', '1.2'], self::ids($msg->mime_parts));
        self::assertSame('%PDF-1.4 fake', $msg->mime_parts['1.2']->body);
        self::assertSame('doc.pdf', $msg->mime_parts['1.2']->filename);
        foreach ($msg->mime_parts as $p) {
            self::assertTrue($p->body_modified);
            self::assertSame('stream', $p->encoding);
        }
        self::assertTrue(self::partStatus($proc, '1')->signature?->cryptoValid());
    }

    public function testTamperedOpaqueSignedIsShownButMarkedModified(): void
    {
        $der = $this->opaqueSign(self::TEXT);
        $pos = strpos($der, 'Second line.');
        self::assertIsInt($pos);
        $der[$pos] = 'X';
        $raw = self::headers() . self::pkcs7Entity($der, 'application/pkcs7-mime; smime-type=signed-data; name="smime.p7m"');
        $msg = self::message($raw);
        $proc = $this->processor($raw);

        $res = self::hook($proc, $msg, $msg->headers->structure);

        $sig = self::partStatus($proc, '1')->signature;
        self::assertNotNull($sig);
        self::assertFalse($sig->cryptoValid());
        self::assertSame('sig_modified', $sig->lines()[0][0]);
        self::assertSame(VerificationResult::LEVEL_ERROR, $sig->level());
        self::assertSame('text/plain', $res['mimetype']);
        self::assertStringContainsString('Xecond line.', (string) $res['structure']->body);
        self::assertSame($sig, $proc->rootSignature());
        self::assertFalse($sig->cryptoValid());
    }

    public function testDeeplyNestedOpaqueSignedTerminatesAtDepthLimit(): void
    {
        $entity = self::TEXT;
        for ($i = 0; $i < 6; $i++) {
            $entity = self::pkcs7Entity($this->opaqueSign($entity), 'application/pkcs7-mime; smime-type=signed-data; name="smime.p7m"');
        }
        $raw = self::headers() . $entity;
        $msg = self::message($raw);
        $proc = $this->processor($raw);

        $t = microtime(true);
        $res = self::hook($proc, $msg, $msg->headers->structure);
        self::assertLessThan(30, microtime(true) - $t);

        // five layers unwrapped (depth 0..4), the sixth is left as an S/MIME part for Roundcube
        self::assertSame('application/pkcs7-mime', $res['mimetype']);
        self::assertSame('1', $res['structure']->mime_id);
        self::assertTrue($res['structure']->body_modified);
        self::assertStringStartsWith("\x30", (string) $res['structure']->body, 'remaining layer is still a CMS structure');
        $sig = self::partStatus($proc, '1')->signature;
        self::assertNotNull($sig);
        self::assertTrue($sig->cryptoValid());
        self::assertCount(1, array_filter($this->calls, static fn ($c) => $c[0] === 'get_message_part'), 'only the outer layer is fetched from IMAP');
        $this->assertNoInternalError($proc);
    }

    // --- enveloped -----------------------------------------------------------------------------

    public function testEnvelopedForAliceIsDecrypted(): void
    {
        $raw = $this->envelopedMessage(self::TEXT);
        $msg = self::message($raw);
        $orig = $msg->headers->structure;
        $before = serialize($orig);
        $proc = $this->processor($raw);

        $res = self::hook($proc, $msg, $orig);

        $new = $res['structure'];
        self::assertSame('text/plain', $res['mimetype']);
        self::assertSame('1', $new->mime_id);
        self::assertTrue($new->body_modified);
        self::assertSame('stream', $new->encoding);
        self::assertStringContainsString('SECRET-PLAINTEXT-MARKER', (string) $new->body);
        self::assertSame($new, $msg->mime_parts['1']);

        $st = self::partStatus($proc, '1');
        self::assertTrue($st->decryption);
        self::assertSame('aes-256-cbc', $st->cipher);
        self::assertTrue($st->unauthenticated);
        self::assertFalse($st->notDecrypted);
        self::assertNull($st->signature);
        self::assertTrue($st->isEncrypted());
        self::assertFalse($st->isSigned());
        self::assertTrue($proc->hasDecrypted());
        self::assertFalse($proc->hasSignature());
        self::assertNull($proc->rootSignature());
        self::assertTrue($proc->isDecryptedPart('1'));

        // messages_cache leak guard: the cached original structure never sees plaintext
        self::assertSame($orig, $msg->headers->structure);
        $after = serialize($msg->headers->structure);
        self::assertSame($before, $after);
        self::assertStringNotContainsString('SECRET-PLAINTEXT-MARKER', $after);
        self::assertSame('application/pkcs7-mime', $orig->mimetype);
        $this->assertNoInternalError($proc);
    }

    public function testEnvelopedMultipartIsRenumberedAndOriginalTreeUntouched(): void
    {
        $b = 'in-' . bin2hex(random_bytes(4));
        $a = 'alt-' . bin2hex(random_bytes(4));
        $inner = 'Content-Type: multipart/mixed; boundary="' . $b . "\"\r\n\r\n"
            . '--' . $b . "\r\n"
            . 'Content-Type: multipart/alternative; boundary="' . $a . "\"\r\n\r\n"
            . '--' . $a . "\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nSECRET-PLAINTEXT-MARKER plain\r\n"
            . '--' . $a . "\r\nContent-Type: text/html; charset=us-ascii\r\n\r\n<p>SECRET-PLAINTEXT-MARKER html</p>\r\n"
            . '--' . $a . "--\r\n"
            . '--' . $b . "\r\n"
            . "Content-Type: image/png; name=\"x.png\"\r\nContent-Disposition: attachment; filename=\"x.png\"\r\nContent-Transfer-Encoding: base64\r\n\r\n"
            . base64_encode("\x89PNG-SECRET-PLAINTEXT-MARKER") . "\r\n"
            . '--' . $b . "--\r\n";
        $raw = $this->envelopedMessage($inner);
        $msg = self::message($raw);
        $before = serialize($msg->headers->structure);
        $proc = $this->processor($raw);

        $res = self::walk($proc, $msg);

        self::assertSame('multipart/mixed', $res['mimetype']);
        self::assertSame(['1', '1.1', '1.1.1', '1.1.2', '1.2'], self::ids($msg->mime_parts));
        self::assertSame('text/html', $msg->mime_parts['1.1.2']->mimetype);
        self::assertSame("\x89PNG-SECRET-PLAINTEXT-MARKER", $msg->mime_parts['1.2']->body);
        self::assertSame('', $msg->mime_parts['1.1']->body);
        foreach (['1', '1.1', '1.1.1', '1.1.2', '1.2'] as $id) {
            self::assertTrue($proc->isDecryptedPart($id), $id);
        }
        self::assertFalse($proc->isDecryptedPart('2'));
        self::assertFalse($proc->isDecryptedPart('10'));
        self::assertFalse($proc->isDecryptedPart(''));
        self::assertSame(self::partStatus($proc, '1'), $proc->statusFor('1.1.2'));
        self::assertSame($before, serialize($msg->headers->structure));
        self::assertStringNotContainsString('SECRET-PLAINTEXT-MARKER', serialize($msg->headers->structure));
        self::assertCount(1, $proc->statuses(), 'children of decrypted content get no own status');
        $this->assertNoInternalError($proc);
    }

    public function testDecryptedHtmlStaysAContentPart(): void
    {
        $html = "Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
            . "<html><body><p>SECRET-PLAINTEXT-MARKER</p><img src=3D\"http://tracker.example.test/x.png\"></body></html>\r\n";
        $raw = $this->envelopedMessage($html);
        $msg = self::message($raw);
        $proc = $this->processor($raw);

        $res = self::hook($proc, $msg, $msg->headers->structure);

        $new = $res['structure'];
        self::assertSame('text/html', $res['mimetype']);
        self::assertSame('text', $new->ctype_primary);
        self::assertSame('html', $new->ctype_secondary);
        self::assertNotSame('attachment', $new->disposition);
        self::assertSame('utf-8', strtolower((string) $new->charset));
        self::assertSame('stream', $new->encoding);
        // transfer-decoded, but otherwise untouched: washing is Roundcube's job
        self::assertStringContainsString('<img src="http://tracker.example.test/x.png">', (string) $new->body);
        self::assertTrue($proc->isDecryptedPart('1'));
    }

    public function testSignedAndEncryptedVerifiesInnerSignature(): void
    {
        $raw = self::headers() . self::envelopedEntity(
            $this->cms()->encrypt($this->clearSignedEntity(), [TestPki::cert('alice')], CmsService::CIPHER_AES_256_CBC)
        );
        $msg = self::message($raw);
        $before = serialize($msg->headers->structure);
        $proc = $this->processor($raw);

        $res = self::walk($proc, $msg);

        self::assertSame('multipart/signed', $res['mimetype']);
        self::assertSame('1', $res['structure']->mime_id);
        self::assertSame(['1', '1.1', '1.2'], self::ids($msg->mime_parts));
        $st = self::partStatus($proc, '1');
        self::assertTrue($st->decryption);
        self::assertSame('aes-256-cbc', $st->cipher);
        self::assertFalse($st->unauthenticated, 'integrity protected by the valid inner signature');
        self::assertFalse($st->partial);
        $sig = $st->signature;
        self::assertNotNull($sig);
        self::assertTrue($sig->cryptoValid());
        self::assertSame(VerificationResult::LEVEL_OK, $sig->level());
        self::assertSame('status_sig_ok', $sig->headline());
        self::assertSame($sig, $proc->rootSignature());
        self::assertSame(['1.2'], self::ids(array_flip($proc->hiddenParts())));
        self::assertSame($st, $proc->statusFor('1.1'));
        self::assertTrue($proc->isDecryptedPart('1.1'));
        // the signed content came from the decrypted entity, never from IMAP
        self::assertNotContains(['get_raw_body', 'TEXT'], $this->calls);
        self::assertNotContains(['get_raw_body', '1'], $this->calls);
        self::assertSame($before, serialize($msg->headers->structure));
        $this->assertNoInternalError($proc);
    }

    public function testSignedAndEncryptedWithTamperedInnerSignatureStaysUnauthenticated(): void
    {
        $entity = str_replace('Second line.', 'Second lime.', $this->clearSignedEntity());
        $raw = self::headers() . self::envelopedEntity($this->cms()->encrypt($entity, [TestPki::cert('alice')]));
        $msg = self::message($raw);
        $proc = $this->processor($raw);

        self::hook($proc, $msg, $msg->headers->structure);

        $st = self::partStatus($proc, '1');
        self::assertTrue($st->decryption);
        self::assertTrue($st->unauthenticated);
        self::assertNotNull($st->signature);
        self::assertSame('sig_modified', $st->signature->lines()[0][0]);
    }

    public function testGcmAuthEnvelopedIsDecryptedAndAuthenticated(): void
    {
        $in = $this->tmp . '/gcm-in';
        file_put_contents($in, self::TEXT);
        self::sh([self::OPENSSL, 'cms', '-encrypt', '-binary', '-aes-256-gcm', '-in', $in, '-outform', 'DER', '-out', $in . '.der', TestPki::path('alice.crt')]);
        $der = (string) file_get_contents($in . '.der');
        $raw = self::headers() . self::envelopedEntity($der, true);
        $msg = self::message($raw);
        $proc = $this->processor($raw);

        $res = self::hook($proc, $msg, $msg->headers->structure);

        $st = self::partStatus($proc, '1');
        self::assertTrue($st->decryption, 'decryption: ' . var_export($st->decryption, true));
        self::assertSame('aes-256-gcm', $st->cipher);
        self::assertFalse($st->unauthenticated);
        self::assertStringContainsString('SECRET-PLAINTEXT-MARKER', (string) $res['structure']->body);
        $this->assertNoInternalError($proc);
    }

    public function testCiphertextForSomeoneElseIsDecryptNokey(): void
    {
        $raw = $this->envelopedMessage(self::TEXT, ['bob']);
        $msg = self::message($raw);
        $orig = $msg->headers->structure;
        $proc = $this->processor($raw);

        $res = self::hook($proc, $msg, $orig);

        self::assertSame($orig, $res['structure']);
        self::assertSame('application/pkcs7-mime', $res['mimetype']);
        $st = self::partStatus($proc, '1');
        self::assertSame('decrypt_nokey', $st->decryption);
        self::assertTrue($st->isEncrypted());
        self::assertFalse($proc->hasDecrypted());
        self::assertFalse($proc->isDecryptedPart('1'));
        self::assertSame($orig, $msg->mime_parts['1']);
    }

    public function testUserWithoutKeysIsDecryptNokeys(): void
    {
        $raw = $this->envelopedMessage(self::TEXT, ['alice', 'bob']);
        $msg = self::message($raw);
        $proc = $this->processor($raw, self::USER_BOB);

        self::hook($proc, $msg, $msg->headers->structure);

        self::assertSame('decrypt_nokeys', self::partStatus($proc, '1')->decryption);
        self::assertFalse($proc->hasDecrypted());
    }

    public function testMultiRecipientCiphertextIsDecryptedByAlice(): void
    {
        $raw = $this->envelopedMessage(self::TEXT, ['bob', 'carol', 'alice']);
        $msg = self::message($raw);
        $proc = $this->processor($raw);

        $res = self::hook($proc, $msg, $msg->headers->structure);

        self::assertTrue(self::partStatus($proc, '1')->decryption);
        self::assertStringContainsString('SECRET-PLAINTEXT-MARKER', (string) $res['structure']->body);
    }

    /**
     * @return iterable<string, array{0: \Closure(string): string}>
     */
    public static function corruptions(): iterable
    {
        yield 'garbage' => [static fn (string $der): string => "\x01\x02this is not a CMS structure at all\xff"];
        yield 'truncated' => [static fn (string $der): string => substr($der, 0, intdiv(strlen($der), 2))];
        yield 'wrong outer tag' => [static fn (string $der): string => "\x31" . substr($der, 1)];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('corruptions')]
    public function testCorruptedCmsIsMalformed(\Closure $corrupt): void
    {
        $der = $this->cms()->encrypt(self::TEXT, [TestPki::cert('alice')]);
        $raw = self::headers() . self::envelopedEntity($corrupt($der));
        $msg = self::message($raw);
        $proc = $this->processor($raw);

        $res = self::hook($proc, $msg, $msg->headers->structure);

        self::assertSame('malformed', self::partStatus($proc, '1')->decryption);
        self::assertSame($msg->headers->structure, $res['structure']);
        self::assertFalse($proc->hasDecrypted());
        $this->assertNoInternalError($proc);
    }

    public function testEmptyPkcs7PartIsMalformed(): void
    {
        $raw = self::headers() . "Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=\"smime.p7m\"\r\nContent-Transfer-Encoding: base64\r\n\r\n\r\n";
        $msg = self::message($raw);
        $msg->headers->structure->size = 1;
        $proc = $this->processor($raw);

        self::hook($proc, $msg, $msg->headers->structure);

        self::assertSame('malformed', self::partStatus($proc, '1')->decryption);
    }

    public function testDecryptionDisabledLeavesCiphertext(): void
    {
        $raw = $this->envelopedMessage(self::TEXT);
        $msg = self::message($raw);
        $proc = $this->processor($raw, self::USER_ALICE, true, false);

        $res = self::hook($proc, $msg, $msg->headers->structure);

        $st = self::partStatus($proc, '1');
        self::assertTrue($st->notDecrypted);
        self::assertNull($st->decryption);
        self::assertSame('application/pkcs7-mime', $res['mimetype']);
        self::assertFalse($proc->hasDecrypted());
    }

    // --- EFAIL: nested encrypted parts are never decrypted ---------------------------------------

    public function testEncryptedAttachmentInsideMixedIsNotDecrypted(): void
    {
        $b = 'outer-' . bin2hex(random_bytes(4));
        $der = $this->cms()->encrypt(self::TEXT, [TestPki::cert('alice')]);
        $raw = self::headers()
            . 'Content-Type: multipart/mixed; boundary="' . $b . "\"\r\n\r\n"
            . '--' . $b . "\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nattacker controlled text\r\n"
            . '--' . $b . "\r\n" . self::envelopedEntity($der)
            . '--' . $b . "--\r\n";
        $msg = self::message($raw);
        $part = $msg->mime_parts['2'];
        self::assertSame('application/pkcs7-mime', $part->mimetype);
        $proc = $this->processor($raw);

        // Roundcube never fires the hook for an application/* leaf, but even if it did:
        $res = self::hook($proc, $msg, $part, true);

        self::assertSame($part, $res['structure']);
        $st = self::partStatus($proc, '2');
        self::assertTrue($st->notDecrypted);
        self::assertNull($st->decryption);
        self::assertFalse($proc->hasDecrypted());
        self::assertFalse($proc->isDecryptedPart('2'));
        self::assertSame($part, $msg->mime_parts['2']);
    }

    public function testEncryptedForwardedMessageIsNotDecryptedAndLabelledNested(): void
    {
        $b = 'outer-' . bin2hex(random_bytes(4));
        $embedded = $this->envelopedMessage(self::TEXT, ['alice']);
        $raw = self::headers('Mallory <mallory@example.test>', null, 'Fwd: secret')
            . 'Content-Type: multipart/mixed; boundary="' . $b . "\"\r\n\r\n"
            . '--' . $b . "\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nplease read the attached message\r\n"
            . '--' . $b . "\r\nContent-Type: message/rfc822\r\n\r\n"
            . $embedded
            . '--' . $b . "--\r\n";
        $msg = self::message($raw);
        $rfc = $msg->mime_parts['2'];
        self::assertSame('application/pkcs7-mime', $rfc->real_mimetype);
        self::assertSame('2.1', $rfc->parts[0]->mime_id);
        $proc = $this->processor($raw);

        self::walk($proc, $msg);

        // never decrypted (EFAIL / decryption oracle)
        self::assertFalse($proc->hasDecrypted());
        foreach ($msg->mime_parts as $p) {
            self::assertStringNotContainsString('SECRET-PLAINTEXT-MARKER', (string) $p->body);
        }
        // ... and reported as a deliberately not decrypted nested part, not as a broken message
        $st = self::partStatus($proc, '2');
        self::assertNull($st->decryption, 'got decryption label ' . var_export($st->decryption, true));
        self::assertTrue($st->notDecrypted);
    }

    /**
     * Audit MS-02: unwrapping the opaque SignedData of a forwarded message must not turn its content
     * into a "root" part - ciphertext nested inside it is never decrypted.
     */
    public function testForwardedOpaqueSignedEnvelopeIsNotDecrypted(): void
    {
        $b = 'outer-' . bin2hex(random_bytes(4));
        $enveloped = self::envelopedEntity($this->cms()->encrypt(self::TEXT, [TestPki::cert('alice')]));
        $embedded = self::headers('Bob <bob@example.test>', null, 'original')
            . self::pkcs7Entity($this->opaqueSign($enveloped, 'bob'), 'application/pkcs7-mime; smime-type=signed-data; name="smime.p7m"');
        $raw = self::headers('Mallory <mallory@example.test>', null, 'Fwd: original')
            . 'Content-Type: multipart/mixed; boundary="' . $b . "\"\r\n\r\n"
            . '--' . $b . "\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nplease read the attached message\r\n"
            . '--' . $b . "\r\nContent-Type: message/rfc822\r\n\r\n"
            . $embedded
            . '--' . $b . "--\r\n";
        $msg = self::message($raw);
        self::assertSame('message/rfc822', $msg->mime_parts['2']->mimetype);
        $proc = $this->processor($raw);

        self::walk($proc, $msg);

        self::assertFalse($proc->hasDecrypted());
        foreach ($msg->mime_parts as $p) {
            self::assertStringNotContainsString('SECRET-PLAINTEXT-MARKER', (string) $p->body);
        }
        $st = self::partStatus($proc, '2');
        self::assertTrue($st->partial, 'forwarded signature never covers the message');
        self::assertTrue($st->notDecrypted, 'nested ciphertext is reported as deliberately not decrypted');
        self::assertNotTrue($st->decryption);
        self::assertNull($proc->rootSignature());
        $this->assertNoInternalError($proc);
    }

    /**
     * Audit MS-02: a forwarded opaque SignedData wrapping another SignedData keeps the "partial"
     * label on every unwrapped layer.
     */
    public function testForwardedNestedOpaqueSignedStaysPartial(): void
    {
        $b = 'outer-' . bin2hex(random_bytes(4));
        $inner = self::pkcs7Entity($this->opaqueSign(self::TEXT, 'alice'), 'application/pkcs7-mime; smime-type=signed-data; name="smime.p7m"');
        $embedded = self::headers('Alice <alice@example.test>', null, 'original')
            . self::pkcs7Entity($this->opaqueSign($inner, 'alice'), 'application/pkcs7-mime; smime-type=signed-data; name="smime.p7m"');
        $raw = self::headers('Mallory <mallory@example.test>', null, 'Fwd: original')
            . 'Content-Type: multipart/mixed; boundary="' . $b . "\"\r\n\r\n"
            . '--' . $b . "\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nsee below\r\n"
            . '--' . $b . "\r\nContent-Type: message/rfc822\r\n\r\n"
            . $embedded
            . '--' . $b . "--\r\n";
        $msg = self::message($raw);
        $proc = $this->processor($raw);

        self::walk($proc, $msg);

        foreach ($proc->statuses() as $id => $st) {
            if ($st->signature !== null) {
                self::assertTrue($st->partial, 'signature status of part ' . $id . ' must be partial');
            }
        }
        self::assertNull($proc->rootSignature());
        self::assertFalse($proc->hasDecrypted());
        $this->assertNoInternalError($proc);
    }

    public function testOriginalStructureNeverContainsPlaintextAfterFullWalk(): void
    {
        $raw = self::headers() . self::envelopedEntity(
            $this->cms()->encrypt($this->clearSignedEntity(), [TestPki::cert('alice')])
        );
        $msg = self::message($raw);
        $orig = $msg->headers->structure;
        $origMimeParts = $msg->mime_parts;
        $before = serialize($orig);
        $proc = $this->processor($raw);

        self::walk($proc, $msg);
        // second request: fresh rcube_message from the same (cached) structure, same deterministic ids
        $msg2 = self::message($raw);
        $proc2 = $this->processor($raw);
        self::walk($proc2, $msg2);

        self::assertSame($before, serialize($orig));
        self::assertStringNotContainsString('SECRET-PLAINTEXT-MARKER', serialize($orig));
        self::assertNull($orig->body);
        self::assertFalse((bool) $orig->body_modified);
        self::assertSame($orig, $origMimeParts['1']);
        self::assertSame(self::ids($msg->mime_parts), self::ids($msg2->mime_parts));
        self::assertTrue(self::partStatus($proc2, '1')->signature?->cryptoValid());
    }

    // --- helpers -------------------------------------------------------------------------------

    /**
     * @param list<string> $cmd
     */
    private static function sh(array $cmd): void
    {
        $p = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($p);
        $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $rc = proc_close($p);
        if ($rc !== 0) {
            self::fail('command failed (' . $rc . '): ' . implode(' ', $cmd) . "\n" . $out);
        }
    }

    private static function rmTree(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (scandir($dir) ?: [] as $f) {
            if ($f === '.' || $f === '..') {
                continue;
            }
            $p = $dir . '/' . $f;
            is_dir($p) && !is_link($p) ? self::rmTree($p) : @unlink($p);
        }
        @rmdir($dir);
    }
}

/**
 * Minimal IMAP section resolver (RFC 3501 6.4.5) over a raw RFC 5322 message with CRLF line endings.
 */
final class MimeSections
{
    /**
     * @return false|string
     */
    public static function section(string $raw, ?string $section): string|false
    {
        if ($section === null || $section === '') {
            return $raw;
        }
        $cur = $raw;
        $isMessage = true;
        foreach (explode('.', $section) as $p) {
            if ($p === 'TEXT' || $p === 'HEADER') {
                if (!$isMessage && self::type($cur) === 'message/rfc822') {
                    $cur = self::split($cur)[1];
                }
                [$h, $b] = self::split($cur);
                return $p === 'TEXT' ? $b : $h . "\r\n\r\n";
            }
            if ($p === 'MIME') {
                return self::split($cur)[0] . "\r\n\r\n";
            }
            if (!ctype_digit($p) || (int) $p < 1) {
                return false;
            }
            $n = (int) $p;
            if (!$isMessage && self::type($cur) === 'message/rfc822') {
                $cur = self::split($cur)[1];
                $isMessage = true;
            }
            if (str_starts_with(self::type($cur), 'multipart/')) {
                $children = self::children($cur);
                if (!isset($children[$n - 1])) {
                    return false;
                }
                $cur = $children[$n - 1];
            } elseif (!$isMessage || $n !== 1) {
                return false;
            }
            $isMessage = false;
        }
        return self::split($cur)[1];
    }

    /**
     * @return array{0: string, 1: string} header block (without the empty line) and body
     */
    private static function split(string $entity): array
    {
        if (str_starts_with($entity, "\r\n")) {
            return ['', substr($entity, 2)];
        }
        $pos = strpos($entity, "\r\n\r\n");
        return $pos === false ? [$entity, ''] : [substr($entity, 0, $pos), substr($entity, $pos + 4)];
    }

    private static function header(string $entity, string $name): string
    {
        $h = (string) preg_replace('/\r\n[ \t]+/', ' ', self::split($entity)[0]);
        return preg_match('/^' . preg_quote($name, '/') . ':[ \t]*(.*)$/im', $h, $m) ? trim($m[1]) : '';
    }

    private static function type(string $entity): string
    {
        $ct = self::header($entity, 'Content-Type');
        return $ct === '' ? 'text/plain' : strtolower(trim(explode(';', $ct)[0]));
    }

    /**
     * @return list<string>
     */
    private static function children(string $entity): array
    {
        $ct = self::header($entity, 'Content-Type');
        if (!preg_match('/boundary="?([^";]+)"?/i', $ct, $m)) {
            return [];
        }
        $body = self::split($entity)[1];
        $q = preg_quote('--' . $m[1], '/');
        preg_match_all('/(?:^|\r\n)' . $q . '(--)?[ \t]*(?:\r\n|$)/', $body, $all, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);
        $out = [];
        for ($i = 0; $i < count($all) - 1; $i++) {
            if (isset($all[$i][1]) && $all[$i][1][0] === '--') {
                break;
            }
            $start = $all[$i][0][1] + strlen($all[$i][0][0]);
            $out[] = substr($body, $start, $all[$i + 1][0][1] - $start);
        }
        return $out;
    }
}
