<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use MimeShield\Cert\Certificate;
use MimeShield\Crypto\SignatureCheck;
use MimeShield\Tests\TestPki;
use MimeShield\Trust\ChainResult;
use MimeShield\Trust\RevocationResult;
use MimeShield\Trust\VerificationResult as VR;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Pure policy tests of VerificationResult (level, lines, headline) on synthetic inputs.
 */
final class VerificationResultTest extends TestCase
{
    private const INT_NAME = 'MIME Shield Test Intermediate CA';

    private static function check(bool $valid = true, string $failure = SignatureCheck::FAIL_NONE, string $digest = 'sha256', ?int $signingTime = null, bool $canonicalized = false): SignatureCheck
    {
        $info = [
            'detached' => true,
            'digests' => [$digest],
            'signers' => [['digest' => $digest, 'signature' => 'rsaEncryption', 'signingTime' => $signingTime, 'sid' => []]],
            'certificates' => 2,
        ];
        return new SignatureCheck($valid, $failure, [TestPki::read('alice.crt')], [TestPki::read('int.crt')], $info, null, $canonicalized);
    }

    /**
     * Baseline: everything fine. $o overrides single constructor arguments.
     *
     * @param array<string, mixed> $o
     */
    private static function vr(array $o = []): VR
    {
        return new VR(
            $o['check'] ?? self::check(),
            array_key_exists('signer', $o) ? $o['signer'] : TestPki::cert('alice'),
            array_key_exists('chain', $o) ? $o['chain'] : new ChainResult(ChainResult::TRUSTED, ['leaf', 'int', 'root']),
            $o['identity'] ?? VR::IDENTITY_MATCH,
            $o['time'] ?? VR::TIME_VALID,
            $o['purposeOk'] ?? true,
            $o['rev'] ?? new RevocationResult(RevocationResult::NOT_CHECKED, 'disabled'),
            $o['weak'] ?? false,
            $o['forbidden'] ?? false,
            $o['small'] ?? false,
            $o['from'] ?? ['alice@example.test'],
            $o['partial'] ?? false,
            $o['legacy'] ?? false,
        );
    }

    /**
     * @return array<string, array{0: array<string, string>, 1: string}>
     */
    private static function byLabel(VR $r): array
    {
        $out = [];
        foreach ($r->lines() as $line) {
            self::assertCount(3, $line);
            [$label, $vars, $sev] = $line;
            self::assertIsString($label);
            self::assertIsArray($vars);
            self::assertContains($sev, [VR::LEVEL_OK, VR::LEVEL_WARNING, VR::LEVEL_ERROR]);
            self::assertArrayNotHasKey($label, $out, 'duplicate line ' . $label);
            $out[$label] = [$vars, $sev];
        }
        return $out;
    }

    public function testBaselineIsOkWithExactLines(): void
    {
        $r = self::vr();
        self::assertTrue($r->cryptoValid());
        self::assertSame(VR::LEVEL_OK, $r->level());
        self::assertSame('status_sig_ok', $r->headline());
        self::assertSame([
            ['sig_cryptovalid', [], VR::LEVEL_OK],
            ['chain_trusted', ['issuer' => self::INT_NAME], VR::LEVEL_OK],
            ['identity_match', ['email' => 'alice@example.test'], VR::LEVEL_OK],
            ['revocation_notchecked', [], VR::LEVEL_WARNING],
        ], $r->lines());
    }

    /**
     * One deviation from the baseline at a time => [level, headline].
     *
     * @return iterable<string, array{0: \Closure(): array<string, mixed>, 1: string, 2: string}>
     */
    public static function singleDeviations(): iterable
    {
        yield 'modified' => [static fn () => ['check' => self::check(false, SignatureCheck::FAIL_MODIFIED)], VR::LEVEL_ERROR, 'status_sig_invalid'];
        yield 'malformed' => [static fn () => ['check' => self::check(false, SignatureCheck::FAIL_MALFORMED)], VR::LEVEL_ERROR, 'status_sig_invalid'];
        yield 'forbidden digest' => [static fn () => ['check' => self::check(true, '', 'md5'), 'forbidden' => true], VR::LEVEL_ERROR, 'status_sig_invalid'];
        yield 'no signer' => [static fn () => ['signer' => null, 'chain' => null], VR::LEVEL_ERROR, 'status_sig_badcert'];
        yield 'identity mismatch' => [static fn () => ['identity' => VR::IDENTITY_MISMATCH], VR::LEVEL_ERROR, 'status_sig_mismatch'];
        yield 'revoked' => [static fn () => ['rev' => new RevocationResult(RevocationResult::REVOKED, 'keyCompromise', 1700000000)], VR::LEVEL_ERROR, 'status_sig_revoked'];
        yield 'bad purpose' => [static fn () => ['purposeOk' => false], VR::LEVEL_ERROR, 'status_sig_badcert'];
        yield 'chain untrusted root' => [static fn () => ['chain' => new ChainResult(ChainResult::UNTRUSTED_ROOT, [])], VR::LEVEL_WARNING, 'status_sig_untrusted'];
        yield 'chain incomplete' => [static fn () => ['chain' => new ChainResult(ChainResult::INCOMPLETE, [])], VR::LEVEL_WARNING, 'status_sig_untrusted'];
        yield 'chain bad purpose' => [static fn () => ['chain' => new ChainResult(ChainResult::BAD_PURPOSE, [])], VR::LEVEL_WARNING, 'status_sig_untrusted'];
        yield 'chain no trust store' => [static fn () => ['chain' => new ChainResult(ChainResult::NO_TRUST_STORE, [])], VR::LEVEL_WARNING, 'status_sig_untrusted'];
        yield 'chain missing' => [static fn () => ['chain' => null], VR::LEVEL_WARNING, 'status_sig_untrusted'];
        yield 'chain expired' => [static fn () => ['chain' => new ChainResult(ChainResult::EXPIRED, [])], VR::LEVEL_WARNING, 'status_sig_expired'];
        yield 'chain not yet valid' => [static fn () => ['chain' => new ChainResult(ChainResult::NOT_YET_VALID, [])], VR::LEVEL_WARNING, 'status_sig_notyet'];
        yield 'cert expired' => [static fn () => ['time' => VR::TIME_EXPIRED], VR::LEVEL_WARNING, 'status_sig_expired'];
        yield 'cert not yet valid' => [static fn () => ['time' => VR::TIME_NOTYET], VR::LEVEL_WARNING, 'status_sig_notyet'];
        yield 'identity sender' => [static fn () => ['identity' => VR::IDENTITY_SENDER], VR::LEVEL_WARNING, 'status_sig_warning'];
        yield 'identity noemail' => [static fn () => ['identity' => VR::IDENTITY_NOEMAIL], VR::LEVEL_WARNING, 'status_sig_warning'];
        yield 'identity nofrom' => [static fn () => ['identity' => VR::IDENTITY_NOFROM], VR::LEVEL_WARNING, 'status_sig_warning'];
        yield 'revocation unknown' => [static fn () => ['rev' => new RevocationResult(RevocationResult::UNKNOWN, 'revocationunavailable')], VR::LEVEL_WARNING, 'status_sig_warning'];
        yield 'weak digest' => [static fn () => ['check' => self::check(true, '', 'sha1'), 'weak' => true], VR::LEVEL_WARNING, 'status_sig_warning'];
        yield 'small key' => [static fn () => ['small' => true], VR::LEVEL_WARNING, 'status_sig_warning'];
        yield 'partial' => [static fn () => ['partial' => true], VR::LEVEL_WARNING, 'status_sig_warning'];
        yield 'revocation good' => [static fn () => ['rev' => new RevocationResult(RevocationResult::GOOD)], VR::LEVEL_OK, 'status_sig_ok'];
        yield 'legacy email' => [static fn () => ['legacy' => true], VR::LEVEL_OK, 'status_sig_ok'];
        yield 'canonicalized' => [static fn () => ['check' => self::check(true, '', 'sha256', null, true)], VR::LEVEL_OK, 'status_sig_ok'];
    }

    #[DataProvider('singleDeviations')]
    public function testLevelAndHeadline(\Closure $overrides, string $level, string $headline): void
    {
        $r = self::vr($overrides());
        self::assertSame($level, $r->level());
        self::assertSame($headline, $r->headline());
        // level and headline must agree on "ok"
        self::assertSame($level === VR::LEVEL_OK, $r->headline() === 'status_sig_ok');
    }

    /**
     * @return iterable<string, array{0: \Closure(): array<string, mixed>, 1: string, 2: string}>
     */
    public static function precedence(): iterable
    {
        yield 'invalid beats mismatch and revoked' => [static fn () => ['check' => self::check(false, SignatureCheck::FAIL_MODIFIED), 'identity' => VR::IDENTITY_MISMATCH, 'rev' => new RevocationResult(RevocationResult::REVOKED)], VR::LEVEL_ERROR, 'status_sig_invalid'];
        yield 'forbidden beats mismatch' => [static fn () => ['forbidden' => true, 'identity' => VR::IDENTITY_MISMATCH], VR::LEVEL_ERROR, 'status_sig_invalid'];
        yield 'mismatch beats revoked' => [static fn () => ['identity' => VR::IDENTITY_MISMATCH, 'rev' => new RevocationResult(RevocationResult::REVOKED)], VR::LEVEL_ERROR, 'status_sig_mismatch'];
        yield 'revoked beats bad purpose' => [static fn () => ['rev' => new RevocationResult(RevocationResult::REVOKED), 'purposeOk' => false], VR::LEVEL_ERROR, 'status_sig_revoked'];
        yield 'bad purpose beats expired and untrusted' => [static fn () => ['purposeOk' => false, 'time' => VR::TIME_EXPIRED, 'chain' => new ChainResult(ChainResult::UNTRUSTED_ROOT, [])], VR::LEVEL_ERROR, 'status_sig_badcert'];
        yield 'expired beats not yet valid chain' => [static fn () => ['time' => VR::TIME_EXPIRED, 'chain' => new ChainResult(ChainResult::NOT_YET_VALID, [])], VR::LEVEL_WARNING, 'status_sig_expired'];
        yield 'expired beats untrusted' => [static fn () => ['time' => VR::TIME_EXPIRED, 'chain' => new ChainResult(ChainResult::INCOMPLETE, [], true)], VR::LEVEL_WARNING, 'status_sig_expired'];
        yield 'not yet valid beats untrusted' => [static fn () => ['time' => VR::TIME_NOTYET, 'chain' => new ChainResult(ChainResult::UNTRUSTED_ROOT, [])], VR::LEVEL_WARNING, 'status_sig_notyet'];
        yield 'untrusted beats generic warnings' => [static fn () => ['chain' => new ChainResult(ChainResult::INCOMPLETE, []), 'weak' => true, 'identity' => VR::IDENTITY_SENDER, 'small' => true], VR::LEVEL_WARNING, 'status_sig_untrusted'];
        yield 'error beats warnings' => [static fn () => ['identity' => VR::IDENTITY_MISMATCH, 'weak' => true, 'partial' => true, 'time' => VR::TIME_EXPIRED], VR::LEVEL_ERROR, 'status_sig_mismatch'];
        yield 'no signer beats untrusted' => [static fn () => ['signer' => null, 'chain' => new ChainResult(ChainResult::UNTRUSTED_ROOT, [])], VR::LEVEL_ERROR, 'status_sig_badcert'];
    }

    #[DataProvider('precedence')]
    public function testPrecedence(\Closure $overrides, string $level, string $headline): void
    {
        $r = self::vr($overrides());
        self::assertSame($level, $r->level());
        self::assertSame($headline, $r->headline());
    }

    public function testForbiddenDigestMakesCryptoInvalid(): void
    {
        self::assertFalse(self::vr(['forbidden' => true])->cryptoValid());
        self::assertFalse(self::vr(['check' => self::check(false, SignatureCheck::FAIL_MODIFIED)])->cryptoValid());
        self::assertTrue(self::vr(['weak' => true])->cryptoValid());
    }

    public function testValidSignatureNeverImpliesTrust(): void
    {
        foreach ([ChainResult::UNTRUSTED_ROOT, ChainResult::INCOMPLETE, ChainResult::EXPIRED, ChainResult::NOT_YET_VALID, ChainResult::BAD_PURPOSE, ChainResult::NO_TRUST_STORE, null] as $status) {
            $r = self::vr(['chain' => $status === null ? null : new ChainResult($status, [])]);
            self::assertTrue($r->cryptoValid());
            self::assertNotSame(VR::LEVEL_OK, $r->level(), (string) $status);
            self::assertNotSame('status_sig_ok', $r->headline(), (string) $status);
            $lines = self::byLabel($r);
            self::assertSame(VR::LEVEL_OK, $lines['sig_cryptovalid'][1]);
            self::assertArrayNotHasKey('chain_trusted', $lines);
        }
    }

    /**
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function failureLabels(): iterable
    {
        yield 'modified' => [SignatureCheck::FAIL_MODIFIED, 'sig_modified'];
        yield 'unsupported' => [SignatureCheck::FAIL_UNSUPPORTED, 'sig_unsupported'];
        yield 'no signer' => [SignatureCheck::FAIL_NO_SIGNER, 'sig_nosigner'];
        yield 'malformed' => [SignatureCheck::FAIL_MALFORMED, 'sig_malformed'];
        yield 'unknown reason' => [SignatureCheck::FAIL_NONE, 'sig_malformed'];
    }

    #[DataProvider('failureLabels')]
    public function testCryptoFailureLines(string $failure, string $label): void
    {
        $r = self::vr(['check' => self::check(false, $failure)]);
        self::assertSame([$label, [], VR::LEVEL_ERROR], $r->lines()[0]);
        self::assertArrayNotHasKey('sig_cryptovalid', self::byLabel($r));
    }

    public function testForbiddenDigestLine(): void
    {
        $r = self::vr(['check' => self::check(true, '', 'md5'), 'forbidden' => true]);
        self::assertSame(['sig_forbiddendigest', ['digest' => 'md5'], VR::LEVEL_ERROR], $r->lines()[0]);
        self::assertArrayNotHasKey('sig_cryptovalid', self::byLabel($r));
    }

    /**
     * @return iterable<string, array{0: ?string, 1: string, 2: array<string, string>, 3: string}>
     */
    public static function chainLines(): iterable
    {
        yield 'trusted' => [ChainResult::TRUSTED, 'chain_trusted', ['issuer' => self::INT_NAME], VR::LEVEL_OK];
        yield 'untrusted root' => [ChainResult::UNTRUSTED_ROOT, 'chain_untrusted', ['issuer' => self::INT_NAME], VR::LEVEL_WARNING];
        yield 'incomplete' => [ChainResult::INCOMPLETE, 'chain_incomplete', ['issuer' => self::INT_NAME], VR::LEVEL_WARNING];
        yield 'expired' => [ChainResult::EXPIRED, 'chain_expiredpath', [], VR::LEVEL_WARNING];
        yield 'not yet valid' => [ChainResult::NOT_YET_VALID, 'chain_notyetpath', [], VR::LEVEL_WARNING];
        yield 'bad purpose' => [ChainResult::BAD_PURPOSE, 'chain_badpurpose', [], VR::LEVEL_WARNING];
        yield 'no trust store' => [ChainResult::NO_TRUST_STORE, 'chain_notruststore', [], VR::LEVEL_WARNING];
        yield 'not evaluated' => [null, 'chain_notruststore', [], VR::LEVEL_WARNING];
    }

    /**
     * @param array<string, string> $vars
     */
    #[DataProvider('chainLines')]
    public function testChainLines(?string $status, string $label, array $vars, string $severity): void
    {
        $r = self::vr(['chain' => $status === null ? null : new ChainResult($status, [])]);
        self::assertSame([$label, $vars, $severity], $r->lines()[1]);
    }

    public function testBadPurposeLineComesBeforeChainLine(): void
    {
        $lines = self::vr(['purposeOk' => false])->lines();
        self::assertSame(['cert_badpurpose', [], VR::LEVEL_ERROR], $lines[1]);
        self::assertSame('chain_trusted', $lines[2][0]);
    }

    public function testExpiredCertificateLines(): void
    {
        $expired = TestPki::cert('expired'); // 2020-01-01 .. 2021-01-01
        $base = ['signer' => $expired, 'time' => VR::TIME_EXPIRED];

        // signed while the certificate was valid
        $st = gmmktime(12, 30, 0, 6, 1, 2020);
        $lines = self::byLabel(self::vr($base + ['check' => self::check(true, '', 'sha256', $st)]));
        self::assertSame([['date' => '2021-01-01', 'signed' => '2020-06-01 12:30 UTC'], VR::LEVEL_WARNING], $lines['cert_expired_signedwhilevalid']);
        self::assertArrayNotHasKey('cert_expired', $lines);

        // boundaries are inclusive
        foreach ([$expired->notBefore, $expired->notAfter] as $edge) {
            $lines = self::byLabel(self::vr($base + ['check' => self::check(true, '', 'sha256', $edge)]));
            self::assertArrayHasKey('cert_expired_signedwhilevalid', $lines);
        }

        // claimed signing time outside validity, or none: plain "expired"
        foreach ([$expired->notAfter + 1, $expired->notBefore - 1, null] as $claimed) {
            $lines = self::byLabel(self::vr($base + ['check' => self::check(true, '', 'sha256', $claimed)]));
            self::assertSame([['date' => '2021-01-01'], VR::LEVEL_WARNING], $lines['cert_expired'], var_export($claimed, true));
            self::assertArrayNotHasKey('cert_expired_signedwhilevalid', $lines);
        }
    }

    public function testNotYetValidLine(): void
    {
        $lines = self::byLabel(self::vr(['signer' => TestPki::cert('notyet'), 'time' => VR::TIME_NOTYET]));
        self::assertSame([['date' => '2035-01-01'], VR::LEVEL_WARNING], $lines['cert_notyetvalid']);
        self::assertArrayNotHasKey('cert_expired', $lines);
    }

    public function testValidTimeHasNoTimeLine(): void
    {
        $lines = self::byLabel(self::vr());
        foreach (['cert_expired', 'cert_expired_signedwhilevalid', 'cert_notyetvalid'] as $l) {
            self::assertArrayNotHasKey($l, $lines);
        }
    }

    /**
     * @return iterable<string, array{0: string, 1: string, 2: array<string, string>, 3: string}>
     */
    public static function identityLines(): iterable
    {
        yield 'match' => [VR::IDENTITY_MATCH, 'identity_match', ['email' => 'alice@example.test'], VR::LEVEL_OK];
        yield 'sender' => [VR::IDENTITY_SENDER, 'identity_senderonly', ['email' => 'alice@example.test'], VR::LEVEL_WARNING];
        yield 'mismatch' => [VR::IDENTITY_MISMATCH, 'identity_mismatch', ['email' => 'alice@example.test', 'from' => 'mallory@example.test, eve@example.test'], VR::LEVEL_ERROR];
        yield 'noemail' => [VR::IDENTITY_NOEMAIL, 'identity_noemail', [], VR::LEVEL_WARNING];
        yield 'nofrom' => [VR::IDENTITY_NOFROM, 'identity_nofrom', [], VR::LEVEL_WARNING];
    }

    /**
     * @param array<string, string> $vars
     */
    #[DataProvider('identityLines')]
    public function testIdentityLines(string $identity, string $label, array $vars, string $severity): void
    {
        $lines = self::byLabel(self::vr(['identity' => $identity, 'from' => ['mallory@example.test', 'eve@example.test']]));
        self::assertSame([$vars, $severity], $lines[$label]);
    }

    public function testLegacyEmailLine(): void
    {
        $lines = self::byLabel(self::vr(['legacy' => true]));
        self::assertSame([[], VR::LEVEL_WARNING], $lines['identity_legacyemail']);
        self::assertArrayNotHasKey('identity_legacyemail', self::byLabel(self::vr()));
    }

    /**
     * @return iterable<string, array{0: RevocationResult, 1: string, 2: array<string, string>, 3: string}>
     */
    public static function revocationLines(): iterable
    {
        yield 'good' => [new RevocationResult(RevocationResult::GOOD), 'revocation_good', [], VR::LEVEL_OK];
        yield 'revoked' => [new RevocationResult(RevocationResult::REVOKED, 'keyCompromise', gmmktime(0, 0, 0, 3, 15, 2026)), 'revocation_revoked', ['date' => '2026-03-15', 'reason' => 'keyCompromise'], VR::LEVEL_ERROR];
        yield 'revoked without date' => [new RevocationResult(RevocationResult::REVOKED, 'unspecified'), 'revocation_revoked', ['date' => '?', 'reason' => 'unspecified'], VR::LEVEL_ERROR];
        yield 'unknown' => [new RevocationResult(RevocationResult::UNKNOWN, 'x'), 'revocation_unknown', [], VR::LEVEL_WARNING];
        yield 'not checked' => [new RevocationResult(RevocationResult::NOT_CHECKED, 'disabled'), 'revocation_notchecked', [], VR::LEVEL_WARNING];
    }

    /**
     * @param array<string, string> $vars
     */
    #[DataProvider('revocationLines')]
    public function testRevocationLines(RevocationResult $rev, string $label, array $vars, string $severity): void
    {
        $lines = self::byLabel(self::vr(['rev' => $rev]));
        self::assertSame([$vars, $severity], $lines[$label]);
    }

    public function testAlgorithmAndMiscLines(): void
    {
        $lines = self::byLabel(self::vr(['check' => self::check(true, '', 'sha1', null, true), 'weak' => true, 'small' => true, 'partial' => true]));
        self::assertSame([['digest' => 'SHA1'], VR::LEVEL_WARNING], $lines['sig_weakdigest']);
        self::assertSame([['bits' => '2048'], VR::LEVEL_WARNING], $lines['cert_smallkey']);
        self::assertSame([[], VR::LEVEL_WARNING], $lines['sig_partial']);
        self::assertSame([[], VR::LEVEL_OK], $lines['sig_canonicalized']);

        $plain = self::byLabel(self::vr());
        foreach (['sig_weakdigest', 'cert_smallkey', 'sig_partial', 'sig_canonicalized', 'cert_badpurpose'] as $l) {
            self::assertArrayNotHasKey($l, $plain);
        }
    }

    public function testWithoutSignerOnlySignatureLevelLinesAppear(): void
    {
        $r = self::vr(['signer' => null, 'chain' => null, 'small' => true, 'weak' => true, 'check' => self::check(true, '', 'sha1')]);
        $labels = array_column($r->lines(), 0);
        self::assertSame(['sig_cryptovalid', 'sig_weakdigest'], $labels);
        self::assertSame(VR::LEVEL_ERROR, $r->level());
    }

    public function testUntrustedDataStaysInVars(): void
    {
        // From addresses are attacker controlled: they only ever appear in vars, never in labels
        $from = ['<script>@example.test'];
        $r = self::vr(['identity' => VR::IDENTITY_MISMATCH, 'from' => $from]);
        foreach ($r->lines() as [$label]) {
            self::assertMatchesRegularExpression('/^[a-z_]+$/', $label);
        }
        self::assertSame('<script>@example.test', self::byLabel($r)['identity_mismatch'][0]['from']);
    }

    public function testSignerEmailsListedInIdentityLine(): void
    {
        $legacy = TestPki::cert('legacyemail');
        self::assertInstanceOf(Certificate::class, $legacy);
        $lines = self::byLabel(self::vr(['signer' => $legacy, 'legacy' => true, 'from' => ['legacy@example.test']]));
        self::assertSame(['email' => 'legacy@example.test'], $lines['identity_match'][0]);
    }
}
