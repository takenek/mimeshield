<?php

/**
 * MIME Shield interop helper (TEST ONLY): produce CMS with the plugin's CmsService, or check CMS
 * produced by other implementations with the plugin's verification/decryption code.
 *
 *   plugin_cms.php make <outdir>
 *   plugin_cms.php check <content-file> <detached-sig-der> <enveloped-der> <expected-signer-email>
 *
 * @license GPL-3.0-or-later
 */

declare(strict_types=1);

require __DIR__ . '/../../lib/autoload.php';

use MimeShield\Cert\Certificate;
use MimeShield\Crypto\CmsService;
use MimeShield\Service\SignatureVerifier;
use MimeShield\Trust\ChainValidator;
use MimeShield\Trust\RevocationChecker;
use MimeShield\Trust\TrustStore;

MimeShield\Log::setSink(static function (string $l): void {
});
$P = __DIR__ . '/../fixtures/pki/';
$cms = new CmsService(sys_get_temp_dir());
$alice = Certificate::fromString((string) file_get_contents($P . 'alice.crt'));
$bob = Certificate::fromString((string) file_get_contents($P . 'bob.crt'));

if (($argv[1] ?? '') === 'make') {
    $out = rtrim($argv[2], '/');
    $content = "Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nZa=C5=BC=C3=B3=C5=82=C4=87 g=C4=99=C5=9Bl=C4=85 ja=C5=BA=C5=84\r\n";
    file_put_contents("$out/content.txt", $content);
    file_put_contents("$out/plugin-sig.der", $cms->signDetached($content, $alice, (string) file_get_contents($P . 'alice.key'), [(string) file_get_contents($P . 'int.crt')]));
    file_put_contents("$out/plugin-enc.der", $cms->encrypt($content, [$bob, $alice]));
    exit(0);
}

[$content, $sig, $enc, $email] = [(string) file_get_contents($argv[2]), (string) file_get_contents($argv[3]), (string) file_get_contents($argv[4]), $argv[5]];
$ts = new TrustStore([$P . 'root.crt'], false);
$verifier = new SignatureVerifier(new ChainValidator($ts, sys_get_temp_dir()), $ts, new RevocationChecker('off', null, ''));
$check = $cms->verifyDetached($content, $sig);
$r = $verifier->evaluate($check, [$email], []);
$dec = $cms->decrypt($enc, $alice, (string) file_get_contents($P . 'alice.key'));
$ok = $check->valid && $r->level() === 'ok' && $dec === $content;
printf("verify=%s digest=%s level=%s chain=%s identity=%s decrypt=%s\n", $check->valid ? 'valid' : 'INVALID', $check->digest(), $r->level(), $r->chain->status ?? '-', $r->identity, $dec === $content ? 'ok' : 'FAIL');
exit($ok ? 0 : 1);
