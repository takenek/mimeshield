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

namespace MimeShield\Ui;

use MimeShield\Exception\MimeShieldException;
use MimeShield\Log;
use MimeShield\Mime\PartStatus;
use MimeShield\Trust\VerificationResult;

/**
 * Message view: S/MIME status bar (show / preview / print) and "save sender certificate".
 *
 * Everything in the bar is built with html::* and rcube::Q(); certificate fields (CN, issuer, SAN,
 * ...) are untrusted input and are always escaped. The state is conveyed by text and an icon, not
 * only by colour.
 */
final class MessageUi
{
    private const SEVERITY = ['ok' => 0, 'warning' => 1, 'error' => 2];

    /** "save sender certificate" requests per minute, per session and per user account */
    private const SAVECERT_PER_MINUTE = 20;

    public function __construct(private readonly \mimeshield $plugin)
    {
    }

    /**
     * message_body_prefix: status bar above the first displayed part covered by a status.
     *
     * @param array<string, mixed> $p
     *
     * @return array<string, mixed>
     */
    public function bodyPrefix(array $p): array
    {
        $part = $p['part'] ?? null;
        $id = is_object($part) && isset($part->mime_id) ? (string) $part->mime_id : '0';
        $st = $this->plugin->services()->incoming(false)->statusFor($id);
        if ($st !== null && !$st->shown) {
            $st->shown = true;
            $p['prefix'] = ($p['prefix'] ?? '') . $this->render($st);
        }
        return $p;
    }

    /**
     * template_object_messagebody: statuses that were never shown (e.g. decryption failed and
     * Roundcube displays its own "encrypted message" placeholder) are prepended to the body.
     *
     * @param array<string, mixed> $p
     *
     * @return array<string, mixed>
     */
    public function messageBody(array $p): array
    {
        $html = '';
        foreach ($this->plugin->services()->incoming(false)->statuses() as $st) {
            if (!$st->shown && ($st->isEncrypted() || $st->isSigned())) {
                $st->shown = true;
                $html .= $this->render($st);
            }
        }
        if ($html !== '') {
            $p['content'] = $html . ($p['content'] ?? '');
        }
        return $p;
    }

    /**
     * template_object_messageheaders: a compact S/MIME indicator in the header area, OUTSIDE the
     * message content - shown for every message, also without S/MIME ("not signed"), so that content
     * imitating the status bar cannot stand in for it (audit F-10). The bar above the content stays
     * as the detailed view.
     *
     * @param array<string, mixed> $p
     *
     * @return array<string, mixed>
     */
    public function messageHeaders(array $p): array
    {
        if (!empty($p['valueof']) || !empty($p['valueOf'])) {
            return $p; // single header value (e.g. the subject line), not the header block
        }
        $p['content'] = ($p['content'] ?? '') . $this->headerBadge();
        return $p;
    }

    public function headerBadge(): string
    {
        $services = $this->plugin->services();
        $incoming = $services->hasIncoming() ? $services->incoming(false) : null;
        $st = $incoming?->statusFor('0');
        if ($st !== null) {
            [, $level, $headline] = $this->evaluate($st);
            $label = match ($level) {
                'ok' => $st->decryption === true ? 'badge_ok_enc' : 'badge_ok',
                'warning' => 'badge_warning',
                default => 'badge_error',
            };
            if (str_starts_with($headline, 'status_sig_norevocation')) {
                $label = 'badge_norevocation';
            }
        } elseif ($incoming !== null && $incoming->statuses() !== []) {
            [$level, $label] = ['warning', 'badge_partial'];
        } else {
            [$level, $label] = ['none', 'badge_none'];
        }
        $icon = ['ok' => "\u{2714}", 'warning' => "\u{26A0}", 'error' => "\u{2716}", 'none' => "\u{25CB}"][$level];
        return \html::div(['class' => 'mimeshield-badge mimeshield-badge-' . $level, 'role' => 'status'],
            \html::span(['class' => 'mimeshield-mark', 'aria-hidden' => 'true'], $icon) . ' '
            . \rcube::Q($this->plugin->text($label)));
    }

    /**
     * Render the status bar for one part.
     */
    public function render(PartStatus $st): string
    {
        [$lines, $level, $headline, $kind] = $this->evaluate($st);
        $sig = $st->signature;

        $cssType = ['ok' => 'confirmation', 'warning' => 'warning', 'error' => 'error'][$level];
        $icon = ['ok' => "\u{2714}", 'warning' => "\u{26A0}", 'error' => "\u{2716}"];

        $items = '';
        foreach ($lines as [$label, $vars, $sev]) {
            $items .= \html::tag('li', ['class' => 'mimeshield-line mimeshield-' . $sev],
                \html::span(['class' => 'mimeshield-mark', 'aria-hidden' => 'true'], $icon[$sev] ?? '')
                . \html::span(['class' => 'voice'], \rcube::Q($this->plugin->text('severity_' . $sev)) . ': ')
                . \rcube::Q($this->plugin->text($label, array_map('strval', $vars)))
            );
        }

        $body = \html::tag('strong', ['class' => 'mimeshield-headline'],
            \html::span(['class' => 'mimeshield-mark', 'aria-hidden' => 'true'], $icon[$level]) . ' '
            . \rcube::Q($this->plugin->text($headline !== '' ? $headline : 'status_sig_invalid')))
            . \html::tag('ul', ['class' => 'mimeshield-lines'], $items);

        if ($sig !== null && $sig->signer !== null) {
            $body .= $this->certDetails($sig);
            if ($this->canOfferSave($sig) && $this->plugin->rcmail()->action !== 'print') {
                $body .= \html::p(['class' => 'mimeshield-actions'],
                    \html::a(['href' => '#', 'class' => 'mimeshield-savecert', 'role' => 'button'], \rcube::Q($this->plugin->text('savesendercert'))));
            }
        }

        return \html::div([
            'class' => 'part-notice ' . $cssType . ' ' . $kind . ' mimeshield-status mimeshield-level-' . $level,
            'role' => 'status',
        ], $body);
    }

    /**
     * Status of one part: [lines, level (ok|warning|error), headline label, kind].
     *
     * @return array{0: list<array{0: string, 1: array<string, string>, 2: string}>, 1: string, 2: string, 3: string}
     */
    private function evaluate(PartStatus $st): array
    {
        $lines = [];
        $level = 'ok';
        $headline = '';
        $kind = $st->isEncrypted() ? 'encrypted' : 'signed';

        if ($st->decryption === true) {
            $lines[] = ['enc_decrypted', ['cipher' => strtoupper($st->cipher ?: '?')], 'ok'];
            $headline = 'status_encrypted';
            if (!str_starts_with((string) $st->cipher, 'aes-')) {
                // outdated or unrecognised content encryption (3DES, DES, RC2, other OIDs; audit I-11)
                $lines[] = ['enc_weakcipher', ['cipher' => strtoupper($st->cipher)], 'warning'];
                $level = 'warning';
            }
        } elseif (is_string($st->decryption)) {
            $lines[] = [$this->knownLabel($st->decryption, 'decrypt_failed'), [], 'error'];
            $headline = 'status_decrypt_failed';
            $level = 'error';
        } elseif ($st->notDecrypted) {
            $lines[] = ['enc_notdecrypted', [], 'warning'];
            $headline = 'status_encrypted_nested';
            $level = 'warning';
        }

        $sig = $st->signature;
        if ($sig !== null) {
            foreach ($sig->lines() as $l) {
                $lines[] = $l;
            }
            $headline = $headline === 'status_encrypted' ? $sig->headline() . '_enc' : $sig->headline();
            $level = $this->max($level, $sig->level());
            if ($level !== 'error' && $sig->level() === VerificationResult::LEVEL_OK
                && $sig->revocation->status === \MimeShield\Trust\RevocationResult::NOT_CHECKED) {
                // The administrator may disable CRL checks, but the UI must not imply that the
                // certificate's current revocation state was checked (audit I-01).
                $headline = $st->decryption === true ? 'status_sig_norevocation_enc' : 'status_sig_norevocation';
                $level = $this->max($level, 'warning');
            }
        } elseif ($st->signatureError !== null) {
            $lines[] = [$this->knownLabel($st->signatureError, 'sig_malformed'), [], 'error'];
            $headline = 'status_sig_invalid';
            $level = 'error';
        } elseif ($st->decryption === true) {
            // encrypted, not signed: sender cannot be authenticated
            $lines[] = ['enc_notsigned', [], 'warning'];
            $level = $this->max($level, 'warning');
        }

        if ($st->decryption === true && $st->unauthenticated && ($sig === null || !$sig->cryptoValid())) {
            $lines[] = ['enc_unauthenticated', [], 'warning'];
            $level = $this->max($level, 'warning');
        }
        if ($st->partial && $sig === null) {
            $lines[] = ['sig_partial', [], 'warning'];
            $level = $this->max($level, 'warning');
        }

        return [$lines, $level, $headline, $kind];
    }

    private function certDetails(VerificationResult $sig): string
    {
        $c = $sig->signer;
        $rows = [
            'subject' => $c->subject,
            'emailaddress' => implode(', ', $c->emails()) ?: '-',
            'issuer' => $c->issuer,
            'serial' => $c->serialHex,
            'fingerprint' => self::formatFingerprint($c->fingerprint),
            'validfrom' => gmdate('Y-m-d H:i', $c->notBefore) . ' UTC',
            'validuntil' => gmdate('Y-m-d H:i', $c->notAfter) . ' UTC',
            'keyalgorithm' => $c->keyDescription(),
            'digest' => strtoupper($sig->check->digest()),
        ];
        if (($t = $sig->check->signingTime()) !== null) {
            $rows['signingtime'] = gmdate('Y-m-d H:i', $t) . ' UTC';
        }
        if ($sig->chain !== null && $sig->chain->path !== []) {
            $rows['chain'] = implode(' → ', array_slice($sig->chain->path, 0, 8));
        }
        $dl = '';
        foreach ($rows as $k => $v) {
            $dl .= \html::tag('dt', [], \rcube::Q($this->plugin->text($k))) . \html::tag('dd', [], \rcube::Q($v));
        }
        return \html::tag('details', ['class' => 'mimeshield-details'],
            \html::tag('summary', [], \rcube::Q($this->plugin->text('certdetails'))) . \html::tag('dl', [], $dl));
    }

    private function canOfferSave(VerificationResult $sig): bool
    {
        if (!$sig->cryptoValid() || $sig->identity !== VerificationResult::IDENTITY_MATCH || $sig->signer === null
            || $sig->signer->isExpired() || !$sig->signer->canEncrypt() || $sig->partial) {
            return false;
        }
        try {
            return $this->plugin->services()->certs()->repository()->findByFingerprint($sig->signer->fingerprint) === null
                && $this->plugin->services()->keys()->repository()->findByFingerprint($sig->signer->fingerprint) === null;
        } catch (MimeShieldException) {
            return false;
        }
    }

    /**
     * AJAX: store the signer certificate of the currently displayed message.
     * The certificate is re-extracted and re-verified server-side; nothing from the client is trusted.
     */
    public function saveCertAction(): void
    {
        $rc = $this->plugin->rcmail();
        $uid = (string) \rcube_utils::get_input_string('_uid', \rcube_utils::INPUT_POST);
        $mbox = (string) \rcube_utils::get_input_string('_mbox', \rcube_utils::INPUT_POST, true);
        $confirm = (bool) \rcube_utils::get_input_value('_confirm', \rcube_utils::INPUT_POST);
        // a confirmation is valid only for the certificate whose fingerprint the user was shown
        $confirmedFp = strtolower((string) \rcube_utils::get_input_string('_fingerprint', \rcube_utils::INPUT_POST));

        if (!preg_match('/^[0-9]+$/D', $uid) || $mbox === '') {
            $rc->output->show_message('mimeshield.invalidrequest', 'error');
            $rc->output->send();
        }
        // each request re-fetches and re-verifies the message: bound the frequency per session and per
        // user account across sessions (audit I-17; same pattern as the key import)
        if (!\MimeShield\RateLimiter::allow($_SESSION, 'mimeshield_rl_savecert', self::SAVECERT_PER_MINUTE, 60)
            || !\MimeShield\RateLimiter::allowForUser($this->plugin->services()->db(), $this->plugin->services()->userId(), 'savecert', self::SAVECERT_PER_MINUTE, 60)) {
            $rc->output->show_message('mimeshield.ratelimited', 'error');
            $rc->output->send();
        }

        try {
            $rc->storage->set_folder($mbox);
            new \rcube_message($uid, $mbox); // runs the S/MIME hooks (verification enabled for this action)
            $result = $this->plugin->services()->incoming(true)->rootSignature();
            if ($result === null) {
                throw new \MimeShield\Exception\ValidationException('savecertrefused', 'no verified signature');
            }
            $confirm = $confirm && $result->signer !== null && hash_equals($result->signer->fingerprint, $confirmedFp);
            $r = $this->plugin->services()->certs()->saveFromMessage($result, $confirm);
            if ($r['confirm'] !== []) {
                $rc->output->command('plugin.mimeshield_savecert_confirm', ['changes' => $r['confirm']]);
            } else {
                $rc->output->show_message('mimeshield.certsaved', 'confirmation');
                $rc->output->command('plugin.mimeshield_savecert_done', ['trust' => $r['trust']]);
            }
        } catch (MimeShieldException $e) {
            $label = $rc->text_exists('mimeshield.' . $e->getUserLabel()) ? $e->getUserLabel() : 'internalerror';
            $rc->output->show_message('mimeshield.' . $label, 'error', $e->getVars());
        } catch (\Throwable $e) {
            Log::exception('savecert', $e);
            $rc->output->show_message('mimeshield.internalerror', 'error');
        }
        $rc->output->send();
    }

    public static function formatFingerprint(string $hex): string
    {
        return strtoupper(implode(':', str_split($hex, 2)));
    }

    private function max(string $a, string $b): string
    {
        return self::SEVERITY[$b] > self::SEVERITY[$a] ? $b : $a;
    }

    private function knownLabel(string $label, string $fallback): string
    {
        return $this->plugin->rcmail()->text_exists('mimeshield.' . $label) ? $label : $fallback;
    }
}
