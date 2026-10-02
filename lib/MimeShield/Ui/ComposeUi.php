<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Ui;

use MimeShield\Exception\MimeShieldException;
use MimeShield\Log;
use MimeShield\RateLimiter;
use MimeShield\Service\CertificateService;
use MimeShield\Service\OutgoingService;
use MimeShield\Trust\AddressMatcher;

/**
 * Compose screen: "Sign S/MIME" / "Encrypt S/MIME" options, sender certificate status and
 * recipient certificate status (AJAX, debounced and cached on the client).
 */
final class ComposeUi
{
    /** recipient status requests per session and minute */
    private const RECIPIENTS_PER_MINUTE = 30;

    /** @var array{restore: ?array{sign: bool, encrypt: bool}, force: bool} */
    private static array $state = ['restore' => null, 'force' => false];

    public function __construct(private readonly \mimeshield $plugin)
    {
    }

    /**
     * message_compose_body: environment for the compose JS, draft option restore, force-encrypt on
     * replies to encrypted messages.
     *
     * @param array<string, mixed> $p
     *
     * @return array<string, mixed>
     */
    public function composeBody(array $p): array
    {
        $rc = $this->plugin->rcmail();
        $cfg = $this->plugin->config();
        $out = $rc->output;

        $restore = null;
        $mode = (string) ($p['mode'] ?? '');
        $message = $p['message'] ?? null;
        // only the user's own drafts carry trusted options (an "edit as new" of received mail could
        // contain an attacker-supplied X-MimeShield-Options header)
        if ($mode === 'draft' && $message instanceof \rcube_message && $message->uid) {
            try {
                $raw = $rc->storage->get_raw_headers($message->uid);
                if (is_string($raw) && preg_match('/^' . preg_quote(OutgoingService::DRAFT_HEADER, '/') . ':\s*sign=([01]);\s*encrypt=([01])/mi', $raw, $m)) {
                    $restore = ['sign' => $m[1] === '1', 'encrypt' => $m[2] === '1'];
                }
            } catch (\Throwable $e) {
                Log::debug('compose', 'draft options not restored: ' . $e->getMessage());
            }
        }

        $force = false;
        $services = $this->plugin->services();
        if ($services->hasIncoming() && $services->incoming(false)->hasDecrypted()) {
            // reply/forward/edit of an encrypted message: keep it encrypted by default
            $force = true;
        }

        if ($force && $mode === 'draft' && !empty($p['html']) && is_string($p['body'] ?? null) && $p['body'] !== '') {
            // EFAIL hardening: for drafts core sets is_safe=true AFTER our message_load hook and washes
            // with remote content allowed; wash decrypted draft HTML again with remote resources
            // blocked, keeping the compose attachment URLs of inline images (same-origin, relative)
            $keep = [];
            if (preg_match_all('/\ssrc="(\.\/\?_task=mail&[^"]*_action=display-attachment[^"]*)"/', $p['body'], $mm)) {
                foreach ($mm[1] as $u) {
                    $u = html_entity_decode($u, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                    $keep[$u] = $u;
                }
            }
            $p['body'] = \rcmail_action_mail_index::wash_html($p['body'], [
                'safe' => false,
                'add_comments' => false,
                'ignore_elements' => ['body'],
            ], $keep);
        }

        $out->set_env('mimeshield_restore', $restore);
        $out->set_env('mimeshield_force_encrypt', $force);
        $out->set_env('mimeshield_locks', $cfg->optionsLock());
        $out->set_env('mimeshield_identities', $this->identityMap());
        $out->set_env('mimeshield_bcc_mode', $cfg->bccMode());

        // shared with optionsHtml(), rendered later in the same request (template_container hook)
        self::$state = ['restore' => $restore, 'force' => $force];

        return $p;
    }

    /**
     * HTML for the compose options sidebar (elastic "composeoptions" container).
     */
    public function optionsHtml(): string
    {
        $rc = $this->plugin->rcmail();
        $cfg = $this->plugin->config();
        $state = self::$state;

        $locks = $cfg->optionsLock();
        $signDefault = $cfg->optionDefault('sign');
        $encDefault = $cfg->optionDefault('encrypt') || (!empty($state['force']) && !$cfg->isLocked('encrypt'));
        if (is_array($state['restore'] ?? null)) {
            $signDefault = !in_array('sign', $locks, true) ? $state['restore']['sign'] : $signDefault;
            $encDefault = !in_array('encrypt', $locks, true) ? ($state['restore']['encrypt'] || !empty($state['force'])) : $encDefault;
        }

        $rows = '';
        if ($cfg->bool('mimeshield_enable_signing')) {
            $rows .= $this->checkboxRow('_mimeshield_sign', 'mimeshield-sign', 'sign', $signDefault, in_array('sign', $locks, true));
        }
        if ($cfg->bool('mimeshield_enable_encryption')) {
            $rows .= $this->checkboxRow('_mimeshield_encrypt', 'mimeshield-encrypt', 'encrypt', $encDefault, in_array('encrypt', $locks, true));
        }
        if ($rows === '') {
            return '';
        }

        $status = \html::div(['id' => 'mimeshield-status', 'class' => 'mimeshield-compose-status', 'aria-live' => 'polite'], '')
            . \html::div(['id' => 'mimeshield-recipients', 'class' => 'mimeshield-recipients', 'aria-live' => 'polite'], '');

        // a visible, separate "S/MIME" section among the core compose options
        return \html::tag('fieldset', ['id' => 'mimeshield-compose', 'class' => 'mimeshield-compose', 'aria-label' => $this->plugin->text('smimeoptions')],
            \html::tag('legend', [], \rcube::Q($this->plugin->text('smimesection'))) . $rows . $status);
    }

    private function checkboxRow(string $name, string $id, string $label, bool $checked, bool $locked): string
    {
        $chk = new \html_checkbox(['name' => $name, 'id' => $id, 'value' => '1', 'class' => 'form-check-input', 'disabled' => $locked]);
        return \html::div('form-group form-check row',
            \html::label(['for' => $id, 'class' => 'col-form-label col-6'], \rcube::Q($this->plugin->text($label)))
            . \html::div('form-check col-6', $chk->show($checked ? '1' : ''))
        );
    }

    /**
     * Per-identity signing capability (public certificate data only - never key material).
     *
     * @return array<int, array<string, mixed>>
     */
    public function identityMap(): array
    {
        $rc = $this->plugin->rcmail();
        $keys = $this->plugin->services()->keys();
        $out = [];
        foreach ((array) $rc->user->list_identities() as $ident) {
            $iid = (int) $ident['identity_id'];
            $entry = ['email' => (string) $ident['email'], 'sign' => false, 'encryptself' => false];
            try {
                $rec = $keys->signerFor(['identity_id' => $iid, 'email' => (string) $ident['email']]);
                $c = $rec->certificate();
                $entry['sign'] = true;
                $entry['cert'] = $c->displayName();
                $entry['issuer'] = $c->issuerDisplayName();
                $entry['until'] = gmdate('Y-m-d', $c->notAfter);
                $entry['soon'] = $c->notAfter - time() < 30 * 86400;
            } catch (MimeShieldException $e) {
                // short status text for the compose sidebar (the long variants are send errors)
                $short = [
                    'signnocert' => 'id_nocert', 'signaddressmismatch' => 'id_mismatch', 'signcertexpired' => 'id_expired',
                    'signcertnotyet' => 'id_notyet', 'signcertusage' => 'id_usage',
                ][$e->getUserLabel()] ?? 'nocertificate';
                $entry['reason'] = $this->plugin->text($short, $e->getVars());
            }
            $entry['encryptself'] = $keys->encryptionCertFor((string) $ident['email'], $iid) !== null;
            $out[$iid] = $entry;
        }
        return $out;
    }

    /**
     * AJAX: certificate status of recipient addresses.
     */
    public function recipientsAction(): void
    {
        $rc = $this->plugin->rcmail();
        // every address costs a chain validation (and with CRL checking possibly a download): bound
        // the frequency per session (audit MS-11); the send itself still re-checks every recipient
        if (!RateLimiter::allow($_SESSION, 'mimeshield_rl_recipients', self::RECIPIENTS_PER_MINUTE, 60)) {
            Log::info('compose', 'recipient status requests throttled');
            $rc->output->command('plugin.mimeshield_recipients', ['recipients' => [], 'aliases' => [], 'throttled' => true]);
            $rc->output->send();
        }
        $input = self::postedAddresses();
        $max = $this->plugin->config()->int('mimeshield_max_recipients', 1, 1000);
        $emails = [];
        $aliases = [];
        foreach ($input as $a) {
            $n = AddressMatcher::normalize($a);
            if ($n !== null) {
                $emails[$n] = true;
                if (mb_strtolower($a) !== $n) {
                    $aliases[mb_strtolower($a)] = $n;
                }
            }
            if (count($emails) >= $max) {
                break;
            }
        }

        $result = [];
        try {
            $resolved = $this->plugin->services()->certs()->resolveRecipients(array_keys($emails));
            foreach ($resolved as $email => $r) {
                $entry = ['status' => $r['status']];
                if ($r['cert'] !== null) {
                    $entry['until'] = gmdate('Y-m-d', $r['cert']->notAfter);
                }
                if ($r['status'] === CertificateService::R_INVALID && $r['detail'] !== '') {
                    $entry['detail'] = $r['detail'];
                }
                if ($r['detail'] === CertificateService::D_REVOCATION_UNKNOWN) {
                    $entry['revocation'] = 'unknown';
                }
                $result[$email] = $entry;
            }
        } catch (MimeShieldException $e) {
            Log::error('compose', 'recipient lookup failed: ' . $e->getMessage());
        }

        $rc->output->command('plugin.mimeshield_recipients', ['recipients' => $result, 'aliases' => $aliases]);
        $rc->output->send();
    }

    /**
     * Addresses posted by the compose script (_addresses: list or comma/newline separated string).
     *
     * @return list<string>
     */
    private static function postedAddresses(): array
    {
        $raw = \rcube_utils::get_input_value('_addresses', \rcube_utils::INPUT_POST);
        $list = [];
        if (is_array($raw)) {
            foreach ($raw as $a) {
                if (is_string($a)) {
                    $list[] = $a;
                }
            }
        } elseif (is_string($raw)) {
            $list = preg_split('/[,\n;]+/', $raw) ?: [];
        }
        return array_slice(array_map('trim', $list), 0, 1000);
    }
}
