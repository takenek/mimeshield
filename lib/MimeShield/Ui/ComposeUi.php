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
use MimeShield\Service\CertificateService;
use MimeShield\Service\OutgoingService;
use MimeShield\Trust\AddressMatcher;

/**
 * Compose screen: "Sign S/MIME" / "Encrypt S/MIME" options, sender certificate status and
 * recipient certificate status (AJAX, debounced and cached on the client).
 */
final class ComposeUi
{
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
        if (($mode === 'draft' || $mode === 'edit') && $message instanceof \rcube_message && $message->uid) {
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
        $signDefault = (bool) $rc->config->get('mimeshield_sign_default', false);
        $encDefault = (bool) $rc->config->get('mimeshield_encrypt_default', false) || !empty($state['force']);
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

        return \html::div(['id' => 'mimeshield-compose', 'class' => 'mimeshield-compose'],
            \html::tag('h3', ['class' => 'voice'], \rcube::Q($this->plugin->text('smimeoptions'))) . $rows . $status);
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
                $entry['reason'] = $this->plugin->text($e->getUserLabel(), $e->getVars());
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
        $input = self::postedAddresses();
        $max = $this->plugin->config()->int('mimeshield_max_recipients', 1, 1000);
        $emails = [];
        foreach ($input as $a) {
            $n = AddressMatcher::normalize($a);
            if ($n !== null) {
                $emails[$n] = true;
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
                $result[$email] = $entry;
            }
        } catch (MimeShieldException $e) {
            Log::error('compose', 'recipient lookup failed: ' . $e->getMessage());
        }

        $rc->output->command('plugin.mimeshield_recipients', ['recipients' => $result]);
        $rc->output->send();
    }

    /**
     * AJAX: refreshed identity map (e.g. after importing a certificate in another tab).
     */
    public function identitiesAction(): void
    {
        $rc = $this->plugin->rcmail();
        $rc->output->command('plugin.mimeshield_identities', ['identities' => $this->identityMap()]);
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
