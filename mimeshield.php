<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * Sign, verify, encrypt and decrypt e-mail with S/MIME (RFC 8551), PKCS#12 import, encrypted
 * private key store, recipient certificate store, trust validation, multiple identities.
 *
 * @author    MIME Shield contributors
 * @license   GPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

use MimeShield\Config;
use MimeShield\Exception\MimeShieldException;
use MimeShield\Exception\MissingCertificatesException;
use MimeShield\Log;
use MimeShield\Mime\DotGuard;
use MimeShield\Mime\SmimeMessage;
use MimeShield\Services;
use MimeShield\Storage\Database;
use MimeShield\Ui\ComposeUi;
use MimeShield\Ui\MessageUi;
use MimeShield\Ui\SettingsUi;

class mimeshield extends rcube_plugin
{
    public $task = 'mail|settings|cli';

    private rcmail $rc;

    private ?Services $services = null;

    /** @var null|array{sign: bool, encrypt: bool} expectations of the current send request */
    private ?array $expect = null;

    private bool $schemaOk = false;

    #[\Override]
    public function init(): void
    {
        require_once __DIR__ . '/lib/autoload.php';

        $this->rc = rcmail::get_instance();
        $this->load_config();
        Log::setDebug((bool) $this->rc->config->get('mimeshield_debug', false));

        if ($this->rc->task === 'cli') {
            $this->add_hook('user_delete', [$this, 'user_delete']);
            return;
        }

        if (empty($this->rc->user->ID)) {
            return; // login page etc.
        }

        $this->add_texts('localization/', [
            'sign', 'encrypt', 'status', 'nocertificate', 'certvalid', 'recipientsstatus', 'recipient_ok',
            'recipient_missing', 'recipient_expired', 'recipient_invalid', 'recipient_untrusted', 'recipient_checking',
            'missingtitle', 'missingintro', 'sendunencrypted', 'cancel', 'confirmdeletekey', 'confirmdeletecert',
            'confirmreplace', 'saving', 'loading', 'bccwarning', 'forceencryptwarning', 'sendwithoutencrypt',
            'signdisabledidentity', 'importkey', 'importcert', 'certsaved', 'replacetitle', 'replacebutton',
            'enigmaconflict', 'expiresat', 'encryptlocked', 'signingcert',
        ]);

        $this->schemaOk = $this->checkSchema();
        if (!$this->schemaOk) {
            if ($this->rc->task === 'settings') {
                $this->add_hook('settings_actions', [$this, 'settings_actions']);
                $this->register_action('plugin.mimeshield', [$this, 'action_schema_missing']);
            }
            return;
        }

        $action = (string) $this->rc->action;

        if ($this->rc->task === 'mail') {
            $this->add_hook('message_part_structure', [$this, 'message_part_structure']);
            $this->add_hook('message_load', [$this, 'message_load']);
            $this->add_hook('message_part_get', [$this, 'message_part_get']);
            $this->add_hook('message_part_before', [$this, 'message_part_before']);

            if (in_array($action, ['show', 'preview', 'print'], true)) {
                $this->add_hook('message_body_prefix', [$this, 'message_body_prefix']);
                $this->add_hook('template_object_messagebody', [$this, 'template_messagebody']);
                $this->includeAssets();
            } elseif ($action === 'compose') {
                $this->add_hook('message_compose_body', [$this, 'message_compose_body']);
                $this->add_hook('template_container', [$this, 'template_container']);
                $this->includeAssets();
            } elseif ($action === 'send') {
                $this->add_hook('message_ready', [$this, 'message_ready']);
                $this->add_hook('message_before_send', [$this, 'message_before_send']);
            }

            $this->register_action('plugin.mimeshield-recipients', [$this, 'action_recipients']);
            $this->register_action('plugin.mimeshield-savecert', [$this, 'action_savecert']);
        } elseif ($this->rc->task === 'settings') {
            $this->add_hook('settings_actions', [$this, 'settings_actions']);
            $this->add_hook('preferences_list', [$this, 'preferences_list']);
            $this->add_hook('preferences_save', [$this, 'preferences_save']);
            $this->add_hook('identity_delete', [$this, 'identity_delete']);

            foreach (SettingsUi::ACTIONS as $name => $method) {
                $this->register_action($name, [$this, 'settings_dispatch']);
            }
            if (str_starts_with($action, 'plugin.mimeshield')) {
                $this->includeAssets();
            }
        }
    }

    /**
     * Plugin information shown in Roundcube's "About" page.
     *
     * @return array<string, string>
     */
    #[\Override]
    public static function info()
    {
        return [
            'name' => 'MIME Shield',
            'vendor' => 'MIME Shield contributors',
            'version' => '1.0.0',
            'license' => 'GPL-3.0-or-later',
            'uri' => 'https://github.com/takenek/mimeshield',
        ];
    }

    public function services(): Services
    {
        $prefs = !empty($this->rc->user->ID) ? (array) $this->rc->user->get_prefs() : [];
        return $this->services ??= new Services($this->rc, new Config($this->rc->config, $prefs));
    }

    public function config(): Config
    {
        return $this->services()->config;
    }

    public function rcmail(): rcmail
    {
        return $this->rc;
    }

    /**
     * Localized plain text with variables (NOT escaped - escape on output).
     *
     * @param array<string, string> $vars
     */
    public function text(string $label, array $vars = []): string
    {
        return $this->rc->gettext(['name' => 'mimeshield.' . $label, 'vars' => $vars]);
    }

    /**
     * Strict CSRF protection for state-changing plugin actions.
     *
     * Roundcube's global check skips requests with an empty $_POST (e.g. a file-only multipart
     * upload) and all GET requests, so every mutating action requires POST plus a valid request
     * token (X-Roundcube-Request header or _token field), compared in constant time.
     */
    public function requirePostToken(): void
    {
        $token = (string) $this->rc->get_request_token();
        $sent = rcube_utils::request_header('X-Roundcube-Request');
        if (!is_string($sent) || $sent === '') {
            $sent = (string) rcube_utils::get_input_string('_token', rcube_utils::INPUT_POST);
        }
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || $token === '' || !hash_equals($token, (string) $sent)) {
            Log::warning('csrf', 'request token check failed', ['action' => (string) $this->rc->action]);
            header('HTTP/1.1 403 Forbidden');
            exit('Invalid request');
        }
    }

    private function checkSchema(): bool
    {
        $cached = $_SESSION['mimeshield_schema'] ?? null;
        if ($cached === Database::SCHEMA_VERSION) {
            return true;
        }
        try {
            $ok = $this->services()->db()->isSchemaCurrent();
        } catch (Throwable $e) {
            $ok = false;
        }
        if ($ok) {
            $_SESSION['mimeshield_schema'] = Database::SCHEMA_VERSION;
        } else {
            Log::error('schema', 'MIME Shield database schema missing or outdated - run bin/updatedb.sh --package=mimeshield --dir=plugins/mimeshield/SQL');
        }
        return $ok;
    }

    private function includeAssets(): void
    {
        $this->include_script('js/mimeshield.js');
        $skin = $this->local_skin_path();
        $this->include_stylesheet((is_dir($this->home . '/' . $skin) ? $skin : 'skins/elastic') . '/mimeshield.css');
    }

    // ------------------------------------------------------------------ incoming mail

    public function message_part_structure(array $p): array
    {
        $action = (string) $this->rc->action;
        $verify = in_array($action, ['show', 'preview', 'print', 'plugin.mimeshield-savecert'], true);
        $decrypt = $action !== 'compose' || $this->config()->bool('mimeshield_decrypt_in_compose');
        return $this->services()->incoming($verify, $decrypt)->partStructure($p);
    }

    public function message_load(array $p): array
    {
        if (!$this->services()->hasIncoming() || empty($p['object'])) {
            return $p;
        }
        $incoming = $this->services()->incoming(false);
        if ($incoming->hasDecrypted()) {
            // EFAIL hardening for every path that washes decrypted HTML outside print_body() (get
            // action, HTML reply/forward): never treat a message with decrypted content as "safe"
            $p['object']->is_safe = false;
            $this->rc->config->set('show_images', 0);
            unset($_GET['_safe'], $_REQUEST['_safe']);
        }
        $hidden = $incoming->hiddenParts();
        if ($hidden !== [] && is_array($p['object']->attachments)) {
            $p['object']->attachments = array_values(array_filter(
                $p['object']->attachments,
                static fn ($a) => !in_array((string) $a->mime_id, $hidden, true)
            ));
        }
        return $p;
    }

    public function message_part_get(array $p): array
    {
        if ($this->services()->hasIncoming() && $this->services()->incoming(false)->isDecryptedPart((string) ($p['id'] ?? ''))) {
            // never write thumbnails of decrypted images to the persistent thumbnail cache
            if (!empty($_GET['_thumb'])) {
                $_GET['_thumb'] = 0;
                $_GET['_embed'] = 1;
                $_REQUEST['_embed'] = 1;
            }
            header('Cache-Control: private, no-store, max-age=0');
        }
        return $p;
    }

    public function message_part_before(array $p): array
    {
        if ($this->services()->hasIncoming() && $this->services()->incoming(false)->isDecryptedPart((string) ($p['id'] ?? ''))) {
            // EFAIL hardening: never load remote resources from decrypted HTML
            $p['safe'] = false;
        }
        return $p;
    }

    public function message_body_prefix(array $p): array
    {
        if (!$this->services()->hasIncoming()) {
            return $p;
        }
        return (new MessageUi($this))->bodyPrefix($p);
    }

    public function template_messagebody(array $p): array
    {
        if (!$this->services()->hasIncoming()) {
            return $p;
        }
        return (new MessageUi($this))->messageBody($p);
    }

    // ------------------------------------------------------------------ compose

    public function message_compose_body(array $p): array
    {
        return (new ComposeUi($this))->composeBody($p);
    }

    public function template_container(array $p): array
    {
        if (($p['name'] ?? '') === 'composeoptions') {
            $p['content'] = ($p['content'] ?? '') . (new ComposeUi($this))->optionsHtml();
        }
        return $p;
    }

    public function action_recipients(): void
    {
        $this->requirePostToken();
        (new ComposeUi($this))->recipientsAction();
    }

    public function action_savecert(): void
    {
        $this->requirePostToken();
        (new MessageUi($this))->saveCertAction();
    }

    // ------------------------------------------------------------------ sending

    public function message_ready(array $p): array
    {
        $saveonly = !empty($_GET['_saveonly']);
        $draft = !empty($_POST['_draft']) && !$saveonly;
        $cfg = $this->config();

        $sign = (bool) rcube_utils::get_input_value('_mimeshield_sign', rcube_utils::INPUT_POST);
        $encrypt = (bool) rcube_utils::get_input_value('_mimeshield_encrypt', rcube_utils::INPUT_POST);
        // locked options are enforced server-side with the ADMINISTRATOR value
        if ($cfg->isLocked('sign')) {
            $sign = $cfg->optionDefault('sign');
        }
        if ($cfg->isLocked('encrypt')) {
            $encrypt = $cfg->optionDefault('encrypt');
        }

        try {
            if ($sign && !$cfg->bool('mimeshield_enable_signing')) {
                throw new \MimeShield\Exception\ValidationException('signingdisabled', 'signing disabled by administrator');
            }
            if ($encrypt && !$cfg->bool('mimeshield_enable_encryption')) {
                throw new \MimeShield\Exception\ValidationException('encryptiondisabled', 'encryption disabled by administrator');
            }
            if (!$sign && !$encrypt) {
                if ($draft) {
                    // still remember (unchecked) options in the draft
                    $p['message']->headers([\MimeShield\Service\OutgoingService::DRAFT_HEADER => 'sign=0; encrypt=0'], true);
                }
                return $p;
            }
            if (rcube_utils::get_input_value('_enigma_sign', rcube_utils::INPUT_POST) || rcube_utils::get_input_value('_enigma_encrypt', rcube_utils::INPUT_POST)) {
                throw new \MimeShield\Exception\ValidationException('enigmaconflict', 'PGP and S/MIME selected together');
            }

            $identity = $this->composeIdentity();
            $result = $this->services()->outgoing()->process($p['message'], $identity, $sign, $encrypt, $draft);
            if ($result !== null) {
                $p['message'] = $result;
            }
            if (!$draft) {
                $this->expect = ['sign' => $sign, 'encrypt' => $encrypt];
            }
        } catch (MissingCertificatesException $e) {
            $this->abortSend($e, $draft, ['recipients' => $e->recipients()]);
        } catch (MimeShieldException $e) {
            $this->abortSend($e, $draft);
        } catch (Throwable $e) {
            Log::error('send', 'unexpected error: ' . get_class($e) . ': ' . $e->getMessage());
            $this->abortSend(new \MimeShield\Exception\CryptoException('internalerror', $e->getMessage()), $draft);
        }

        return $p;
    }

    /**
     * Last line of defence (fail closed) + per-recipient Bcc envelopes + Net_SMTP dot guard.
     */
    public function message_before_send(array $p): array
    {
        if ($this->expect === null) {
            return $p; // not a mimeshield send (or another action reaching rcube::deliver_message)
        }
        $msg = $p['message'] ?? null;
        $ok = $msg instanceof SmimeMessage
            && (!$this->expect['sign'] || $msg->isSigned())
            && (!$this->expect['encrypt'] || $msg->isEncrypted())
            && !$msg->isDraft();
        if (!$ok) {
            Log::error('send', 'S/MIME was requested but the message to be sent is not protected - blocking');
            return ['abort' => true, 'result' => false, 'error' => ['label' => 'mimeshield.internalerror', 'vars' => []]] + $p;
        }

        // Net_SMTP string path: keep chunk borders away from mid-line dots (clear-signed only)
        if ($msg->isSigned() && !$msg->isEncrypted()) {
            for ($i = 0; $i < 8; $i++) {
                $data = (clone $msg)->txtHeaders(['Bcc' => null], true) . "\r\n" . $msg->body();
                if (DotGuard::riskyOffsets($data) === []) {
                    break;
                }
                $msg->padPreamble(1);
            }
        }

        $envelopes = $msg->bccEnvelopes();
        if ($envelopes !== []) {
            $rc = $this->rc;
            if (!is_object($rc->smtp)) {
                $rc->smtp_init(true);
            }
            $headers = $msg->variant()->txtHeaders(['Bcc' => null], true);
            foreach ($envelopes as $env) {
                $sent = $rc->smtp->send_mail($p['from'], [$env['address']], $headers, $env['body'], $p['options'] ?? []);
                if (!$sent) {
                    Log::error('send', 'Bcc envelope delivery failed', ['response' => implode(' ', (array) $rc->smtp->get_response())]);
                    return ['abort' => true, 'result' => false, 'error' => ['label' => 'mimeshield.bccsendfailed', 'vars' => []]] + $p;
                }
            }
            // main delivery without the Bcc recipients (they got their own envelopes); the Sent copy
            // (original object) keeps the Bcc header
            $p['message'] = $msg->variant();
            $mainRecipients = \MimeShield\Trust\AddressMatcher::parseList(implode(', ', array_filter([
                is_array($p['mailto'] ?? null) ? implode(', ', $p['mailto']) : (string) ($p['mailto'] ?? ''),
                (string) ($p['message']->headers()['Cc'] ?? ''),
            ])), true);
            if ($mainRecipients === []) {
                // Bcc-only message: every recipient already got an envelope; report success so that
                // Roundcube stores the Sent copy instead of attempting an SMTP transaction without recipients
                return ['abort' => true, 'result' => true] + $p;
            }
        }

        return $p;
    }

    /**
     * Identity selected in compose, verified to belong to the user.
     *
     * @return array{identity_id: int, email: string}
     */
    private function composeIdentity(): array
    {
        $from = rcube_utils::get_input_string('_from', rcube_utils::INPUT_POST);
        if (!is_numeric($from)) {
            throw new \MimeShield\Exception\ValidationException('signnoidentity', 'free-text From is not an identity');
        }
        $ident = $this->rc->user->get_identity((int) $from); // scoped to the current user
        if (empty($ident) || empty($ident['email'])) {
            throw new \MimeShield\Exception\ValidationException('signnoidentity', 'identity not found');
        }
        return ['identity_id' => (int) $ident['identity_id'], 'email' => (string) $ident['email']];
    }

    /**
     * Stop the send/draft request with a user-visible error (send() exits).
     *
     * @param array<string, mixed> $data
     */
    private function abortSend(MimeShieldException $e, bool $draft, array $data = []): void
    {
        $label = 'mimeshield.' . $e->getUserLabel();
        if (!$this->rc->text_exists($label)) {
            $label = 'mimeshield.internalerror';
        }
        Log::info('send', 'sending blocked: ' . $e->getMessage(), ['draft' => $draft]);
        $this->rc->output->show_message($label, 'error', $e->getVars());
        if ($data !== []) {
            $this->rc->output->command('plugin.mimeshield_send_error', ['type' => $e->getUserLabel()] + $data);
        }
        if ($draft) {
            $this->rc->output->command('auto_save_start');
        }
        $this->rc->output->send('iframe');
    }

    // ------------------------------------------------------------------ settings

    public function settings_actions(array $p): array
    {
        $p['actions'][] = [
            'action' => 'plugin.mimeshield',
            'class' => 'mimeshield-keys',
            'label' => 'mykeys',
            'title' => 'mykeystitle',
            'domain' => 'mimeshield',
        ];
        if ($this->schemaOk) {
            $p['actions'][] = [
                'action' => 'plugin.mimeshield-contacts',
                'class' => 'mimeshield-contacts',
                'label' => 'contactcerts',
                'title' => 'contactcertstitle',
                'domain' => 'mimeshield',
            ];
        }
        return $p;
    }

    public function settings_dispatch(): void
    {
        (new SettingsUi($this))->dispatch((string) $this->rc->action);
    }

    public function action_schema_missing(): void
    {
        $this->rc->output->set_pagetitle($this->text('mykeys'));
        $this->rc->output->show_message('mimeshield.schemamissing', 'error');
        $this->rc->output->send('mimeshield.schema');
    }

    public function preferences_list(array $p): array
    {
        return (new SettingsUi($this))->preferencesList($p);
    }

    public function preferences_save(array $p): array
    {
        return (new SettingsUi($this))->preferencesSave($p);
    }

    public function identity_delete(array $p): array
    {
        // identities are soft-deleted (del=1): remove the signing bindings explicitly. Roundcube
        // refuses to delete the last identity (rcube_user::delete_identity), so keep its binding.
        if (count((array) $this->rc->user->list_identities()) <= 1) {
            return $p;
        }
        try {
            $repo = $this->services()->keys()->repository();
            foreach (explode(',', (string) ($p['id'] ?? '')) as $iid) {
                if (ctype_digit(trim($iid))) {
                    $repo->unbind((int) trim($iid));
                }
            }
        } catch (Throwable $e) {
            Log::error('identity', 'cannot remove bindings of deleted identity: ' . $e->getMessage());
        }
        return $p;
    }

    public function user_delete(array $p): array
    {
        // rows are removed by the FK cascade; delete explicitly as well (inside deluser.sh transaction)
        try {
            if (!empty($p['user']) && $p['user'] instanceof rcube_user && $p['user']->ID) {
                $db = new Database($this->rc->get_dbh());
                $uid = (int) $p['user']->ID;
                foreach (['mimeshield_bindings', 'mimeshield_cert_emails', 'mimeshield_certs', 'mimeshield_keys'] as $t) {
                    $db->query('DELETE FROM ' . $db->table($t) . ' WHERE `user_id` = ?', $uid);
                }
            }
        } catch (Throwable $e) {
            Log::error('user_delete', 'cleanup failed: ' . $e->getMessage());
            $p['abort'] = true;
        }
        return $p;
    }
}
