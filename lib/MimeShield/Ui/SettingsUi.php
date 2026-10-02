<?php

declare(strict_types=1);

/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Ui;

use MimeShield\Cert\Certificate;
use MimeShield\Exception\ConfigException;
use MimeShield\Exception\MimeShieldException;
use MimeShield\KeyStore\KeyVault;
use MimeShield\Log;
use MimeShield\Storage\CertRecord;
use MimeShield\Storage\KeyRecord;
use MimeShield\Trust\AddressMatcher;
use MimeShield\Trust\ChainResult;
use MimeShield\Trust\ChainValidator;

/**
 * Settings: "S/MIME certificates" (own keys) and "S/MIME contacts" (recipient certificates),
 * plus the S/MIME block in Preferences > Encryption.
 *
 * Private keys are never exported and never sent to the browser.
 */
final class SettingsUi
{
    public const ACTIONS = [
        'plugin.mimeshield' => 'keysPage',
        'plugin.mimeshield-keyinfo' => 'keyInfo',
        'plugin.mimeshield-keyimport' => 'keyImport',
        'plugin.mimeshield-keydelete' => 'keyDelete',
        'plugin.mimeshield-bind' => 'bind',
        'plugin.mimeshield-export' => 'export',
        'plugin.mimeshield-contacts' => 'contactsPage',
        'plugin.mimeshield-certinfo' => 'certInfo',
        'plugin.mimeshield-certimport' => 'certImport',
        'plugin.mimeshield-certdelete' => 'certDelete',
        'plugin.mimeshield-certprefer' => 'certPrefer',
    ];

    private const MUTATING = [
        'plugin.mimeshield-keydelete', 'plugin.mimeshield-bind', 'plugin.mimeshield-certdelete', 'plugin.mimeshield-certprefer',
    ];

    private \rcmail $rc;

    private string $frameHtml = '';

    public function __construct(private readonly \mimeshield $plugin)
    {
        $this->rc = $plugin->rcmail();
    }

    public function dispatch(string $action): void
    {
        $method = self::ACTIONS[$action] ?? null;
        if ($method === null) {
            return;
        }
        if (in_array($action, self::MUTATING, true)) {
            $this->plugin->requirePostToken();
        }
        try {
            $this->{$method}();
        } catch (MimeShieldException $e) {
            Log::info('settings', $action . ' failed: ' . $e->getMessage());
            $this->fail($e->getUserLabel(), $e->getVars());
        } catch (\Throwable $e) {
            Log::error('settings', $action . ' unexpected error: ' . get_class($e) . ': ' . $e->getMessage());
            $this->fail('internalerror');
        }
    }

    // ------------------------------------------------------------------ list pages

    private function keysPage(): void
    {
        $this->rc->output->set_pagetitle($this->plugin->text('mykeys'));
        $this->rc->output->set_env('mimeshield_page', 'keys');
        $this->rc->output->set_env('mimeshield_select', (int) \rcube_utils::get_input_string('_sel', \rcube_utils::INPUT_GET));
        $this->keystoreWarning();
        $this->plugin->register_handler('plugin.mimeshieldlist', [$this, 'keysList']);
        $this->plugin->register_handler('plugin.mimeshieldtitle', fn () => \rcube::Q($this->plugin->text('mykeys')));
        $this->rc->output->send('mimeshield.list');
    }

    private function contactsPage(): void
    {
        $this->rc->output->set_pagetitle($this->plugin->text('contactcerts'));
        $this->rc->output->set_env('mimeshield_page', 'contacts');
        $this->rc->output->set_env('mimeshield_select', (int) \rcube_utils::get_input_string('_sel', \rcube_utils::INPUT_GET));
        $this->plugin->register_handler('plugin.mimeshieldlist', [$this, 'contactsList']);
        $this->plugin->register_handler('plugin.mimeshieldtitle', fn () => \rcube::Q($this->plugin->text('contactcerts')));
        $this->rc->output->send('mimeshield.list');
    }

    /**
     * @param array<string, string> $attrib
     */
    public function keysList(array $attrib): string
    {
        $bindings = $this->plugin->services()->keys()->repository()->bindings();
        $boundCount = array_count_values($bindings);
        $rows = '';
        foreach ($this->plugin->services()->keys()->repository()->all() as $rec) {
            try {
                $c = $rec->certificate();
            } catch (MimeShieldException) {
                continue;
            }
            $badges = $this->validityBadge($c);
            if (!empty($boundCount[$rec->id()])) {
                $badges .= ' ' . \html::span('mimeshield-badge mimeshield-badge-ok', \rcube::Q($this->plugin->text('badge_signing')));
            }
            $rows .= $this->listRow($rec->id(), $c->displayName(), implode(', ', $c->emails()) ?: '-', $c, $badges);
        }
        return $this->listTable($attrib, $rows, 'nokeys');
    }

    /**
     * @param array<string, string> $attrib
     */
    public function contactsList(array $attrib): string
    {
        $rows = '';
        foreach ($this->plugin->services()->certs()->repository()->all() as $rec) {
            try {
                $c = $rec->certificate();
            } catch (MimeShieldException) {
                continue;
            }
            $badges = $this->validityBadge($c) . ' ' . $this->trustBadge($rec->trust());
            if ($rec->preferredFor !== []) {
                $badges .= ' ' . \html::span('mimeshield-badge', \rcube::Q($this->plugin->text('badge_preferred')));
            }
            $rows .= $this->listRow($rec->id(), implode(', ', $rec->emails()) ?: '-', $c->displayName(), $c, $badges);
        }
        return $this->listTable($attrib, $rows, 'nocerts');
    }

    /**
     * @param array<string, string> $attrib
     */
    private function listTable(array $attrib, string $rows, string $emptyLabel): string
    {
        $id = $attrib['id'] ?? 'mimeshield-list';
        $this->rc->output->add_gui_object('mimeshieldlist', $id);
        $this->rc->output->set_env('mimeshield_list_empty', $rows === '');
        $table = \html::tag('table', [
            'id' => $id,
            'class' => trim(($attrib['class'] ?? '') . ' listing records-table mimeshield-list'),
            'role' => 'listbox',
            'data-label-msg' => $this->plugin->text($emptyLabel),
        ], \html::tag('tbody', [], $rows));
        return $table;
    }

    private function listRow(int $id, string $title, string $subtitle, Certificate $c, string $badges): string
    {
        $content = \html::span('name', \rcube::Q($title))
            . \html::span('mimeshield-sub', \rcube::Q($subtitle))
            . \html::span('mimeshield-sub', \rcube::Q($this->plugin->text('validuntil')) . ': ' . \rcube::Q(gmdate('Y-m-d', $c->notAfter)) . ' ' . $badges);
        return \html::tag('tr', ['id' => 'rcmrow' . $id], \html::tag('td', ['class' => 'name'], $content));
    }

    private function validityBadge(Certificate $c): string
    {
        if ($c->isExpired()) {
            return \html::span('mimeshield-badge mimeshield-badge-error', \rcube::Q($this->plugin->text('badge_expired')));
        }
        if ($c->isNotYetValid()) {
            return \html::span('mimeshield-badge mimeshield-badge-warning', \rcube::Q($this->plugin->text('badge_notyet')));
        }
        return \html::span('mimeshield-badge mimeshield-badge-ok', \rcube::Q($this->plugin->text('badge_valid')));
    }

    private function trustBadge(string $trust): string
    {
        $cls = $trust === 'verified' ? 'ok' : 'warning';
        return \html::span('mimeshield-badge mimeshield-badge-' . $cls, \rcube::Q($this->plugin->text('trust_' . $trust)));
    }

    // ------------------------------------------------------------------ own keys

    private function keyInfo(?int $id = null): void
    {
        $id ??= (int) \rcube_utils::get_input_string('_id', \rcube_utils::INPUT_GET);
        $rec = $this->plugin->services()->keys()->repository()->get($id);
        if ($rec === null) {
            $this->fail('notfound');
        }
        $c = $rec->certificate();
        $html = $this->certTable($c, $rec->chainPems(), ChainValidator::PURPOSE_SIGN);
        $html .= $this->bindingForm($rec);
        $html .= \html::div('formbuttons mimeshield-buttons',
            \html::a(['href' => '#', 'class' => 'button mimeshield-export', 'data-type' => 'key', 'data-id' => (string) $rec->id()], \rcube::Q($this->plugin->text('exportpublic')))
            . ' ' . \html::a(['href' => '#', 'class' => 'button delete mimeshield-delete', 'data-type' => 'key', 'data-id' => (string) $rec->id()], \rcube::Q($this->plugin->text('deletekey')))
        );
        $html .= \html::p('hint mimeshield-hint', \rcube::Q($this->plugin->text('keystorednotice')));
        $this->rc->output->set_env('mimeshield_item', $rec->id());
        $this->sendFrame($this->plugin->text('keyprops'), $html);
    }

    private function bindingForm(KeyRecord $rec): string
    {
        $c = $rec->certificate();
        $keys = $this->plugin->services()->keys();
        $bindings = $keys->repository()->bindings();
        $rows = '';
        foreach ((array) $this->rc->user->list_identities() as $ident) {
            $iid = (int) $ident['identity_id'];
            $eligible = $keys->isUsableForSigning($rec, (string) $ident['email']);
            $checked = ($bindings[$iid] ?? null) === $rec->id();
            $cb = new \html_checkbox(['name' => '_identities[]', 'value' => (string) $iid, 'id' => 'msident' . $iid, 'disabled' => !$eligible && !$checked]);
            $label = trim((string) $ident['name'] . ' <' . (string) $ident['email'] . '>');
            $note = '';
            if (!$eligible) {
                $note = ' ' . \html::span('hint', \rcube::Q($this->plugin->text(
                    AddressMatcher::matchesAny((string) $ident['email'], $c->emails()) ? 'bind_notusable' : 'bind_wrongaddress')));
            }
            $rows .= \html::div('form-check', $cb->show($checked ? (string) $iid : '') . ' '
                . \html::label(['for' => 'msident' . $iid, 'class' => 'form-check-label'], \rcube::Q($label)) . $note);
        }
        return \html::tag('fieldset', ['class' => 'mimeshield-bindings'],
            \html::tag('legend', [], \rcube::Q($this->plugin->text('signidentities')))
            . \html::p('hint', \rcube::Q($this->plugin->text('signidentitieshint')))
            . $rows
            . \html::p('formbuttons', \html::a(['href' => '#', 'class' => 'button mainaction mimeshield-bind', 'data-id' => (string) $rec->id()], \rcube::Q($this->plugin->text('savebindings')))));
    }

    private function keyImport(): void
    {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            $this->importForm('key');
            return;
        }
        $this->plugin->requirePostToken();
        $password = (string) \rcube_utils::get_input_string('_password', \rcube_utils::INPUT_POST, true);
        unset($_POST['_password'], $_REQUEST['_password']);
        try {
            $data = $this->uploadedFile($this->plugin->config()->int('mimeshield_max_key_upload', 1024, 1048576), ['p12', 'pfx', 'pem', 'key']);
            $identities = array_map(static fn ($i) => ['identity_id' => $i['identity_id'], 'email' => (string) $i['email']], (array) $this->rc->user->list_identities());
            $result = $this->plugin->services()->keys()->import($data, $password, $identities);
        } catch (MimeShieldException $e) {
            Log::info('import', 'key import rejected: ' . $e->getMessage());
            $this->rc->output->show_message('mimeshield.' . $this->knownLabel($e->getUserLabel()), 'error', $e->getVars());
            $this->importForm('key');
            return;
        } finally {
            KeyVault::wipe($password);
            if (isset($data)) {
                KeyVault::wipe($data);
            }
        }
        $this->rc->output->show_message('mimeshield.keyimported', 'confirmation');
        foreach ($result['warnings'] as $w) {
            $this->rc->output->show_message('mimeshield.' . $w, 'warning');
        }
        $this->rc->output->command('parent.mimeshield_list_reload', $result['id']);
        $this->keyInfo($result['id']);
    }

    private function keyDelete(): void
    {
        $id = (int) \rcube_utils::get_input_string('_id', \rcube_utils::INPUT_POST);
        if (!$this->plugin->services()->keys()->delete($id)) {
            $this->fail('notfound');
        }
        $this->rc->output->show_message('mimeshield.keydeleted', 'confirmation');
        $this->rc->output->command('plugin.mimeshield_list_reload', ['id' => 0]);
        $this->rc->output->send();
    }

    private function bind(): void
    {
        $keyId = (int) \rcube_utils::get_input_string('_id', \rcube_utils::INPUT_POST);
        $posted = array_map('intval', (array) \rcube_utils::get_input_value('_identities', \rcube_utils::INPUT_POST));
        $keys = $this->plugin->services()->keys();
        $repo = $keys->repository();
        $rec = $repo->get($keyId);
        if ($rec === null) {
            $this->fail('notfound');
        }
        $current = $repo->bindings();
        foreach ((array) $this->rc->user->list_identities() as $ident) {
            $iid = (int) $ident['identity_id'];
            $want = in_array($iid, $posted, true);
            if ($want && ($current[$iid] ?? null) !== $keyId) {
                // never bind a certificate to an identity with another address (or unusable cert)
                if (!$keys->isUsableForSigning($rec, (string) $ident['email'])) {
                    $this->fail('bind_wrongaddress');
                }
                $repo->bind($iid, $keyId);
            } elseif (!$want && ($current[$iid] ?? null) === $keyId) {
                $repo->unbind($iid);
            }
        }
        $this->rc->output->show_message('mimeshield.bindingssaved', 'confirmation');
        $this->rc->output->command('plugin.mimeshield_list_reload', ['id' => $keyId]);
        $this->rc->output->send();
    }

    /**
     * Download a PUBLIC certificate (own or contact). Private keys can never be exported.
     */
    private function export(): void
    {
        $this->rc->request_security_check(\rcube_utils::INPUT_GET);
        $type = (string) \rcube_utils::get_input_string('_type', \rcube_utils::INPUT_GET);
        $id = (int) \rcube_utils::get_input_string('_id', \rcube_utils::INPUT_GET);
        $cert = null;
        if ($type === 'key') {
            $cert = $this->plugin->services()->keys()->repository()->get($id)?->certificate();
        } elseif ($type === 'cert') {
            $cert = $this->plugin->services()->certs()->repository()->get($id)?->certificate();
        }
        if ($cert === null) {
            $this->fail('notfound');
        }
        $name = 'certificate-' . substr($cert->fingerprint, 0, 16) . '.pem';
        $this->rc->output->download_headers($name, ['type' => 'application/x-pem-file', 'length' => strlen($cert->pem)]);
        echo $cert->pem;
        exit;
    }

    // ------------------------------------------------------------------ contacts

    private function certInfo(?int $id = null): void
    {
        $id ??= (int) \rcube_utils::get_input_string('_id', \rcube_utils::INPUT_GET);
        $rec = $this->plugin->services()->certs()->repository()->get($id);
        if ($rec === null) {
            $this->fail('notfound');
        }
        $c = $rec->certificate();
        $html = $this->certTable($c, $rec->chainPems(), $c->canEncrypt() ? ChainValidator::PURPOSE_ENCRYPT : ChainValidator::PURPOSE_SIGN, $rec);
        $html .= $this->preferredForm($rec);
        $html .= \html::div('formbuttons mimeshield-buttons',
            \html::a(['href' => '#', 'class' => 'button mimeshield-export', 'data-type' => 'cert', 'data-id' => (string) $rec->id()], \rcube::Q($this->plugin->text('exportpublic')))
            . ' ' . \html::a(['href' => '#', 'class' => 'button delete mimeshield-delete', 'data-type' => 'cert', 'data-id' => (string) $rec->id()], \rcube::Q($this->plugin->text('deletecert')))
        );
        $this->rc->output->set_env('mimeshield_item', $rec->id());
        $this->sendFrame($this->plugin->text('certprops'), $html);
    }

    private function preferredForm(CertRecord $rec): string
    {
        $out = '';
        $repo = $this->plugin->services()->certs()->repository();
        foreach ($rec->emails() as $email) {
            $others = $repo->findByEmail($email);
            if (count($others) < 2) {
                continue;
            }
            $isPref = in_array($email, $rec->preferredFor, true);
            $out .= \html::div('form-check',
                \rcube::Q($email) . ': '
                . ($isPref
                    ? \html::span('mimeshield-badge mimeshield-badge-ok', \rcube::Q($this->plugin->text('badge_preferred')))
                    : \html::a(['href' => '#', 'class' => 'button mimeshield-prefer', 'data-id' => (string) $rec->id(), 'data-email' => $email], \rcube::Q($this->plugin->text('makepreferred'))))
                . ' ' . \html::span('hint', \rcube::Q($this->plugin->text('certsforaddress', ['n' => (string) count($others)]))));
        }
        return $out === '' ? '' : \html::tag('fieldset', ['class' => 'mimeshield-preferred'], \html::tag('legend', [], \rcube::Q($this->plugin->text('preferredcert'))) . $out);
    }

    private function certImport(): void
    {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            unset($_SESSION['mimeshield_pending_cert']);
            $this->importForm('cert');
            return;
        }
        $this->plugin->requirePostToken();
        $confirmed = (bool) \rcube_utils::get_input_value('_confirm', \rcube_utils::INPUT_POST);
        if ($confirmed && !empty($_SESSION['mimeshield_pending_cert']) && is_string($_SESSION['mimeshield_pending_cert'])) {
            // public certificate data kept in the session between upload and confirmation
            $data = base64_decode($_SESSION['mimeshield_pending_cert'], true) ?: '';
        } else {
            try {
                $data = $this->uploadedFile($this->plugin->config()->int('mimeshield_max_cert_upload', 1024, 1048576), ['cer', 'crt', 'pem', 'der', 'p7b', 'p7c']);
            } catch (MimeShieldException $e) {
                $this->rc->output->show_message('mimeshield.' . $this->knownLabel($e->getUserLabel()), 'error', $e->getVars());
                $this->importForm('cert');
                return;
            }
        }
        unset($_SESSION['mimeshield_pending_cert']);

        try {
            $result = $this->plugin->services()->certs()->importFile($data, $confirmed);
        } catch (MimeShieldException $e) {
            Log::info('import', 'certificate import rejected: ' . $e->getMessage());
            $this->rc->output->show_message('mimeshield.' . $this->knownLabel($e->getUserLabel()), 'error', $e->getVars());
            $this->importForm('cert');
            return;
        }
        if ($result['confirm'] !== []) {
            $_SESSION['mimeshield_pending_cert'] = base64_encode($data);
            $this->confirmReplaceForm($result['confirm']);
            return;
        }
        if ($result['imported'] === []) {
            $this->rc->output->show_message('mimeshield.certexists', 'warning');
            $this->importForm('cert');
            return;
        }
        $first = $result['imported'][0];
        $this->rc->output->show_message('mimeshield.certimported', 'confirmation');
        if ($first['trust'] !== 'verified') {
            $this->rc->output->show_message('mimeshield.certimporteduntrusted', 'warning');
        }
        $this->rc->output->command('parent.mimeshield_list_reload', $first['id']);
        $this->certInfo($first['id']);
    }

    /**
     * @param list<array{email: string, old: list<string>, new: string}> $changes
     */
    private function confirmReplaceForm(array $changes): void
    {
        $items = '';
        foreach ($changes as $ch) {
            $items .= \html::tag('li', [], \html::tag('strong', [], \rcube::Q($ch['email'])) . \html::br()
                . \rcube::Q($this->plugin->text('oldfingerprint')) . ': ' . \html::tag('code', [], \rcube::Q(implode(', ', array_map([MessageUi::class, 'formatFingerprint'], $ch['old'])))) . \html::br()
                . \rcube::Q($this->plugin->text('newfingerprint')) . ': ' . \html::tag('code', [], \rcube::Q(MessageUi::formatFingerprint($ch['new']))));
        }
        $form = $this->rc->output->form_tag(['action' => $this->rc->url(['action' => 'plugin.mimeshield-certimport', '_framed' => 1]), 'method' => 'post'],
            \html::div('boxwarning mimeshield-warning', \rcube::Q($this->plugin->text('fingerprintchanged')))
            . \html::tag('ul', [], $items)
            . (new \html_hiddenfield(['name' => '_confirm', 'value' => '1']))->show()
            . \html::p('formbuttons', \html::tag('button', ['type' => 'submit', 'class' => 'button mainaction'], \rcube::Q($this->plugin->text('replacebutton')))));
        $this->sendFrame($this->plugin->text('replacetitle'), $form);
    }

    private function certDelete(): void
    {
        $id = (int) \rcube_utils::get_input_string('_id', \rcube_utils::INPUT_POST);
        if (!$this->plugin->services()->certs()->repository()->delete($id)) {
            $this->fail('notfound');
        }
        $this->rc->output->show_message('mimeshield.certdeleted', 'confirmation');
        $this->rc->output->command('plugin.mimeshield_list_reload', ['id' => 0]);
        $this->rc->output->send();
    }

    private function certPrefer(): void
    {
        $id = (int) \rcube_utils::get_input_string('_id', \rcube_utils::INPUT_POST);
        $email = AddressMatcher::normalize((string) \rcube_utils::get_input_string('_email', \rcube_utils::INPUT_POST));
        $rec = $this->plugin->services()->certs()->repository()->get($id);
        if ($rec === null || $email === null || !in_array($email, $rec->emails(), true)) {
            $this->fail('notfound');
        }
        $this->plugin->services()->certs()->repository()->setPreferred($id, $email);
        $this->rc->output->show_message('mimeshield.preferredsaved', 'confirmation');
        $this->rc->output->command('plugin.mimeshield_list_reload', ['id' => $id]);
        $this->rc->output->send();
    }

    // ------------------------------------------------------------------ shared rendering

    /**
     * @param list<string> $chainPems
     */
    private function certTable(Certificate $c, array $chainPems, string $purpose, ?CertRecord $rec = null): string
    {
        $chain = $this->plugin->services()->chains()->validate($c, $chainPems, $purpose);
        $rows = [
            'subject' => $c->subject,
            'issuer' => $c->issuer,
            'emailaddress' => implode(', ', $c->emails()) ?: '-',
            'serial' => $c->serialHex,
            'fingerprint' => MessageUi::formatFingerprint($c->fingerprint),
            'validfrom' => gmdate('Y-m-d H:i', $c->notBefore) . ' UTC',
            'validuntil' => gmdate('Y-m-d H:i', $c->notAfter) . ' UTC',
            'keyusage' => implode(', ', $c->keyUsageNames()) ?: $this->plugin->text('notrestricted'),
            'extkeyusage' => implode(', ', $c->extendedKeyUsageNames()) ?: $this->plugin->text('notrestricted'),
            'keyalgorithm' => $c->keyDescription(),
            'signaturealg' => $c->signatureAlgorithm,
            'chainstatus' => $this->plugin->text('chainstatus_' . $chain->status),
            'chain' => implode(' → ', $chain->path),
            'usage' => implode(', ', array_filter([$c->canSign() ? $this->plugin->text('usage_sign') : '', $c->canEncrypt() ? $this->plugin->text('usage_encrypt') : ''])) ?: '-',
        ];
        if ($c->usesLegacySubjectEmail()) {
            $rows['emailaddress'] .= ' (' . $this->plugin->text('legacyemailshort') . ')';
        }
        if ($rec !== null) {
            $rows['trust'] = $this->plugin->text('trust_' . $rec->trust());
            $rows['source'] = $this->plugin->text('source_' . $rec->source());
            $rows['added'] = $rec->created() . ' UTC';
        }
        $tbody = '';
        foreach ($rows as $k => $v) {
            $tbody .= \html::tag('tr', [], \html::tag('td', ['class' => 'title'], \rcube::Q($this->plugin->text($k)))
                . \html::tag('td', ['class' => 'mimeshield-value'], \rcube::Q((string) $v)));
        }
        $status = $c->isExpired() ? 'warn_expired' : ($c->isNotYetValid() ? 'warn_notyetvalid' : '');
        $pre = $status !== '' ? \html::div('boxwarning mimeshield-warning', \rcube::Q($this->plugin->text($status))) : '';
        if ($chain->status !== ChainResult::TRUSTED) {
            $pre .= \html::div('boxwarning mimeshield-warning', \rcube::Q($this->plugin->text('chainwarn_' . $chain->status)));
        }
        return $pre . \html::tag('table', ['class' => 'propform mimeshield-certtable'], \html::tag('tbody', [], $tbody));
    }

    private function importForm(string $type): void
    {
        $isKey = $type === 'key';
        $action = $isKey ? 'plugin.mimeshield-keyimport' : 'plugin.mimeshield-certimport';
        $max = $isKey ? $this->plugin->config()->int('mimeshield_max_key_upload', 1024, 1048576) : $this->plugin->config()->int('mimeshield_max_cert_upload', 1024, 1048576);

        $file = new \html_inputfield(['type' => 'file', 'name' => '_file', 'id' => 'mimeshield-file', 'required' => true,
            'accept' => $isKey ? '.p12,.pfx,.pem,application/x-pkcs12' : '.cer,.crt,.pem,.der,.p7b,.p7c']);
        $rows = \html::tag('tr', [], \html::tag('td', ['class' => 'title'], \html::label('mimeshield-file', \rcube::Q($this->plugin->text($isKey ? 'keyfile' : 'certfile'))))
            . \html::tag('td', [], $file->show() . \html::div('hint', \rcube::Q($this->plugin->text('maxsize', ['size' => \rcmail_action::show_bytes($max)])))));
        if ($isKey) {
            $pw = new \html_passwordfield(['name' => '_password', 'id' => 'mimeshield-password', 'autocomplete' => 'off']);
            $rows .= \html::tag('tr', [], \html::tag('td', ['class' => 'title'], \html::label('mimeshield-password', \rcube::Q($this->plugin->text('p12password'))))
                . \html::tag('td', [], $pw->show() . \html::div('hint', \rcube::Q($this->plugin->text('passwordnotstored')))));
        }
        $intro = \html::p('hint', \rcube::Q($this->plugin->text($isKey ? 'importkeyintro' : 'importcertintro')));
        $form = $this->rc->output->form_tag([
            'action' => $this->rc->url(['action' => $action, '_framed' => 1]),
            'method' => 'post',
            'enctype' => 'multipart/form-data',
            'id' => 'mimeshield-importform',
        ], $intro . \html::tag('table', ['class' => 'propform'], \html::tag('tbody', [], $rows))
            . \html::p('formbuttons', \html::tag('button', ['type' => 'submit', 'class' => 'button mainaction import'], \rcube::Q($this->plugin->text('import')))));
        if ($isKey) {
            $form .= \html::p('hint mimeshield-hint', \rcube::Q($this->plugin->text('keystorednotice')));
        }
        $this->sendFrame($this->plugin->text($isKey ? 'importkey' : 'importcert'), $form);
    }

    /**
     * Read an uploaded file (POST, is_uploaded_file, size limits, extension sanity check). The file
     * name is never used as a path; the content decides the format.
     *
     * @param list<string> $extensions
     */
    private function uploadedFile(int $maxBytes, array $extensions): string
    {
        $f = $_FILES['_file'] ?? null;
        if (!is_array($f) || is_array($f['tmp_name'] ?? null)) {
            if (\rcmail_action::upload_failure()) {
                $this->rc->output->send('iframe');
            }
            throw new \MimeShield\Exception\ValidationException('importempty', 'no file uploaded');
        }
        $err = (int) ($f['error'] ?? UPLOAD_ERR_NO_FILE);
        if ($err === UPLOAD_ERR_INI_SIZE || $err === UPLOAD_ERR_FORM_SIZE) {
            throw new \MimeShield\Exception\ValidationException('importtoolarge', 'upload too large');
        }
        if ($err !== UPLOAD_ERR_OK || empty($f['tmp_name']) || !is_uploaded_file((string) $f['tmp_name'])) {
            throw new \MimeShield\Exception\ValidationException('importempty', 'upload error ' . $err);
        }
        $size = (int) @filesize((string) $f['tmp_name']);
        if ($size <= 0) {
            throw new \MimeShield\Exception\ValidationException('importempty', 'empty upload');
        }
        if ($size > $maxBytes) {
            throw new \MimeShield\Exception\ValidationException('importtoolarge', 'upload too large');
        }
        $ext = strtolower(pathinfo((string) ($f['name'] ?? ''), PATHINFO_EXTENSION));
        if ($ext !== '' && !in_array($ext, $extensions, true)) {
            throw new \MimeShield\Exception\ValidationException('importbadtype', 'unexpected file type');
        }
        $data = file_get_contents((string) $f['tmp_name'], false, null, 0, $maxBytes + 1);
        @unlink((string) $f['tmp_name']);
        if ($data === false || strlen($data) > $maxBytes) {
            throw new \MimeShield\Exception\ValidationException('importtoolarge', 'upload too large');
        }
        return $data;
    }

    private function knownLabel(string $label): string
    {
        return $this->rc->text_exists('mimeshield.' . $label) ? $label : 'internalerror';
    }

    private function keystoreWarning(): void
    {
        try {
            $this->plugin->services()->masterKeys()->activeKid();
        } catch (ConfigException $e) {
            Log::error('keystore', 'master key unavailable: ' . $e->getMessage());
            $this->rc->output->set_env('mimeshield_keystore_error', true);
            $this->rc->output->show_message('mimeshield.keystoreunavailable', 'error');
        }
    }

    private function sendFrame(string $title, string $html): void
    {
        $this->frameHtml = $html;
        $this->rc->output->set_pagetitle($title);
        $this->plugin->register_handler('plugin.mimeshieldframe', fn () => $this->frameHtml);
        $this->plugin->register_handler('plugin.mimeshieldtitle', fn () => \rcube::Q($title));
        $this->rc->output->send('mimeshield.frame');
    }

    /**
     * @param array<string, string> $vars
     */
    private function fail(string $label, array $vars = []): never
    {
        $label = $this->rc->text_exists('mimeshield.' . $label) ? $label : 'internalerror';
        $this->rc->output->show_message('mimeshield.' . $label, 'error', $vars);
        if ($this->rc->output->type === 'js') {
            $this->rc->output->send();
        }
        if (!empty($_REQUEST['_framed'])) {
            $this->sendFrame($this->plugin->text('error'), \html::div('boxerror', \rcube::Q($this->plugin->text($label, $vars))));
        }
        $this->rc->output->send('iframe');
        exit;
    }

    // ------------------------------------------------------------------ preferences

    /**
     * @param array<string, mixed> $p
     *
     * @return array<string, mixed>
     */
    public function preferencesList(array $p): array
    {
        if (($p['section'] ?? '') !== 'encryption') {
            return $p;
        }
        $cfg = $this->plugin->config();
        $noOverride = array_flip((array) $this->rc->config->get('dont_override', []));
        $opts = [];
        if ($cfg->bool('mimeshield_enable_signing') && !isset($noOverride['mimeshield_sign_default']) && !in_array('sign', $cfg->optionsLock(), true)) {
            $opts['mimeshield_sign_default'] = 'prefsigndefault';
        }
        if ($cfg->bool('mimeshield_enable_encryption') && !isset($noOverride['mimeshield_encrypt_default']) && !in_array('encrypt', $cfg->optionsLock(), true)) {
            $opts['mimeshield_encrypt_default'] = 'prefencryptdefault';
        }
        if ($opts === []) {
            return $p;
        }
        if (empty($p['current'])) {
            $p['blocks']['mimeshield']['content'] = true;
            return $p;
        }
        $p['blocks']['mimeshield']['name'] = \rcube::Q($this->plugin->text('smimeprefs'));
        foreach ($opts as $name => $label) {
            $id = 'rcmfd_' . $name;
            $cb = new \html_checkbox(['name' => '_' . $name, 'id' => $id, 'value' => 1]);
            $p['blocks']['mimeshield']['options'][$name] = [
                'title' => \html::label($id, \rcube::Q($this->plugin->text($label))),
                'content' => $cb->show((int) $this->rc->config->get($name, false)),
            ];
        }
        return $p;
    }

    /**
     * @param array<string, mixed> $p
     *
     * @return array<string, mixed>
     */
    public function preferencesSave(array $p): array
    {
        if (($p['section'] ?? '') !== 'encryption') {
            return $p;
        }
        foreach (['mimeshield_sign_default', 'mimeshield_encrypt_default'] as $name) {
            $p['prefs'][$name] = (bool) \rcube_utils::get_input_value('_' . $name, \rcube_utils::INPUT_POST);
        }
        return $p;
    }
}
