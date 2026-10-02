#!/usr/bin/env python3
"""
MIME Shield - browser (headless Chromium) tests of the JavaScript UI (TEST ONLY).

Covers what the HTTP-level E2E suite cannot: compose JS (identity status, identity switch, recipient
status with debounce/cache, compose_field_hash, missing-certificate dialog with Cancel and the
explicit "send without encryption" decision), settings JS (list/frame, export without busy lock),
message view JS (status bar, save sender certificate) and that certificate data never executes.

Usage: python3 tests/ui/test_ui.py [--rc /opt/rcrun/1.7.4] [--php php8.4] [--port 8095] [--smtp 2595]
Requires: chromium, chromium-driver, python3-selenium, the Dovecot test users (see tests/e2e).
"""
import argparse
import glob
import json
import os
import subprocess
import sys
import time
import traceback

from selenium import webdriver
from selenium.common.exceptions import NoAlertPresentException, TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait

HERE = os.path.dirname(os.path.abspath(__file__))
PLUGIN = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(PLUGIN, 'tests', 'e2e'))
from rc import Roundcube  # noqa: E402

PKI = os.path.join(PLUGIN, 'tests', 'fixtures', 'pki')
PASS = 'test-password-Zażółć'
RESULTS = []


def case(name):
    def deco(fn):
        RESULTS.append((name, fn))
        return fn
    return deco


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


class Ctx:
    pass


C = Ctx()


def sink_files():
    return set(glob.glob(os.path.join(C.run, 'smtp', '*.eml')))


def driver():
    o = webdriver.ChromeOptions()
    for a in ('--headless=new', '--no-sandbox', '--disable-dev-shm-usage', '--window-size=1500,1100', '--lang=en-US'):
        o.add_argument(a)
    o.set_capability('goog:loggingPrefs', {'browser': 'ALL'})
    for b in ('/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome'):
        if os.path.exists(b):
            o.binary_location = b
            break
    from selenium.webdriver.chrome.service import Service
    drv = '/usr/bin/chromedriver' if os.path.exists('/usr/bin/chromedriver') else None
    d = webdriver.Chrome(options=o, service=Service(executable_path=drv) if drv else None)
    d.set_page_load_timeout(30)
    return d


def wait(d, cond, timeout=10, msg='timeout'):
    try:
        return WebDriverWait(d, timeout).until(lambda x: cond(x))
    except TimeoutException:
        raise AssertionError(msg)


def js(d, script, *args):
    return d.execute_script(script, *args)


def login(d, user):
    d.delete_all_cookies()
    d.get(C.base + '?_task=logout')
    d.get(C.base + '?_task=login')
    wait(d, lambda x: x.find_elements(By.ID, 'rcmloginuser'), msg='no login form')
    d.find_element(By.ID, 'rcmloginuser').send_keys(user)
    d.find_element(By.ID, 'rcmloginpwd').send_keys('testpass')
    d.find_element(By.ID, 'rcmloginsubmit').click()
    wait(d, lambda x: js(x, 'return !!(window.rcmail && rcmail.env.task == "mail")'), msg='login failed')


def js_errors(d):
    errs = []
    for e in d.get_log('browser'):
        m = e.get('message', '')
        # Chrome notice when the test navigates away from a modified compose page (not a script error)
        if e.get('level') == 'SEVERE' and 'favicon' not in m and "'beforeunload' confirmation panel" not in m:
            errs.append(e['message'])
    return errs


def no_alert(d):
    try:
        a = d.switch_to.alert
        txt = a.text
        a.dismiss()
        return 'alert executed: ' + txt
    except NoAlertPresentException:
        return None


def open_compose(d):
    d.get(C.base + '?_task=mail&_action=compose')
    wait(d, lambda x: js(x, 'return !!(window.rcmail && rcmail.env.compose_id && document.getElementById("mimeshield-sign"))'),
         msg='compose not ready')
    time.sleep(0.5)


# ---------------------------------------------------------------- preparation (HTTP)

def prepare():
    r = subprocess.run([os.path.join(PLUGIN, 'tests', 'e2e', 'setup.sh'), C.args.rc, C.args.php, 'sqlite',
                        str(C.args.port), str(C.args.smtp)], capture_output=True)
    if r.returncode != 0:
        raise SystemExit('setup failed: ' + r.stdout.decode()[-1500:] + r.stderr.decode()[-1500:])
    for u in ('alice', 'bob', 'carol', 'mallory'):
        subprocess.run(['doveadm', 'expunge', '-u', u + '@example.test', 'mailbox', '*', 'all'], capture_output=True)
    C.run = [l.split('=', 1)[1] for l in r.stdout.decode().splitlines() if l.startswith('RUN=')][0]
    C.base = 'http://127.0.0.1:%d/' % C.args.port
    alice = Roundcube(C.base, 'alice@example.test').login()
    alice.import_key(os.path.join(PKI, 'alice.p12'), PASS)
    bundle = os.path.join(C.run, 'bob-chain.pem')
    with open(bundle, 'w') as f:
        f.write(open(os.path.join(PKI, 'bob.crt')).read() + open(os.path.join(PKI, 'int.crt')).read())
    alice.import_cert(bundle)
    alice.add_identity('Alice Second', 'alice-second@example.test')
    bob = Roundcube(C.base, 'bob@example.test').login()
    bob.import_key(os.path.join(PKI, 'bob.p12'), PASS)
    # a signed message from alice to bob for the message view tests
    r = alice.send(to='bob@example.test', subject='ui signed', body='Signed for UI test', sign=True)
    check(Roundcube.sent_ok(r), 'preparation send failed')
    # XSS certificate (generated at runtime, signed by the TEST intermediate CA)
    t = os.path.join(C.run, 'xss')
    os.makedirs(t, exist_ok=True)
    cnf = os.path.join(t, 'x.cnf')
    with open(cnf, 'w') as f:
        f.write('[x]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n'
                'extendedKeyUsage=emailProtection\nsubjectAltName=email:xss@example.test\n')
    subj = '/O=<img src=x onerror=alert(1)>/CN=<script>alert(2)<\\/script>'
    subprocess.run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', t + '/x.key', '-out', t + '/x.csr',
                    '-subj', subj], check=True, capture_output=True)
    subprocess.run(['openssl', 'x509', '-req', '-in', t + '/x.csr', '-CA', PKI + '/int.crt', '-CAkey', PKI + '/int.key',
                    '-CAcreateserial', '-out', t + '/x.crt', '-days', '30', '-extfile', cnf, '-extensions', 'x'],
                   check=True, capture_output=True)
    alice.import_cert(t + '/x.crt')


# ---------------------------------------------------------------- cases

@case('U1 compose: S/MIME options and certificate status of the identity')
def u1(d):
    login(d, 'alice@example.test')
    open_compose(d)
    status = d.find_element(By.ID, 'mimeshield-status').text
    check('alice (TEST ONLY)' in status and 'valid until' in status, 'identity status: %r' % status)
    check(d.find_element(By.ID, 'mimeshield-sign').is_enabled(), 'sign must be enabled')
    check(d.find_element(By.ID, 'mimeshield-encrypt').is_enabled(), 'encrypt must be enabled')
    errs = js_errors(d)
    check(not errs, 'JS errors: %r' % errs)


@case('U2 compose_field_hash: untouched compose is not "changed"; option change is')
def u2(d):
    open_compose(d)
    check(js(d, 'return rcmail.cmp_hash == rcmail.compose_field_hash()'), 'fresh compose reported as changed')
    js(d, '$("#mimeshield-sign").prop("checked", !$("#mimeshield-sign").prop("checked")).trigger("change")')
    check(js(d, 'return rcmail.cmp_hash != rcmail.compose_field_hash()'), 'option change not detected')


@case('U3 identity switch: identity without certificate disables signing')
def u3(d):
    open_compose(d)
    js(d, '$("#mimeshield-sign").prop("checked", true).trigger("change")')
    sel = d.find_element(By.ID, '_from')
    second = js(d, 'var id=null; $.each(rcmail.env.mimeshield_identities, function(k,v){ if (v.email=="alice-second@example.test") id=k; }); return id;')
    check(second, 'second identity missing')
    js(d, 'var s=document.getElementById("_from"); s.value=arguments[0]; s.dispatchEvent(new Event("change"));', second)
    time.sleep(0.5)
    sign = d.find_element(By.ID, 'mimeshield-sign')
    check(not sign.is_enabled() and not sign.is_selected(), 'sign must be off/disabled for an identity without certificate')
    check('no certificate' in d.find_element(By.ID, 'mimeshield-status').text.lower(), 'status should say no certificate')
    first = js(d, 'var id=null; $.each(rcmail.env.mimeshield_identities, function(k,v){ if (v.email=="alice@example.test") id=k; }); return id;')
    js(d, 'var s=document.getElementById("_from"); s.value=arguments[0]; s.dispatchEvent(new Event("change"));', first)
    time.sleep(0.5)
    check(d.find_element(By.ID, 'mimeshield-sign').is_enabled(), 'sign must be enabled again')


@case('U4 recipient status: per-address marks, debounce and cache')
def u4(d):
    open_compose(d)
    js(d, '''window.__ms_req = 0; var orig = rcmail.http_post;
             rcmail.http_post = function(a){ if (a == "plugin.mimeshield-recipients") window.__ms_req++; return orig.apply(rcmail, arguments); };''')
    js(d, '$("#mimeshield-encrypt").prop("checked", true).trigger("change")')
    for v in ('b', 'bo', 'bob@', 'bob@example.test', 'bob@example.test, carol@example.test'):
        js(d, '$("#_to").val(arguments[0]).trigger("input")', v)
        time.sleep(0.05)
    wait(d, lambda x: len(x.find_elements(By.CSS_SELECTOR, '#mimeshield-recipients li')) == 2
         and 'checking' not in x.find_element(By.ID, 'mimeshield-recipients').text, msg='recipient status not rendered')
    txt = d.find_element(By.ID, 'mimeshield-recipients').text
    check('bob@example.test' in txt and 'certificate available' in txt, 'bob status: %r' % txt)
    check('carol@example.test' in txt and 'no certificate' in txt, 'carol status: %r' % txt)
    n = js(d, 'return window.__ms_req')
    check(1 <= n <= 2, 'debounce: %d requests for 5 keystrokes' % n)
    js(d, '$("#_to").val("bob@example.test, carol@example.test").trigger("input")')
    time.sleep(1.2)
    check(js(d, 'return window.__ms_req') == n, 'cache: unchanged list must not query again')


@case('U5 missing certificate: dialog lists recipient; Cancel sends nothing')
def u5(d):
    open_compose(d)
    js(d, '$("#mimeshield-encrypt").prop("checked", true).trigger("change")')
    js(d, '$("#_to").val("carol@example.test").trigger("input")')
    js(d, '$("[name=_subject]").val("ui missing cert")')
    js(d, '$("#composebody").val("body")')
    wait(d, lambda x: 'no certificate' in x.find_element(By.ID, 'mimeshield-recipients').text, msg='status not loaded')
    before = sink_files()
    js(d, 'rcmail.command("send")')
    wait(d, lambda x: x.find_elements(By.CSS_SELECTOR, '.ui-dialog .mimeshield-dialog'), msg='dialog not shown')
    dlg = d.find_element(By.CSS_SELECTOR, '.ui-dialog')
    check('carol@example.test' in dlg.text, 'dialog must list carol: %r' % dlg.text)
    dlg.find_element(By.CSS_SELECTOR, 'button.cancel').click()
    time.sleep(1.5)
    check(sink_files() == before, 'nothing may be sent after Cancel')
    check(d.find_element(By.ID, 'mimeshield-encrypt').is_selected(), 'encryption must stay checked after Cancel')


@case('U6 explicit "send without encryption" sends plaintext only after the click')
def u6(d):
    before = sink_files()
    js(d, 'rcmail.command("send")')
    wait(d, lambda x: x.find_elements(By.CSS_SELECTOR, '.ui-dialog .mimeshield-dialog'), msg='dialog not shown')
    check(sink_files() == before, 'nothing sent before the decision')
    d.find_element(By.CSS_SELECTOR, '.ui-dialog button.send').click()
    wait(d, lambda x: len(sink_files() - before) >= 1, timeout=15, msg='message not sent after explicit decision')
    f = sorted(sink_files() - before)[0]
    data = open(f, 'rb').read()
    check(b'pkcs7-mime' not in data, 'expected an unencrypted message after the explicit decision')


@case('U7 settings: certificate list, details frame, export does not lock the UI')
def u7(d):
    d.get(C.base + '?_task=settings&_action=plugin.mimeshield')
    wait(d, lambda x: x.find_elements(By.CSS_SELECTOR, '#mimeshield-list tr'), msg='key list empty')
    js(d, 'rcmail.mimeshield_list.select(rcmail.mimeshield_list.rows[Object.keys(rcmail.mimeshield_list.rows)[0]].uid)')
    frame_text = 'var f=document.getElementById("mimeshield-frame"); var t=f && f.contentDocument && f.contentDocument.querySelector(".mimeshield-certtable"); return t ? t.innerText : "";'
    txt = wait(d, lambda x: js(x, frame_text), msg='details frame not loaded')
    check('SHA-256' in txt and 'alice@example.test' in txt, 'details: %r' % txt[:300])
    js(d, 'document.getElementById("mimeshield-frame").contentDocument.querySelector(".mimeshield-export").click()')
    time.sleep(1.5)
    check(js(d, 'return !rcmail.busy'), 'UI stays busy after export')
    check(js(d, 'return rcmail.commands["plugin.mimeshield-import"] === true'), 'import command disabled')


@case('U8 contacts with malicious certificate names: no script execution, text escaped')
def u8(d):
    d.get(C.base + '?_task=settings&_action=plugin.mimeshield-contacts')
    wait(d, lambda x: x.find_elements(By.CSS_SELECTOR, '#mimeshield-list tr'), msg='contact list empty')
    check(no_alert(d) is None, 'alert executed on list page')
    rows = d.find_elements(By.CSS_SELECTOR, '#mimeshield-list tr')
    xss = [r for r in rows if 'xss@example.test' in r.text]
    check(xss, 'xss certificate not listed')
    check('<script>alert(2)</script>' in xss[0].text, 'CN must be shown as text: %r' % xss[0].text)
    xss[0].click()
    time.sleep(1.5)
    check(no_alert(d) is None, 'alert executed in details frame')


@case('U9 message view: status bar with icon/text; save sender certificate via button')
def u9(d):
    login(d, 'bob@example.test')
    d.get(C.base + '?_task=mail&_mbox=INBOX')
    uid = wait(d, lambda x: js(x, 'var u=null; if (rcmail.message_list) { var r=rcmail.message_list.rows; for (var k in r) { u=k; } } return u;'),
               msg='message list empty')
    d.get(C.base + '?_task=mail&_action=show&_mbox=INBOX&_uid=%s' % uid)
    bar = wait(d, lambda x: x.find_elements(By.CSS_SELECTOR, '.mimeshield-status'), msg='no status bar')[0]
    check('S/MIME signature valid' in bar.text, 'status text: %r' % bar.text[:300])
    check(bar.find_elements(By.CSS_SELECTOR, '.mimeshield-mark'), 'status icon missing')
    btn = d.find_elements(By.CSS_SELECTOR, 'a.mimeshield-savecert')
    check(btn, 'save button missing')
    btn[0].click()
    wait(d, lambda x: not x.find_elements(By.CSS_SELECTOR, 'a.mimeshield-savecert'), timeout=10, msg='save did not complete')
    errs = js_errors(d)
    check(not errs, 'JS errors: %r' % errs)


@case('U10 settings import via browser form: success message visible after list reload')
def u10(d):
    login(d, 'carol@example.test')
    d.get(C.base + '?_task=settings&_action=plugin.mimeshield')
    wait(d, lambda x: js(x, 'return !!rcmail.commands["plugin.mimeshield-import"]'), msg='import command missing')
    js(d, 'rcmail.command("plugin.mimeshield-import")')
    wait(d, lambda x: js(x, 'var f=document.getElementById("mimeshield-frame"); return !!(f && f.contentDocument && f.contentDocument.getElementById("mimeshield-file"))'), msg='import form not shown')
    d.switch_to.frame('mimeshield-frame')
    d.find_element(By.ID, 'mimeshield-file').send_keys(os.path.join(PKI, 'carol.p12'))
    d.find_element(By.ID, 'mimeshield-password').send_keys(PASS)
    d.find_element(By.CSS_SELECTOR, '#mimeshield-importform button[type=submit]').click()
    d.switch_to.default_content()
    wait(d, lambda x: 'imported' in (js(x, 'return $("#messagestack").text()') or ''), timeout=15, msg='import message not visible')
    wait(d, lambda x: 'automatically assigned to the matching identity' in (js(x, 'return $("#messagestack").text()') or ''), timeout=15,
         msg='auto-binding message not visible')
    wait(d, lambda x: x.find_elements(By.CSS_SELECTOR, '#mimeshield-list tr'), msg='list not reloaded')
    check('carol' in d.find_element(By.ID, 'mimeshield-list').text, 'carol certificate not listed')


@case('U11 delete key: confirmation warns about losing access to old encrypted mail')
def u11(d):
    js(d, 'rcmail.mimeshield_list.select(rcmail.mimeshield_list.rows[Object.keys(rcmail.mimeshield_list.rows)[0]].uid)')
    js(d, 'rcmail.command("plugin.mimeshield-delete")')
    dlg = wait(d, lambda x: x.find_elements(By.CSS_SELECTOR, '.ui-dialog'), msg='no confirmation dialog')[0]
    check('can no longer be decrypted' in dlg.text, 'warning text: %r' % dlg.text)
    dlg.find_element(By.CSS_SELECTOR, 'button.cancel').click()
    time.sleep(0.5)
    check(d.find_elements(By.CSS_SELECTOR, '#mimeshield-list tr'), 'key must still exist after Cancel')


@case('U12 reply to an encrypted message: encryption pre-checked, warning when switched off')
def u12(d):
    alice = Roundcube(C.base, 'alice@example.test').login()
    r = alice.send(to='bob@example.test', subject='ui encrypted', body='Encrypted for UI reply test', encrypt=True)
    check(Roundcube.sent_ok(r), 'preparation send failed')
    login(d, 'bob@example.test')
    bob = Roundcube(C.base, 'bob@example.test').login()
    uid = max(bob.list_uids())
    d.get(C.base + '?_task=mail&_action=compose&_reply_uid=%s&_mbox=INBOX' % uid)
    wait(d, lambda x: js(x, 'return !!(window.rcmail && rcmail.env.compose_id && document.getElementById("mimeshield-encrypt"))'), msg='compose not ready')
    time.sleep(0.5)
    check(d.find_element(By.ID, 'mimeshield-encrypt').is_selected(), 'encrypt must be pre-checked for a reply to encrypted mail')
    check('Encrypted for UI reply test' in js(d, 'return $("#composebody").val()'), 'quoted decrypted text missing')
    js(d, '$("#mimeshield-encrypt").prop("checked", false).trigger("change")')
    check('reveals the quoted content' in d.find_element(By.ID, 'mimeshield-status').text, 'warning not shown')


@case('U13 bindings: Save idle without changes, unsaved-changes notice, primary Save, confirmation after reload; compose S/MIME section')
def u13(d):
    login(d, 'alice@example.test')
    d.get(C.base + '?_task=settings&_action=plugin.mimeshield')
    wait(d, lambda x: x.find_elements(By.CSS_SELECTOR, '#mimeshield-list tr'), msg='key list empty')
    js(d, 'rcmail.mimeshield_list.select(rcmail.mimeshield_list.rows[Object.keys(rcmail.mimeshield_list.rows)[0]].uid)')
    in_frame = 'var f=document.getElementById("mimeshield-frame"); var doc=f && f.contentDocument; '
    wait(d, lambda x: js(x, in_frame + 'return !!(doc && doc.querySelector(".mimeshield-bind.btn-primary"))'), msg='Save is not a primary button')
    check(js(d, in_frame + 'return !!doc.querySelector(".mimeshield-delete.btn-danger") && !doc.querySelector(".mimeshield-bind.btn-danger")'),
          'delete must be danger, save must not')
    unsaved = in_frame + 'var u=doc.querySelector(".mimeshield-unsaved"); return !!u && u.offsetParent !== null;'
    save_enabled = in_frame + 'var b=doc.querySelector(".mimeshield-bind"); return !!b && !b.disabled && b.offsetParent !== null;'
    # the key was bound by its import (setup): checked, nothing pending, Save idle
    check(js(d, in_frame + 'return f.contentWindow.$("input[name=\'_identities[]\']:checked").length') == 1, 'binding of the import not shown')
    check(not js(d, unsaved), 'unsaved notice shown before any change')
    check(not js(d, save_enabled), 'Save enabled before any change')
    toggle = in_frame + 'var w=f.contentWindow; w.$("input[name=\'_identities[]\']:enabled").first().prop("checked", arguments[0]).trigger("change");'
    js(d, toggle, False)
    check(js(d, unsaved), 'unsaved notice not shown after a change')
    check(js(d, save_enabled), 'Save not enabled after a change')
    js(d, toggle, True)
    check(not js(d, unsaved), 'unsaved notice still shown after reverting the change')
    check(not js(d, save_enabled), 'Save still enabled after reverting the change')
    # a disabled Save posts nothing (no busy lock, no reload)
    js(d, 'window.__msOld = 1')
    js(d, in_frame + 'doc.querySelector(".mimeshield-bind").click()')
    time.sleep(1)
    check(js(d, 'return window.__msOld === 1'), 'clicking the disabled Save reloaded the page')
    js(d, toggle, False)
    js(d, 'window.__msOld = 1')  # marks the page before the reload
    js(d, in_frame + 'doc.querySelector(".mimeshield-bind").click()')
    wait(d, lambda x: js(x, 'return !window.__msOld && document.readyState == "complete" && !!window.rcmail && !!rcmail.mimeshield_list'),
         timeout=15, msg='list page not reloaded after saving')
    # on the reloaded page the message can only come from the session flash
    wait(d, lambda x: 'identities saved' in (js(x, 'return $("#messagestack").text()') or ''), timeout=10,
         msg='no confirmation after the list reload')
    wait(d, lambda x: js(x, in_frame + 'return !!(doc && doc.readyState == "complete" && doc.querySelector(".mimeshield-bind") && f.contentWindow.$)'),
         msg='frame not reloaded')
    check(not js(d, unsaved), 'unsaved notice shown after saving')
    check(not js(d, save_enabled), 'Save enabled after saving (stored state is the new baseline)')
    check(js(d, in_frame + 'return f.contentWindow.$("input[name=\'_identities[]\']:checked").length') == 0, 'binding not removed')
    # the saved state is the baseline: checking again is a change
    js(d, toggle, True)
    check(js(d, unsaved) and js(d, save_enabled), 'change after saving not detected')
    js(d, toggle, False)
    check(not js(d, unsaved) and not js(d, save_enabled), 'reverting to the saved state not detected')
    # restore the binding for the other cases
    js(d, toggle, True)
    js(d, 'window.__msOld = 1')
    js(d, in_frame + 'doc.querySelector(".mimeshield-bind").click()')
    wait(d, lambda x: js(x, 'return !window.__msOld && document.readyState == "complete" && !!window.rcmail && !!rcmail.mimeshield_list'),
         timeout=15, msg='list page not reloaded after restoring')
    wait(d, lambda x: js(x, in_frame + 'return !!(doc && doc.querySelector(".mimeshield-bind") && f.contentWindow.$ && f.contentWindow.$("input[name=\'_identities[]\']:checked").length == 1)'),
         timeout=15, msg='binding not restored')
    d.set_window_size(420, 900)
    try:
        d.get(C.base + '?_task=settings&_action=plugin.mimeshield')
        wait(d, lambda x: x.find_elements(By.CSS_SELECTOR, '#mimeshield-list tr'), msg='key list empty (phone)')
        js(d, 'rcmail.mimeshield_list.select(rcmail.mimeshield_list.rows[Object.keys(rcmail.mimeshield_list.rows)[0]].uid)')
        wait(d, lambda x: js(x, in_frame + 'return !!(doc && doc.querySelector(".mimeshield-bind") && f.contentWindow.UI)'), msg='frame not loaded (phone)')
        time.sleep(0.5)
        js(d, 'window.dispatchEvent(new Event("resize"))')
        time.sleep(0.5)
        check(not js(d, 'return $(".content-frame-navigation [class*=mimeshield-]").length'), 'frame buttons cloned into the footer')
        check(js(d, in_frame + 'var b=doc.querySelector(".mimeshield-bind"); return b.offsetParent !== null'), 'Save hidden on a small screen')
    finally:
        d.set_window_size(1500, 1100)
    open_compose(d)
    legend = d.find_element(By.CSS_SELECTOR, 'fieldset#mimeshield-compose > legend')
    check(legend.is_displayed() and legend.text.strip() == 'S/MIME', 'S/MIME section heading: %r' % legend.text)
    check(d.find_elements(By.CSS_SELECTOR, '#mimeshield-compose #mimeshield-sign') and d.find_elements(By.CSS_SELECTOR, '#mimeshield-compose #mimeshield-status'),
          'S/MIME controls not grouped in the section')
    errs = js_errors(d)
    check(not errs, 'JS errors: %r' % errs)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--rc', default='/opt/rcrun/1.7.4')
    ap.add_argument('--php', default='php8.4')
    ap.add_argument('--port', type=int, default=8095)
    ap.add_argument('--smtp', type=int, default=2595)
    C.args = ap.parse_args()
    t0 = time.time()
    prepare()
    d = driver()
    ok = bad = 0
    try:
        for name, fn in RESULTS:
            t = time.time()
            try:
                fn(d)
                ok += 1
                print('PASS %s (%.1fs)' % (name, time.time() - t))
            except Exception as e:  # noqa: BLE001
                bad += 1
                print('FAIL %s: %s' % (name, e))
                if os.environ.get('UI_DEBUG'):
                    traceback.print_exc()
    finally:
        d.quit()
    print('UI: %d passed, %d failed (%.0fs)' % (ok, bad, time.time() - t0))
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
