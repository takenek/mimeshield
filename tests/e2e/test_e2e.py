#!/usr/bin/env python3
"""
MIME Shield - end-to-end suite (TEST ONLY).

Drives a real Roundcube + MIME Shield instance over HTTP (tests/e2e/rc.py), captures the final SMTP
DATA with the SMTP sink (tests/e2e/smtpsink.py) and checks every protected message with the
independent openssl CLI (cms -verify -CAfile root.crt / cms -decrypt), plus the Roundcube UI
(message status bar, settings pages, compose environment).

    python3 tests/e2e/test_e2e.py --rc /opt/rcrun/1.7.4 --php php8.4 --db sqlite --port 8081 --smtp 2526

The environment is (re)created by tests/e2e/setup.sh at the start (use --no-setup to reuse a
running one). Dovecot test users alice/bob/carol/mallory@example.test (password "testpass") are
required; their mailboxes are emptied first.

Output: one "PASS|FAIL|SKIP <case>" line per case and "E2E: N passed, M failed, K skipped".
Exit code 1 when any case failed. --only <regex> runs a subset (setup/import cases always run).
"""
import argparse
import base64
import email
import email.policy
import glob
import imaplib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import requests  # noqa: E402

from rc import Roundcube  # noqa: E402

PLUGIN = os.path.abspath(os.path.join(HERE, '..', '..'))
PKI = os.path.join(PLUGIN, 'tests', 'fixtures', 'pki')
PW = 'test-password-Zażółć'
RUNTIME_PW = 'runtime-pw-Łódź'
OPENSSL = '/usr/bin/openssl'
USERS = ['alice', 'bob', 'carol', 'mallory']
IMAP_PASS = 'testpass'

# UI texts (localization/en_US.inc)
# This test deployment keeps the default revocation mode (off): verification has a visible warning.
T_SIG_OK = 'S/MIME signature valid. Certificate trusted. Sender address matches. Certificate revocation was not checked.'
T_SIG_OK_ENC = 'Encrypted message. S/MIME signature valid, certificate trusted, sender address matches. Certificate revocation was not checked.'
T_SIG_INVALID = 'The S/MIME signature is invalid or the message has been modified.'
T_SIG_UNTRUSTED = 'Signature cryptographically valid, but the certificate chain cannot be confirmed as trusted.'
T_DECRYPTED = 'This message was encrypted with S/MIME and has been decrypted.'
T_NOT_SIGNED = 'The message is not signed: the sender cannot be verified.'


# =========================================================================== runner

class Skip(Exception):
    pass


CASES = []


def case(name, always=False):
    def deco(fn):
        CASES.append((name, fn, always))
        return fn
    return deco


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def eq(a, b, msg=''):
    if a != b:
        raise AssertionError('%s: expected %r, got %r' % (msg, b, a))


# =========================================================================== environment

class Env:
    def __init__(self, args):
        self.args = args
        self.rc_dir = os.path.realpath(args.rc)
        self.run = os.path.join(PLUGIN, 'tests', 'e2e', 'run',
                                '%s-%s-%s' % (os.path.basename(self.rc_dir), os.path.basename(args.php), args.db))
        self.base = 'http://127.0.0.1:%d/' % args.port
        self.tmp = tempfile.mkdtemp(prefix='mimeshield-e2e-')
        self.u = {}           # user -> Roundcube session
        self.state = {}       # data shared between cases
        self.leaks = []       # responses containing private key material

    @property
    def smtp_dir(self):
        return os.path.join(self.run, 'smtp')

    def cleanup(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


E = None  # type: Env


def addr(user):
    return '%s@example.test' % user


def sh(cmd, check_rc=True, **kw):
    r = subprocess.run(cmd, capture_output=True, **kw)
    if check_rc and r.returncode != 0:
        raise AssertionError('command failed (%d): %s\n%s' % (r.returncode, ' '.join(cmd), r.stderr.decode('utf-8', 'replace')))
    return r


def reset_mailboxes():
    for user in USERS:
        subprocess.run(['doveadm', 'expunge', '-u', addr(user), 'mailbox', '*', 'all'], capture_output=True)


def run_setup():
    a = E.args
    r = subprocess.run([os.path.join(HERE, 'setup.sh'), a.rc, a.php, a.db, str(a.port), str(a.smtp)] + ([a.prefix] if a.prefix else []),
                       capture_output=True, timeout=180)
    if r.returncode != 0:
        raise AssertionError('setup.sh failed: %s %s' % (r.stdout.decode()[-2000:], r.stderr.decode()[-2000:]))
    wait_http()


def wait_http(timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if requests.get(E.base + '?_task=login', timeout=3).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(0.3)
    raise AssertionError('Roundcube did not come up on %s' % E.base)


def restart_php():
    """Kill the PHP built-in server and start it again (same command line as setup.sh)."""
    a = E.args
    subprocess.run(['pkill', '-f', '127.0.0.1:%d ' % a.port], capture_output=True)
    end = time.time() + 10
    while time.time() < end:
        try:
            requests.get(E.base, timeout=1)
        except requests.RequestException:
            break
        time.sleep(0.2)
    env = dict(os.environ, ROUNDCUBE_CONFIG_DIR=E.run + '/')
    log = open(os.path.join(E.run, 'php-server.log'), 'ab')
    subprocess.Popen([a.php, '-d', 'variables_order=EGPCS', '-d', 'upload_max_filesize=8M', '-S',
                      '127.0.0.1:%d' % a.port, '-t', os.path.join(E.rc_dir, 'public_html')],
                     env=env, stdout=log, stderr=log, stdin=subprocess.DEVNULL, start_new_session=True)
    wait_http()


def session(user):
    return E.u[user]


def relogin(user):
    s = Roundcube(E.base, addr(user)).login()
    E.u[user] = s
    return s


# =========================================================================== SMTP sink

def sink_mark():
    return set(glob.glob(os.path.join(E.smtp_dir, '*.eml')))


def sink_new(mark, count=1, timeout=10, settle=0.6):
    """New captured messages since mark: list of dicts {data, rcpt, from, path} ordered by sequence."""
    end = time.time() + timeout
    files = []
    while time.time() < end:
        files = sorted(f for f in sink_mark() - mark if os.path.exists(f[:-4] + '.json'))
        if len(files) >= count:
            break
        time.sleep(0.15)
    time.sleep(settle)  # catch unexpected extra deliveries
    files = sorted(f for f in sink_mark() - mark if os.path.exists(f[:-4] + '.json'))
    out = []
    for f in files:
        with open(f, 'rb') as fh:
            data = fh.read()
        with open(f[:-4] + '.json') as fh:
            meta = json.load(fh)
        out.append({'data': data, 'rcpt': meta['rcpt'], 'from': meta['from'], 'path': f})
    return out


def sink_one(mark, rcpt=None):
    got = sink_new(mark, 1)
    eq(len(got), 1, 'number of SMTP transactions')
    if rcpt is not None:
        eq(sorted(got[0]['rcpt']), sorted(rcpt), 'envelope recipients')
    return got[0]


def sink_nothing(mark, wait=1.5):
    time.sleep(wait)
    new = sink_mark() - mark
    eq(len(new), 0, 'SMTP sink must not receive anything')


# =========================================================================== openssl helpers

def ossl(args, data=None):
    return subprocess.run([OPENSSL] + args, input=data, capture_output=True)


def tmpfile(name, data):
    p = os.path.join(E.tmp, name)
    with open(p, 'wb' if isinstance(data, bytes) else 'w') as f:
        f.write(data)
    return p


def cms_verify(data, trusted=True):
    """openssl cms -verify of a complete S/MIME message: (ok, content, signer_pem, stderr)."""
    signer = os.path.join(E.tmp, 'signer-%s.pem' % secrets.token_hex(4))
    args = ['cms', '-verify', '-inform', 'SMIME', '-signer', signer]
    args += ['-CAfile', os.path.join(PKI, 'root.crt')] if trusted else ['-noverify']
    r = ossl(args, data)
    pem = ''
    if os.path.exists(signer):
        with open(signer) as f:
            pem = f.read()
        os.unlink(signer)
    ok = r.returncode == 0 and b'Verification successful' in r.stderr
    return ok, r.stdout, pem, r.stderr.decode('utf-8', 'replace')


def cert_emails(pem):
    r = ossl(['x509', '-noout', '-ext', 'subjectAltName'], pem.encode() if isinstance(pem, str) else pem)
    return re.findall(r'email:([^,\s]+)', r.stdout.decode())


def cert_subject(pem):
    r = ossl(['x509', '-noout', '-subject', '-nameopt', 'RFC2253'], pem.encode() if isinstance(pem, str) else pem)
    return r.stdout.decode().strip()


def cert_fingerprint(pem):
    r = ossl(['x509', '-noout', '-fingerprint', '-sha256'], pem.encode() if isinstance(pem, str) else pem)
    return r.stdout.decode().strip().split('=', 1)[-1].replace(':', '').lower()


def keypair(user):
    """(cert path, key path) for a fixture user or a runtime-generated identity."""
    if user in E.state.get('runtime_keys', {}):
        return E.state['runtime_keys'][user]
    return os.path.join(PKI, user + '.crt'), os.path.join(PKI, user + '.key')


def cms_decrypt(data, user):
    crt, key = keypair(user)
    r = ossl(['cms', '-decrypt', '-inform', 'SMIME', '-recip', crt, '-inkey', key], data)
    return (r.stdout if r.returncode == 0 else None), r.stderr.decode('utf-8', 'replace')


def decryptable_by(data, user):
    return cms_decrypt(data, user)[0] is not None


def smime_sign(content, user, detached=True, md='sha256', chain=True):
    """openssl cms -sign: returns the complete S/MIME entity (with MIME headers, CRLF)."""
    crt, key = keypair(user)
    args = ['cms', '-sign', '-signer', crt, '-inkey', key, '-md', md, '-outform', 'SMIME', '-crlfeol']
    if chain:
        args += ['-certfile', os.path.join(PKI, 'int.crt') if user != 'untrusted' else os.path.join(PKI, 'rogue.crt')]
    if not detached:
        args.append('-nodetach')
    r = ossl(args, content)
    check(r.returncode == 0, 'openssl sign failed: %s' % r.stderr.decode())
    return r.stdout


def smime_encrypt(content, recipients, cipher='-aes-256-cbc', extra=None, outform='SMIME'):
    args = ['cms', '-encrypt', cipher, '-outform', outform, '-crlfeol']
    for u in recipients:
        args += ['-recip', keypair(u)[0]]
    args += list(extra or [])  # -keyopt applies to the preceding -recip
    r = ossl(args, content)
    check(r.returncode == 0, 'openssl encrypt failed: %s' % r.stderr.decode())
    return r.stdout


def recipient_serials(data):
    """Serial numbers (lowercase hex) of the KeyTransRecipientInfo entries of an enveloped message."""
    r = ossl(['cms', '-cmsout', '-print', '-inform', 'SMIME'], data)
    return [s.lower().lstrip('0') for s in re.findall(r'serialNumber:\s*(?:0x)?([0-9A-Fa-f]+)', r.stdout.decode())]


def cert_serial(user):
    r = ossl(['x509', '-noout', '-serial', '-in', keypair(user)[0]])
    return r.stdout.decode().strip().split('=', 1)[1].lower().lstrip('0')


def make_identity_cert(name, email_addr, subject_conf=None, days=3650, section='smime_rsa'):
    """Generate key + certificate signed by the TEST intermediate CA, plus a .p12 (runtime only)."""
    d = os.path.join(E.tmp, 'pki-' + name)
    os.makedirs(d, exist_ok=True)
    key, csr, crt, p12 = (os.path.join(d, name + ext) for ext in ('.key', '.csr', '.crt', '.p12'))
    cnf = os.path.join(d, 'req.cnf')
    with open(cnf, 'w', encoding='utf-8') as f:
        f.write('[req]\nprompt = no\nutf8 = yes\nstring_mask = utf8only\ndistinguished_name = dn\n[dn]\n')
        f.write(subject_conf or 'C = PL\nO = MIME Shield TEST ONLY\nCN = %s (TEST ONLY)\n' % name)
    sh([OPENSSL, 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', key])
    sh([OPENSSL, 'req', '-new', '-key', key, '-out', csr, '-config', cnf, '-utf8'])
    sh([OPENSSL, 'x509', '-req', '-in', csr, '-CA', os.path.join(PKI, 'int.crt'), '-CAkey', os.path.join(PKI, 'int.key'),
        '-set_serial', '0x' + secrets.token_hex(12), '-days', str(days), '-sha256', '-out', crt,
        '-extfile', os.path.join(PKI, 'ext.cnf'), '-extensions', section],
       env=dict(os.environ, SAN_EMAIL=email_addr))
    sh([OPENSSL, 'pkcs12', '-export', '-inkey', key, '-in', crt, '-certfile', os.path.join(PKI, 'int.crt'),
        '-passout', 'pass:' + RUNTIME_PW, '-out', p12])
    E.state.setdefault('runtime_keys', {})[name] = (crt, key)
    return {'key': key, 'crt': crt, 'p12': p12}


def bundle(user):
    """Public certificate + intermediate CA (as a correspondent would publish it)."""
    p = os.path.join(E.tmp, user + '-bundle.pem')
    with open(p, 'w') as f:
        f.write(open(keypair(user)[0]).read() + open(os.path.join(PKI, 'int.crt')).read())
    return p


# =========================================================================== MIME / IMAP helpers

def parse(data):
    return email.message_from_bytes(data, policy=email.policy.default)


def header_block(data):
    return data.split(b'\r\n\r\n', 1)[0].decode('utf-8', 'replace')


def walk_types(msg):
    return [p.get_content_type() for p in msg.walk()]


def text_parts(msg):
    out = []
    for p in msg.walk():
        if p.get_content_maintype() == 'text':
            out.append((p.get_content_type(), p.get_content()))
    return out


def imap(user):
    m = imaplib.IMAP4('127.0.0.1')
    m.login(addr(user), IMAP_PASS)
    return m


def imap_append(user, data, mbox='INBOX'):
    m = imap(user)
    try:
        typ, resp = m.append(mbox, None, None, data)
        check(typ == 'OK', 'IMAP APPEND failed: %r' % resp)
    finally:
        m.logout()


def imap_fetch_all(user, mbox, query=('all',)):
    """[(uid, raw)] of a mailbox, read with doveadm (no IMAP login; line ends normalised to CRLF)."""
    r = sh(['doveadm', '-f', 'pager', 'fetch', '-u', addr(user), 'uid text', 'mailbox', mbox] + list(query))
    out = []
    for rec in r.stdout.split(b'\n\f\n'):
        m = re.match(rb'uid: (\d+)\ntext:\n(.*)', rec, re.S)
        if m:
            out.append((int(m.group(1)), m.group(2).replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')))
    return out


def mailbox_uids(user, mbox='INBOX', query=('all',)):
    r = sh(['doveadm', 'search', '-u', addr(user), 'mailbox', mbox] + list(query))
    return [int(line.split()[1]) for line in r.stdout.decode().splitlines() if line.strip()]


def mail(headers, entity):
    """Prepend RFC 5322 headers to a MIME entity (which carries MIME-Version/Content-* headers)."""
    h = {'Date': email.utils.formatdate(localtime=True), 'Message-ID': email.utils.make_msgid(domain='example.test')}
    h.update(headers)
    head = ''.join('%s: %s\r\n' % (k, v) for k, v in h.items()).encode('utf-8')
    entity = entity.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
    return head + entity


def inner_text(body, ctype='text/plain'):
    return ('Content-Type: %s; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n%s\r\n' % (ctype, body)).encode('utf-8')


def deliver_and_show(user, data, mbox='INBOX', action='show'):
    """IMAP APPEND to the user's mailbox and open the new message in Roundcube: (uid, page)."""
    before = set(mailbox_uids(user, mbox))
    imap_append(user, data, mbox)
    uids = [u for u in mailbox_uids(user, mbox) if u not in before]
    check(len(uids) == 1, 'appended message not found (new uids %r)' % uids)
    return uids[0], session(user).show(uids[0], mbox=mbox, action=action)


def newest_uid(user, mbox='INBOX', subject=None):
    uids = mailbox_uids(user, mbox, ('header', 'subject', subject) if subject else ('all',))
    check(uids, 'no message%s in %s/%s' % (' with subject %r' % subject if subject else '', user, mbox))
    return max(uids)


def status(page):
    return Roundcube.status_level(page), Roundcube.text_of(Roundcube.status_html(page))


def ident_id(user, email_addr=None):
    ids = session(user).identities()
    for k, v in ids.items():
        if v.get('email') == (email_addr or addr(user)):
            return k
    raise AssertionError('identity %s not found for %s: %r' % (email_addr, user, ids))


def messages_of(r):
    return Roundcube.messages(r.text)


def has_message(r, fragment, kind=None):
    return any(fragment in t and (kind is None or k == kind) for t, k in messages_of(r))


def send(user, sink=True, **kw):
    """Send through Roundcube; returns (response, mark)."""
    mark = sink_mark()
    kw.setdefault('identity', ident_id(user))
    r = session(user).send(**kw)
    return r, mark


def assert_sent(r):
    check(Roundcube.sent_ok(r), 'Roundcube did not report success: %r' % (messages_of(r) or r.text[-600:]))


def key_rows(user):
    ids, html_text = session(user).key_ids()
    return ids, html_text


def compose_env(user, **params):
    cid, text = session(user).compose(**params)
    return Roundcube.env_all(text), text


PNG_1PX = base64.b64decode(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==')


# =========================================================================== cases: setup & import

@case('00 environment setup (setup.sh, empty mailboxes, login)', always=True)
def c00():
    if not E.args.no_setup:
        run_setup()
    reset_mailboxes()
    for u in USERS:
        E.u[u] = Roundcube(E.base, addr(u)).login()

    def leak_observer(user, r):
        body = r.content or b''
        if b'PRIVATE KEY' in body or b'ENCRYPTED PRIVATE' in body:
            E.leaks.append((user, r.request.method, r.url))
    Roundcube.response_observers.append(leak_observer)
    check(os.path.isdir(E.smtp_dir), 'sink directory missing')


@case('01 import alice.p12 (PKCS#12, UTF-8 password)', always=True)
def c01():
    a = session('alice')
    r = a.import_key(os.path.join(PKI, 'alice.p12'), PW)
    check(has_message(r, 'Certificate and private key imported.', 'confirmation'), 'no import confirmation: %r' % messages_of(r))
    # the import itself binds the key to the matching identity, and says so
    check(has_message(r, 'automatically assigned to the matching identity', 'confirmation'), 'no auto-binding message: %r' % messages_of(r))
    ids, page = key_rows('alice')
    eq(len(ids), 1, 'alice key rows')
    E.state['alice_key'] = ids[0]
    # details: the stored binding is shown as checked, nothing is pending (Save disabled until a change)
    info = a.get(_task='settings', _action='plugin.mimeshield-keyinfo', _id=ids[0], _framed=1).text
    iid = ident_id('alice')
    check(re.search(r'<input[^>]*id="msident%s"[^>]*checked' % iid, info) or re.search(r'<input[^>]*checked[^>]*id="msident%s"' % iid, info),
          'identity checkbox not checked after the import')
    check(re.search(r'<button[^>]*mimeshield-bind[^>]*disabled', info), 'Save must be disabled without a change')
    check('alice (TEST ONLY)' in page and 'mimeshield-badge-ok' in page, 'key list does not show alice cert as valid/signing')
    env, _ = compose_env('alice')
    ent = env.get('mimeshield_identities', {}).get(ident_id('alice'))
    check(ent and ent.get('sign') is True and 'alice' in ent.get('cert', ''), 'identity not bound for signing: %r' % ent)
    check(ent.get('encryptself') is True, 'encrypt-to-self cert not available')


@case('02 import .pfx (carol EC as .pfx), bob/mallory keys; duplicate gives "already imported"', always=True)
def c02():
    c = session('carol')
    r = c.import_key(os.path.join(PKI, 'carol.p12'), PW, filename='carol.pfx')
    check(has_message(r, 'Certificate and private key imported.', 'confirmation'), 'carol .pfx import: %r' % messages_of(r))
    check(re.search(r'>EC (prime256v1 |P-256 )?\(256 bit\)<', r.text), 'key info page should describe the EC P-256 key')
    for u in ('bob', 'mallory'):
        r = session(u).import_key(os.path.join(PKI, u + '.p12'), PW)
        check(has_message(r, 'Certificate and private key imported.', 'confirmation'), '%s import: %r' % (u, messages_of(r)))
    r = session('alice').import_key(os.path.join(PKI, 'alice.pfx'), PW)
    check(has_message(r, 'This certificate has already been imported.', 'error'), 'duplicate pfx: %r' % messages_of(r))
    eq(len(key_rows('alice')[0]), 1, 'alice key count after duplicate import')
    # correspondents' public certificates (with the intermediate, so the chain is complete)
    for owner, others in (('alice', ['bob', 'carol']), ('carol', ['alice', 'bob']), ('bob', ['carol'])):
        for o in others:
            r = session(owner).import_cert(bundle(o))
            check(has_message(r, 'Certificate imported.', 'confirmation'), '%s importing %s: %r' % (owner, o, messages_of(r)))
            check(not has_message(r, 'issuer is not trusted'), '%s cert should be trusted' % o)


@case('03 wrong PKCS#12 password')
def c03():
    c = session('carol')
    before = key_rows('carol')[0]
    r = c.import_key(os.path.join(PKI, 'alice2.p12'), 'definitely-wrong')
    check(has_message(r, 'Wrong password for the certificate file.', 'error'), 'wrong password msg: %r' % messages_of(r))
    eq(key_rows('carol')[0], before, 'no key may be stored')


@case('04 PKCS#12 without private key')
def c04():
    before = key_rows('alice')[0]
    r = session('alice').import_key(os.path.join(PKI, 'alice-nokey.p12'), PW)
    check(has_message(r, 'The file contains no private key.', 'error'), 'nokey msg: %r' % messages_of(r))
    eq(key_rows('alice')[0], before, 'no key may be stored')


@case('05 mismatched certificate / private key (mismatch.pem)')
def c05():
    before = key_rows('alice')[0]
    r = session('alice').import_key(os.path.join(PKI, 'mismatch.pem'), '')
    check(has_message(r, 'The certificate does not match the private key.', 'error'), 'mismatch msg: %r' % messages_of(r))
    eq(key_rows('alice')[0], before, 'no key may be stored')


def import_unusable(user, ident_email, fixture, warn_text, block_texts):
    s = session(user)
    s.add_identity('Test ' + fixture, ident_email)
    iid = ident_id(user, ident_email)
    r = s.import_key(os.path.join(PKI, fixture + '.p12'), PW)
    check(has_message(r, 'Certificate and private key imported.', 'confirmation'), 'import %s: %r' % (fixture, messages_of(r)))
    check(has_message(r, warn_text, 'warning'), 'missing warning %r: %r' % (warn_text, messages_of(r)))
    env, _ = compose_env(user)
    ent = env.get('mimeshield_identities', {}).get(iid, {})
    check(ent.get('sign') is False, 'identity %s must not be able to sign: %r' % (ident_email, ent))
    # explicit binding is refused as well
    ids, _ = key_rows(user)
    kid = max(ids, key=int)
    rb = s.post_action('plugin.mimeshield-bind', {'_id': kid, '_identities[]': iid}, header=True)
    check('bindingssaved' not in rb.text and 'Saved.' not in rb.text, 'binding an unusable cert must fail: %s' % rb.text[:300])
    # sending signed from that identity is blocked, nothing reaches SMTP
    r, mark = send(user, to=addr('alice'), subject='blocked ' + fixture, body='must not be sent', sign=True, identity=iid)
    check(not Roundcube.sent_ok(r), 'signed send from %s must be blocked' % ident_email)
    check(any(t in m for m, k in messages_of(r) if k == 'error' for t in block_texts), 'block reason: %r' % messages_of(r))
    sink_nothing(mark)


@case('06 expired certificate import (warning, cannot sign; signed send blocked)')
def c06():
    import_unusable('mallory', 'expired@example.test', 'expired', 'This certificate has expired.',
                    ['expired on 2021-01-01', 'No S/MIME certificate is assigned to the identity expired@example.test'])


@case('07 not-yet-valid certificate import (warning, cannot sign; signed send blocked)')
def c07():
    import_unusable('mallory', 'notyet@example.test', 'notyet', 'This certificate is not yet valid.',
                    ['not valid before 2035-01-01', 'No S/MIME certificate is assigned to the identity notyet@example.test'])


@case('08 certificate for another address (wrongmail.p12) is not bindable to alice identity')
def c08():
    a = session('alice')
    r = a.import_key(os.path.join(PKI, 'wrongmail.p12'), PW)
    check(has_message(r, 'Certificate and private key imported.', 'confirmation'), 'wrongmail import: %r' % messages_of(r))
    check(not has_message(r, 'automatically assigned'), 'wrongmail must not be bound by the import: %r' % messages_of(r))
    ids, page = key_rows('alice')
    eq(len(ids), 2, 'alice key rows')
    wid = [i for i in ids if i != E.state['alice_key']][0]
    E.state['wrongmail_key'] = wid
    info = a.get(_task='settings', _action='plugin.mimeshield-keyinfo', _id=wid, _framed=1).text
    iid = ident_id('alice')
    check(re.search(r'<input[^>]*id="msident%s"[^>]*disabled' % iid, info) or re.search(r'<input[^>]*disabled[^>]*id="msident%s"' % iid, info),
          'identity checkbox must be disabled for wrongmail cert')
    rb = a.post_action('plugin.mimeshield-bind', {'_id': wid, '_identities[]': iid}, header=True)
    check('Saved.' not in rb.text and 'assignment to identities saved' not in rb.text, 'binding wrongmail to alice must be refused: %s' % rb.text[:300])
    env, _ = compose_env('alice')
    ent = env['mimeshield_identities'][iid]
    check(ent.get('sign') and ent.get('cert', '').startswith('alice'), 'alice identity must still use alice cert: %r' % ent)


# =========================================================================== cases: signing

def sign_and_check(subject, body, html_body=False, attachments=None, expect_in_content=None):
    r, mark = send('alice', to=addr('bob'), subject=subject, body=body, sign=True, html_body=html_body, attachments=attachments)
    assert_sent(r)
    m = sink_one(mark, [addr('bob')])
    hdr = header_block(m['data'])
    check(re.search(r'Content-Type: multipart/signed;\s*protocol="application/pkcs7-signature";\s*micalg=sha-256', hdr),
          'not a clear-signed S/MIME message: %s' % hdr)
    ok, content, signer, err = cms_verify(m['data'])
    check(ok, 'openssl cms -verify failed: %s' % err)
    eq(cert_emails(signer), [addr('alice')], 'signer certificate e-mail')
    eq(cert_fingerprint(signer), cert_fingerprint(open(os.path.join(PKI, 'alice.crt')).read()), 'signer is alice.crt')
    inner = parse(content)
    for frag in expect_in_content or []:
        check(any(frag in t for _, t in text_parts(inner)), 'signed content lacks %r' % frag)
    uid = newest_uid('bob', subject=subject)
    page = session('bob').show(uid)
    lvl, txt = status(page)
    eq(lvl, 'warning', 'UI status level (%s)' % txt[:200])
    check(T_SIG_OK in txt, 'UI headline: %s' % txt[:300])
    return m, inner, uid, page


@case('09 sign text/plain')
def c09():
    m, inner, uid, page = sign_and_check('e2e 09 plain', 'Hello Bob, plain text e2e 09.', expect_in_content=['Hello Bob, plain text e2e 09.'])
    eq(inner.get_content_type(), 'text/plain', 'signed entity type')
    check('Hello Bob, plain text e2e 09.' in page, 'body not displayed')
    E.state['signed09'] = m['data']
    E.state['signed09_uid'] = uid


@case('10 sign HTML')
def c10():
    m, inner, uid, page = sign_and_check('e2e 10 html', '<p>Hello <b>HTML</b> e2e 10</p>', html_body=True)
    htmls = [t for ct, t in text_parts(inner) if ct == 'text/html']
    check(htmls and '<b>HTML</b>' in htmls[0], 'signed HTML part missing')
    check('e2e 10' in page, 'HTML body not displayed')


@case('11 sign UTF-8 Polish text')
def c11():
    pl = 'Zażółć gęślą jaźń — ĄĆĘŁŃÓŚŹŻ e2e 11'
    m, inner, uid, page = sign_and_check('Zażółć gęślą jaźń 11', pl, expect_in_content=[pl])
    check(pl in page, 'Polish body not displayed correctly')
    check('Zażółć gęślą jaźń 11' in parse(m['data']).get('Subject', ''), 'subject encoding')


@case('12 sign with attachment (rc.upload)')
def c12():
    blob = os.urandom(5000) + b'\r\n.\r\nend\n'
    m, inner, uid, page = sign_and_check('e2e 12 attach', 'see attachment 12', attachments=[('report-12.bin', blob, 'application/octet-stream')])
    atts = [p for p in inner.walk() if p.get_filename() == 'report-12.bin']
    check(atts, 'attachment missing from signed content: %r' % walk_types(inner))
    eq(atts[0].get_content(), blob, 'attachment bytes in signed content')
    parts = Roundcube.part_links(page)
    check(parts, 'no attachment link in UI')
    got = [session('bob').download(uid, p).content for p in parts]
    check(blob in got, 'downloaded attachment differs')


@case('13 sign multipart/alternative (HTML message)')
def c13():
    m, inner, uid, page = sign_and_check('e2e 13 alt', '<p>Alternative <i>13</i></p>', html_body=True)
    eq(inner.get_content_type(), 'multipart/alternative', 'signed entity type')
    eq([p.get_content_type() for p in inner.iter_parts()], ['text/plain', 'text/html'], 'alternative parts')


@case('14 sign multipart/related with inline image (data: URI converted by Roundcube)')
def c14():
    b64 = base64.b64encode(PNG_1PX).decode()
    body = '<p>Inline image 14:</p><p><img src="data:image/png;base64,%s" alt="dot"></p>' % b64
    m, inner, uid, page = sign_and_check('e2e 14 related', body, html_body=True)
    types = walk_types(inner)
    check('multipart/related' in types, 'no multipart/related: %r' % types)
    imgs = [p for p in inner.walk() if p.get_content_type() == 'image/png']
    check(imgs and imgs[0]['Content-ID'], 'inline image without Content-ID')
    eq(imgs[0].get_content(), PNG_1PX, 'inline image bytes')
    cid = imgs[0]['Content-ID'].strip('<>')
    html_part = [t for ct, t in text_parts(inner) if ct == 'text/html'][0]
    check('cid:' + cid in html_part, 'HTML does not reference the inline image by cid')


# =========================================================================== cases: verification UI

@case('15 valid detached signature warns that revocation is unchecked; sender certificate can be saved')
def c15():
    b = session('bob')
    uid = E.state['signed09_uid']
    page = b.show(uid)
    lvl, txt = status(page)
    eq(lvl, 'warning', 'status level')
    check('mimeshield-savecert' in page, 'save sender certificate link missing')
    check('smime.p7s' not in Roundcube.text_of(re.sub(r'<script.*?</script>', '', page, flags=re.S)), 'signature part must be hidden')
    rr = b.post_action('plugin.mimeshield-savecert', {'_uid': uid, '_mbox': 'INBOX'}, task='mail', header=True)
    check('Sender certificate saved.' in rr.text, 'savecert: %s' % rr.text[:400])
    ids, page2 = b.cert_ids()
    check('alice@example.test' in page2, 'alice cert not in bob contacts')


@case('16 modified message detected (tampered copy via IMAP APPEND -> red)')
def c16():
    data = E.state['signed09']
    tampered = data.replace(b'Hello Bob, plain', b'Hello Rob, plain', 1)
    check(tampered != data, 'tampering did not change the message')
    ok, _, _, _ = cms_verify(tampered)
    check(not ok, 'openssl must reject the tampered message')
    uid, page = deliver_and_show('bob', tampered)
    lvl, txt = status(page)
    eq(lvl, 'error', 'status level for modified message (%s)' % txt[:200])
    check(T_SIG_INVALID in txt, 'headline: %s' % txt[:300])
    check('mimeshield-savecert' not in page, 'must not offer saving the cert of a modified message')


@case('17 unknown CA (signed externally with untrusted.p12) -> yellow untrusted')
def c17():
    entity = smime_sign(inner_text('Signed by a rogue CA 17'), 'untrusted')
    msg = mail({'From': addr('alice'), 'To': addr('bob'), 'Subject': 'e2e 17 untrusted'}, entity)
    ok, _, _, _ = cms_verify(msg)
    check(not ok, 'openssl must not trust the rogue chain')
    ok, _, _, err = cms_verify(msg, trusted=False)
    check(ok, 'signature itself must be valid: %s' % err)
    uid, page = deliver_and_show('bob', msg)
    lvl, txt = status(page)
    eq(lvl, 'warning', 'status level (%s)' % txt[:200])
    check(T_SIG_UNTRUSTED in txt, 'headline: %s' % txt[:300])


@case('18 trusted chain (carol EC, intermediate embedded) -> full path and unchecked-revocation warning')
def c18():
    entity = smime_sign(inner_text('Trusted chain 18 from carol'), 'carol')
    msg = mail({'From': 'Carol <%s>' % addr('carol'), 'To': addr('alice'), 'Subject': 'e2e 18 chain'}, entity)
    ok, _, signer, err = cms_verify(msg)
    check(ok, 'openssl verify: %s' % err)
    uid, page = deliver_and_show('alice', msg)
    lvl, txt = status(page)
    eq(lvl, 'warning', 'status level (%s)' % txt[:200])
    check('MIME Shield Test Intermediate CA' in txt and 'MIME Shield Test Root CA' in txt, 'chain path not shown: %s' % txt[-600:])


# =========================================================================== cases: encryption

@case('19 encrypt for one recipient')
def c19():
    body = 'Top secret 19 for Bob only.'
    r, mark = send('alice', to=addr('bob'), subject='e2e 19 enc', body=body, encrypt=True)
    assert_sent(r)
    m = sink_one(mark, [addr('bob')])
    hdr = header_block(m['data'])
    check(re.search(r'Content-Type: application/pkcs7-mime;.*smime-type=enveloped-data', hdr, re.S), 'not enveloped: %s' % hdr)
    check(body.encode() not in m['data'], 'plaintext leaked into SMTP DATA')
    plain, err = cms_decrypt(m['data'], 'bob')
    check(plain is not None, 'bob cannot decrypt: %s' % err)
    check(body in parse(plain).get_content(), 'decrypted body')
    check(decryptable_by(m['data'], 'alice'), 'encrypt-to-self missing')
    check(not decryptable_by(m['data'], 'carol'), 'carol must not be a recipient')
    E.state['enc19'] = m['data']
    E.state['enc19_subject'] = 'e2e 19 enc'


@case('20 encrypt for multiple recipients (To + Cc)')
def c20():
    r, mark = send('alice', to=addr('bob'), cc=addr('carol'), subject='e2e 20 multi', body='For Bob and Carol 20', encrypt=True)
    assert_sent(r)
    m = sink_one(mark, [addr('bob'), addr('carol')])
    for u in ('bob', 'carol', 'alice'):
        check(decryptable_by(m['data'], u), '%s cannot decrypt' % u)
    check(not decryptable_by(m['data'], 'mallory'), 'mallory must not decrypt')
    sers = recipient_serials(m['data'])
    for u in ('bob', 'alice'):
        check(cert_serial(u) in sers, '%s RecipientInfo missing (%r)' % (u, sers))
    uid = newest_uid('carol', subject='e2e 20 multi')
    lvl, txt = status(session('carol').show(uid))
    check(T_DECRYPTED in txt, 'carol (EC/ECDH) UI decryption: %s' % txt[:300])


@case('21 encryption blocked when a recipient certificate is missing')
def c21():
    r, mark = send('alice', to='%s, %s' % (addr('bob'), addr('mallory')), subject='e2e 21 blocked', body='must not leave', encrypt=True)
    check(not Roundcube.sent_ok(r), 'send must be blocked')
    errs = [t for t, k in messages_of(r) if k == 'error']
    check(errs and 'mallory@example.test' in errs[0] and 'NOT sent' in errs[0], 'error message: %r' % errs)
    check('bob@example.test' not in errs[0], 'only the missing address should be listed: %r' % errs)
    check('mimeshield_send_error' in r.text and 'mallory@example.test' in r.text, 'missing-certificates command not sent to UI')
    sink_nothing(mark)


@case('22 Bcc handling (separate envelopes, Sent copy keeps Bcc)')
def c22():
    subj = 'e2e 22 bcc'
    r, mark = send('alice', to=addr('bob'), bcc=addr('carol'), subject=subj, body='Bcc test 22', encrypt=True)
    assert_sent(r)
    got = sink_new(mark, 2)
    eq(len(got), 2, 'SMTP transactions (Bcc envelope + main)')
    bccm = [g for g in got if g['rcpt'] == [addr('carol')]]
    main = [g for g in got if g['rcpt'] == [addr('bob')]]
    check(bccm and main, 'envelopes: %r' % [g['rcpt'] for g in got])
    bccm, main = bccm[0]['data'], main[0]['data']
    for d in (bccm, main):
        check(not re.search(r'^Bcc:', header_block(d), re.M | re.I), 'Bcc header in SMTP DATA')
    check(decryptable_by(bccm, 'carol'), 'carol cannot decrypt her Bcc envelope')
    check(not decryptable_by(bccm, 'bob'), 'bob must not be in the Bcc envelope')
    check(decryptable_by(main, 'bob'), 'bob cannot decrypt main envelope')
    check(not decryptable_by(main, 'carol'), 'main envelope must not contain a Bcc RecipientInfo')
    sent = [raw for _, raw in imap_fetch_all('alice', 'Sent', ('header', 'subject', subj))]
    check(sent, 'Sent copy missing')
    check(re.search(r'^Bcc:.*carol@example\.test', header_block(sent[-1]), re.M | re.I),
          'Sent copy lacks Bcc header')
    check(decryptable_by(sent[-1], 'alice'), 'alice cannot decrypt her Sent copy')
    uid = newest_uid('carol', subject=subj)
    page = session('carol').show(uid)
    check(T_DECRYPTED in status(page)[1] and 'Bcc test 22' in page, 'carol UI decrypt of Bcc copy')


@case('39 Bcc-only encrypted message (separate mode): delivered to the Bcc recipient, Sent copy stored')
def c39():
    subj = 'e2e 39 bcc only'
    r, mark = send('alice', to='', bcc=addr('carol'), subject=subj, body='Bcc only 39', encrypt=True)
    assert_sent(r)
    got = sink_new(mark, 1)
    eq([g['rcpt'] for g in got], [[addr('carol')]], 'exactly one envelope, to the Bcc recipient')
    check(decryptable_by(got[0]['data'], 'carol'), 'carol cannot decrypt')
    sent = [raw for _, raw in imap_fetch_all('alice', 'Sent', ('header', 'subject', subj))]
    check(sent and decryptable_by(sent[-1], 'alice'), 'Sent copy missing or not decryptable by the sender')


@case('40 recipient address the plugin cannot verify blocks encryption (fail closed)')
def c40():
    subj = 'e2e 40 odd address'
    r, mark = send('alice', to=addr('bob') + ', "x y"@example.test', subject=subj, body='x', encrypt=True)
    check(not Roundcube.sent_ok(r), 'message must not be sent')
    msgs = ' '.join(m for m, _ in Roundcube.messages(r.text))
    check('NOT' in msgs or 'nie' in msgs.lower(), 'error message expected: %r' % msgs)
    eq(sink_new(mark, 0, timeout=1), [], 'nothing delivered')


@case('23 decrypt message in UI')
def c23():
    uid = newest_uid('bob', subject=E.state.get('enc19_subject', 'e2e 19 enc'))
    E.state['enc19_uid'] = uid
    page = session('bob').show(uid)
    lvl, txt = status(page)
    check(T_DECRYPTED in txt, 'headline: %s' % txt[:300])
    check('AES-256-CBC' in txt, 'cipher not shown: %s' % txt[:300])
    check(T_NOT_SIGNED in txt, 'unsigned warning missing')
    eq(lvl, 'warning', 'encrypted-only level')
    check('Top secret 19 for Bob only.' in page, 'decrypted body not shown')
    check('smime.p7m' not in Roundcube.text_of(re.sub(r'<script.*?</script>', '', page, flags=re.S)), 'p7m must not be listed as attachment')


@case('24 decrypt with attachment (download and compare bytes)')
def c24():
    blob = os.urandom(20000) + b'\x00end-24'
    r, mark = send('alice', to=addr('bob'), subject='e2e 24 enc attach', body='encrypted with attachment', encrypt=True,
                   attachments=[('secret-24.bin', blob, 'application/octet-stream')])
    assert_sent(r)
    m = sink_one(mark, [addr('bob')])
    plain, err = cms_decrypt(m['data'], 'bob')
    check(plain is not None, err)
    att = [p for p in parse(plain).walk() if p.get_filename() == 'secret-24.bin']
    check(att and att[0].get_content() == blob, 'attachment in decrypted DATA')
    b = session('bob')
    uid = newest_uid('bob', subject='e2e 24 enc attach')
    page = b.show(uid)
    check('secret-24.bin' in page, 'attachment not listed in UI')
    parts = Roundcube.part_links(page)
    got = {p: b.download(uid, p) for p in parts}
    ok = [p for p, resp in got.items() if resp.content == blob]
    check(ok, 'no downloaded part matches (parts %r)' % parts)
    check('no-store' in got[ok[0]].headers.get('Cache-Control', ''), 'decrypted attachment must be sent with no-store')


@case('25 sign + encrypt (openssl decrypt then verify inner signature)')
def c25():
    r, mark = send('alice', to=addr('bob'), subject='e2e 25 signenc', body='signed and encrypted 25', sign=True, encrypt=True)
    assert_sent(r)
    m = sink_one(mark, [addr('bob')])
    plain, err = cms_decrypt(m['data'], 'bob')
    check(plain is not None, err)
    check(re.search(rb'Content-Type: multipart/signed', plain), 'inner entity not clear-signed')
    ok, content, signer, err = cms_verify(plain)
    check(ok, 'inner signature: %s' % err)
    eq(cert_emails(signer), [addr('alice')], 'inner signer')
    check('signed and encrypted 25' in parse(content).get_content(), 'inner content')


@case('26 encrypt + decrypt + verify: inner signature status in UI')
def c26():
    uid = newest_uid('bob', subject='e2e 25 signenc')
    page = session('bob').show(uid)
    lvl, txt = status(page)
    eq(lvl, 'warning', 'level (%s)' % txt[:200])
    check(T_SIG_OK_ENC in txt, 'headline: %s' % txt[:300])
    check('signed and encrypted 25' in page, 'body')


# =========================================================================== cases: identities & isolation

@case('27 identity switch: second identity signs with its own certificate')
def c27():
    a = session('alice')
    work = 'alice-work@example.test'
    a.add_identity('Alice Work', work)
    iid_work = ident_id('alice', work)
    pki = make_identity_cert('alice-work', work)
    r = a.import_key(pki['p12'], RUNTIME_PW)
    check(has_message(r, 'Certificate and private key imported.', 'confirmation'), 'import: %r' % messages_of(r))
    env, _ = compose_env('alice')
    ent = env['mimeshield_identities'][iid_work]
    check(ent.get('sign') and ent.get('cert', '').startswith('alice-work'), 'work identity not bound: %r' % ent)
    ent1 = env['mimeshield_identities'][ident_id('alice')]
    check(ent1.get('cert', '').startswith('alice (TEST'), 'main identity changed: %r' % ent1)
    for iid, expect in ((iid_work, work), (ident_id('alice'), addr('alice'))):
        r, mark = send('alice', to=addr('bob'), subject='e2e 27 from ' + expect, body='identity ' + expect, sign=True, identity=iid)
        assert_sent(r)
        m = sink_one(mark, [addr('bob')])
        ok, _, signer, err = cms_verify(m['data'])
        check(ok, err)
        eq(cert_emails(signer), [expect], 'signer e-mail')
        check(expect in parse(m['data'])['From'], 'From header')
    E.state['alice_work_iid'] = iid_work


@case('28 user isolation: bob/mallory cannot view/delete/bind/export alice keys or contacts')
def c28():
    alice_keys, _ = key_rows('alice')
    alice_certs, _ = session('alice').cert_ids()
    alice_serial = cert_serial('alice').upper()
    for attacker in ('bob', 'mallory'):
        s = session(attacker)
        own_keys = key_rows(attacker)[0]
        for kid in alice_keys:
            if kid in own_keys:
                continue  # ids are global: an id may belong to the attacker himself
            t = s.get(_task='settings', _action='plugin.mimeshield-keyinfo', _id=kid, _framed=1).text
            check('Item not found.' in t and alice_serial not in t and 'alice-work' not in t, '%s: keyinfo leak for id %s' % (attacker, kid))
            rr = s.post_action('plugin.mimeshield-keydelete', {'_id': kid}, header=True)
            check('Item not found.' in rr.text and 'deleted' not in rr.text, '%s: keydelete of foreign id %s: %s' % (attacker, kid, rr.text[:300]))
            rr = s.post_action('plugin.mimeshield-bind', {'_id': kid, '_identities[]': ident_id(attacker)}, header=True)
            check('Item not found.' in rr.text and 'Saved.' not in rr.text, '%s: bind of foreign id %s: %s' % (attacker, kid, rr.text[:300]))
            ex = s.post_action('plugin.mimeshield-export', {'_type': 'key', '_id': kid})
            check(b'BEGIN CERTIFICATE' not in ex.content, '%s: export of foreign key %s' % (attacker, kid))
        own_certs = s.cert_ids()[0]
        for cid in alice_certs:
            if cid in own_certs:
                continue
            t = s.get(_task='settings', _action='plugin.mimeshield-certinfo', _id=cid, _framed=1).text
            check('Item not found.' in t, '%s: certinfo leak for id %s' % (attacker, cid))
            rr = s.post_action('plugin.mimeshield-certdelete', {'_id': cid}, header=True)
            check('Item not found.' in rr.text, '%s: certdelete of foreign id %s' % (attacker, cid))
            rr = s.post_action('plugin.mimeshield-certprefer', {'_id': cid, '_email': addr('bob')}, header=True)
            check('Item not found.' in rr.text, '%s: certprefer of foreign id %s' % (attacker, cid))
        eq(key_rows(attacker)[0], own_keys, '%s keys unchanged' % attacker)
    eq(key_rows('alice')[0], alice_keys, 'alice keys after attack')
    eq(session('alice').cert_ids()[0], alice_certs, 'alice certs after attack')
    env, _ = compose_env('alice')
    check(env['mimeshield_identities'][ident_id('alice')].get('sign'), 'alice binding removed by attacker')
    r, mark = send('alice', to=addr('bob'), subject='e2e 28 still works', body='alice key still works', sign=True)
    assert_sent(r)
    ok, _, signer, err = cms_verify(sink_one(mark)['data'])
    check(ok and cert_emails(signer) == [addr('alice')], 'alice signing after attack: %s' % err)


@case('29 logout/login and PHP restart: decryption still works')
def c29():
    session('bob').logout()
    restart_php()
    b = relogin('bob')
    relogin('alice')
    uid = newest_uid('bob', subject='e2e 19 enc')
    page = b.show(uid)
    check(T_DECRYPTED in status(page)[1] and 'Top secret 19 for Bob only.' in page, 'decrypt after restart')
    r, mark = send('alice', to=addr('bob'), subject='e2e 29 after restart', body='after restart', sign=True, encrypt=True)
    assert_sent(r)
    plain, err = cms_decrypt(sink_one(mark)['data'], 'bob')
    check(plain is not None and cms_verify(plain)[0], 'sign+encrypt after restart: %s' % err)


# =========================================================================== cases: drafts, reply, security

@case('31 encrypted draft: encrypted to self, options header, restored on reopen')
def c31():
    a = session('alice')
    subj = 'e2e 31 draft'
    r = a.send(to=addr('bob'), subject=subj, body='Draft body 31 secret', encrypt=True, sign=True, draft=True, identity=ident_id('alice'))
    check(has_message(r, 'Message saved to Drafts.', 'confirmation'), 'draft not saved: %r' % messages_of(r))
    drafts = imap_fetch_all('alice', 'Drafts', ('header', 'subject', subj))
    check(drafts, 'draft not in Drafts')
    uid, raw = drafts[-1]
    hdr = header_block(raw)
    check(re.search(r'^X-MimeShield-Options:\s*sign=1;\s*encrypt=1', hdr, re.M), 'options header: %s' % hdr)
    check(re.search(r'application/pkcs7-mime', hdr), 'draft not encrypted: %s' % hdr)
    check(b'Draft body 31 secret' not in raw, 'draft plaintext on IMAP')
    check(decryptable_by(raw, 'alice'), 'alice cannot decrypt her draft')
    check(not decryptable_by(raw, 'bob'), 'draft must be encrypted to self only')
    plain, _ = cms_decrypt(raw, 'alice')
    check(not re.search(rb'multipart/signed', plain), 'drafts must never be signed')
    env, text = compose_env('alice', _draft_uid=uid, _mbox='Drafts')
    eq(env.get('mimeshield_restore'), {'sign': True, 'encrypt': True}, 'restored options')
    check('Draft body 31 secret' in text, 'draft body not decrypted into compose')
    check(re.search(r'<input[^>]*name="_mimeshield_encrypt"[^>]*checked', text), 'encrypt checkbox not checked')


@case('47 encrypted HTML draft with a remote image: reopened compose never loads the remote resource')
def c47():
    a = session('alice')
    subj = 'e2e 47 html draft'
    html = '<p>Draft 47</p><p><img src="http://tracker.example.test/d47.png" alt="t"></p>'
    r = a.send(to=addr('bob'), subject=subj, body=html, html_body=True, encrypt=True, draft=True, identity=ident_id('alice'))
    check(has_message(r, 'Message saved to Drafts.', 'confirmation'), 'draft not saved: %r' % messages_of(r))
    uid, raw = imap_fetch_all('alice', 'Drafts', ('header', 'subject', subj))[-1]
    check(b'tracker.example.test' not in raw, 'draft must be encrypted')
    env, text = compose_env('alice', _draft_uid=uid, _mbox='Drafts')
    check('Draft 47' in text, 'draft body not restored')
    check(not re.search(r'src=(&quot;|"|\\")http://tracker\.example\.test', text), 'remote image would be loaded in compose')


@case('32 reply to an encrypted message forces encryption')
def c32():
    uid = newest_uid('bob', subject='e2e 19 enc')
    env, text = compose_env('bob', _reply_uid=uid, _mbox='INBOX')
    eq(env.get('mimeshield_force_encrypt'), True, 'force encrypt env')
    check(re.search(r'<input[^>]*name="_mimeshield_encrypt"[^>]*checked', text), 'encrypt checkbox not pre-checked')
    check('Top secret 19 for Bob only.' in text, 'quoted decrypted text missing')
    env2, _ = compose_env('bob')
    eq(env2.get('mimeshield_force_encrypt'), False, 'new message must not force encryption')


@case('33 CSRF: mutating actions require POST + valid token')
def c33():
    a = session('alice')
    kid = E.state['wrongmail_key']
    u = a.url(_task='settings', _action='plugin.mimeshield-keydelete')
    r = a.s.post(u, data={'_id': kid, '_remote': '1'})
    eq(r.status_code, 403, 'POST without token')
    r = a.s.post(u, data={'_id': kid, '_token': 'x' * 32})
    eq(r.status_code, 403, 'POST with wrong token')
    r = a.s.post(u, data={'_id': kid}, headers={'X-Roundcube-Request': 'wrong-token'})
    eq(r.status_code, 403, 'POST with wrong header token')
    r = a.s.get(a.url(_task='settings', _action='plugin.mimeshield-keydelete', _id=kid, _token=a.token),
                headers={'X-Roundcube-Request': a.token})
    eq(r.status_code, 403, 'GET to keydelete')
    for act in ('plugin.mimeshield-bind', 'plugin.mimeshield-certdelete', 'plugin.mimeshield-certprefer'):
        r = a.s.get(a.url(_task='settings', _action=act, _id=1, _token=a.token))
        eq(r.status_code, 403, 'GET to ' + act)
    # removing the signing binding (no identity posted) needs the token as well
    ub = a.url(_task='settings', _action='plugin.mimeshield-bind')
    for data, headers, what in (({'_id': E.state['alice_key'], '_remote': '1'}, {}, 'without token'),
                                ({'_id': E.state['alice_key'], '_token': 'x' * 32}, {}, 'with wrong token'),
                                ({'_id': E.state['alice_key'], '_remote': '1'}, {'X-Roundcube-Request': 'wrong-token'}, 'with wrong header token')):
        r = a.s.post(ub, data=data, headers=headers)
        eq(r.status_code, 403, 'bind POST ' + what)
    env, _ = compose_env('alice')
    check(env['mimeshield_identities'][ident_id('alice')].get('sign'), 'alice binding removed by a request without token')
    for act, fname in (('plugin.mimeshield-keyimport', 'x.p12'), ('plugin.mimeshield-certimport', 'x.crt')):
        with open(os.path.join(PKI, 'alice2.p12' if act.endswith('keyimport') else 'carol.crt'), 'rb') as f:
            data = f.read()
        r = a.s.post(a.url(_task='settings', _action=act, _framed=1), files={'_file': (fname, data)})
        eq(r.status_code, 403, 'file-only multipart upload without token to ' + act)
    r = a.s.post(a.url(_task='mail', _action='plugin.mimeshield-savecert'), data={'_uid': '1', '_mbox': 'INBOX'})
    eq(r.status_code, 403, 'savecert without token')
    eq(len(key_rows('alice')[0]), 3, 'alice keys unchanged (alice, wrongmail, alice-work)')
    rr = a.post_action('plugin.mimeshield-keydelete', {'_id': kid}, header=True)
    check('Certificate and private key deleted.' in rr.text, 'legit delete with token: %s' % rr.text[:300])
    check(kid not in key_rows('alice')[0], 'key still listed')


XSS_CN = '<script>alert(1)</script>'
XSS_O = '"><img src=x onerror=alert(1)>'


def assert_no_raw_xss(text, where):
    for bad in ('<script>alert(1)', '<img src=x onerror', 'onerror=alert(1)>'):
        if bad in text:
            idx = text.index(bad)
            raise AssertionError('unescaped %r in %s: ...%s...' % (bad, where, text[max(0, idx - 120):idx + 60]))


@case('34 XSS: certificate CN/O with HTML are escaped (settings + status bar)')
def c34():
    conf = 'C = PL\nO = %s\nCN = %s\n' % (XSS_O.replace('"', '\\"'), XSS_CN)
    pki = make_identity_cert('xss', addr('mallory'), subject_conf=conf)
    subj = cert_subject(open(pki['crt']).read()).replace('\\', '')
    check(XSS_CN in subj and XSS_O in subj, 'generated subject: %s' % subj)
    m = session('mallory')
    r = m.import_key(pki['p12'], RUNTIME_PW)
    check(has_message(r, 'Certificate and private key imported.', 'confirmation'), 'import: %r' % messages_of(r))
    check('&lt;script&gt;alert(1)&lt;/script&gt;' in r.text, 'escaped CN not shown on info page')
    assert_no_raw_xss(r.text, 'key import/info page')
    ids, page = key_rows('mallory')
    assert_no_raw_xss(page, 'key list')
    for kid in ids:
        assert_no_raw_xss(m.get(_task='settings', _action='plugin.mimeshield-keyinfo', _id=kid, _framed=1).text, 'keyinfo')
    # contact certificate at alice + status bar of a message signed with it
    r = session('alice').import_cert(pki['crt'], filename='xss.crt')
    assert_no_raw_xss(r.text, 'cert import/info page')
    ids, page = session('alice').cert_ids()
    assert_no_raw_xss(page, 'contacts list')
    entity = smime_sign(inner_text('xss status bar 34'), 'xss')
    msg = mail({'From': addr('mallory'), 'To': addr('alice'), 'Subject': 'e2e 34 xss'}, entity)
    uid, page = deliver_and_show('alice', msg)
    lvl, txt = status(page)
    eq(lvl, 'warning', 'xss-signed message status (%s)' % txt[:200])
    check('&lt;script&gt;alert(1)&lt;/script&gt;' in Roundcube.status_html(page), 'escaped CN not in status bar details')
    assert_no_raw_xss(page, 'message view')
    assert_no_raw_xss(session('alice').show(uid, action='preview'), 'message preview')


@case('35 export returns only the public certificate')
def c35():
    a = session('alice')
    r = a.post_action('plugin.mimeshield-export', {'_type': 'key', '_id': E.state['alice_key']})
    eq(r.status_code, 200, 'export status')
    check(r.content.count(b'-----BEGIN CERTIFICATE-----') == 1 and b'PRIVATE' not in r.content, 'export content')
    eq(cert_fingerprint(r.content), cert_fingerprint(open(os.path.join(PKI, 'alice.crt')).read()), 'exported cert')
    r2 = a.post_action('plugin.mimeshield-export', {'_type': 'key', '_id': E.state['alice_key']}, token=False)
    check(b'BEGIN CERTIFICATE' not in r2.content, 'export without token must be refused')
    # INF-02: GET (token in the URL) is no longer accepted
    r3 = a.get(_task='settings', _action='plugin.mimeshield-export', _type='key', _id=E.state['alice_key'], _token=a.token)
    check(b'BEGIN CERTIFICATE' not in r3.content, 'export via GET must be refused')


@case('36 print page shows the S/MIME status')
def c36():
    b = session('bob')
    page = b.show(newest_uid('bob', subject='e2e 25 signenc'), action='print')
    lvl, txt = status(page)
    eq(lvl, 'warning', 'print status level')
    check(T_SIG_OK_ENC in txt, 'print headline: %s' % txt[:200])
    check('mimeshield-savecert' not in page, 'no save action in print view')


@case('38 re-importing a contact certificate together with its chain makes it usable')
def c38():
    c = session('carol')
    r = c.import_cert(os.path.join(PKI, 'mallory.crt'))
    check(has_message(r, 'Certificate imported.', 'confirmation') and has_message(r, 'issuer is not trusted'),
          'bare certificate import: %r' % messages_of(r))
    code, resp = c.ajax('mail', 'plugin.mimeshield-recipients', {'_addresses': addr('mallory')})
    st = Roundcube.callbacks(resp, 'plugin.mimeshield_recipients') or [{}]
    st = (st[0].get('recipients') or {}).get(addr('mallory'), {})
    eq(st.get('status'), 'invalid', 'bare (chain-incomplete) certificate is not usable')
    # the correspondent now provides the certificate WITH the intermediate CA
    r = c.import_cert(bundle('mallory'))
    code, resp = c.ajax('mail', 'plugin.mimeshield-recipients', {'_addresses': addr('mallory')})
    st = Roundcube.callbacks(resp, 'plugin.mimeshield_recipients') or [{}]
    st = (st[0].get('recipients') or {}).get(addr('mallory'), {})
    eq(st.get('status'), 'ok', 'after importing cert + intermediate the recipient must be usable '
       '(import said %r)' % messages_of(r))


# =========================================================================== cases: inbound interop

def interop_show(entity, subject, sender='bob'):
    msg = mail({'From': addr(sender), 'To': addr('alice'), 'Subject': subject}, entity)
    uid, page = deliver_and_show('alice', msg)
    return msg, uid, page


@case('I1 Outlook: opaque signed-data (application/pkcs7-mime; smime-type=signed-data; smime.p7m)')
def ci1():
    entity = smime_sign(inner_text('Outlook opaque I1'), 'bob', detached=False)
    check(b'smime-type=signed-data' in entity and b'name="smime.p7m"' in entity, 'fixture format')
    msg, uid, page = interop_show(entity, 'interop I1 opaque')
    check(cms_verify(msg)[0], 'openssl verify')
    lvl, txt = status(page)
    eq(lvl, 'warning', 'level (%s)' % txt[:200])
    check(T_SIG_OK in txt and 'Outlook opaque I1' in page, 'status/body')


@case('I2 Outlook: clear-signed with application/x-pkcs7-signature')
def ci2():
    entity = smime_sign(inner_text('Outlook x-pkcs7 I2'), 'bob')
    entity = entity.replace(b'application/pkcs7-signature', b'application/x-pkcs7-signature')
    check(entity.count(b'x-pkcs7-signature') >= 2, 'fixture format')
    msg, uid, page = interop_show(entity, 'interop I2 x-pkcs7')
    lvl, txt = status(page)
    eq(lvl, 'warning', 'level (%s)' % txt[:200])
    check('Outlook x-pkcs7 I2' in page, 'body')


@case('I3 OWA: SHA-1 signature -> warning (legacy digest)')
def ci3():
    entity = smime_sign(inner_text('SHA1 signed I3'), 'bob', md='sha1')
    check(b'micalg="sha1"' in entity or b'micalg=sha1' in entity or b'micalg=sha-1' in entity, 'fixture micalg')
    msg, uid, page = interop_show(entity, 'interop I3 sha1')
    lvl, txt = status(page)
    eq(lvl, 'warning', 'level (%s)' % txt[:200])
    check('SHA1' in txt.upper().replace('-', ''), 'weak digest line missing: %s' % txt[:400])
    check('SHA1 signed I3' in page, 'body')


@case('I4 Outlook: enveloped containing opaque signed-data')
def ci4():
    signed = smime_sign(inner_text('Enveloped opaque I4'), 'bob', detached=False)
    entity = smime_encrypt(signed, ['alice'])
    msg, uid, page = interop_show(entity, 'interop I4 env(opaque)')
    plain, err = cms_decrypt(msg, 'alice')
    check(plain is not None and cms_verify(plain)[0], 'openssl decrypt+verify: %s' % err)
    lvl, txt = status(page)
    check(T_SIG_OK_ENC in txt, 'headline (%s)' % txt[:300])
    eq(lvl, 'warning', 'level')
    check('Enveloped opaque I4' in page, 'body')


@case('I5 triple wrap: signed(enveloped(signed))')
def ci5():
    inner = smime_sign(inner_text('Triple wrapped I5'), 'bob')
    env = smime_encrypt(inner, ['alice'])
    outer = smime_sign(env, 'bob')
    msg, uid, page = interop_show(outer, 'interop I5 triple')
    ok, content, _, err = cms_verify(msg)
    check(ok, 'outer verify: %s' % err)
    plain, err = cms_decrypt(content, 'alice')
    check(plain is not None and cms_verify(plain)[0], 'openssl inner layers: %s' % err)
    lvl, txt = status(page)
    check('Triple wrapped I5' in page, 'inner body not displayed (status: %s)' % txt[:300])
    check(lvl == 'warning', 'level %s (%s)' % (lvl, txt[:300]))


@case('I6 Thunderbird: enveloped containing multipart/signed micalg=sha-256')
def ci6():
    signed = smime_sign(inner_text('Thunderbird style I6 – zażółć'), 'bob')
    check(b'micalg="sha-256"' in signed or b'micalg=sha-256' in signed, 'fixture micalg')
    entity = smime_encrypt(signed, ['alice'])
    msg, uid, page = interop_show(entity, 'interop I6 tb')
    lvl, txt = status(page)
    eq(lvl, 'warning', 'level (%s)' % txt[:200])
    check(T_SIG_OK_ENC in txt and 'Thunderbird style I6 – zażółć' in page, 'status/body')


def strip_icvlen(der):
    """Remove the optional aes-ICVlen INTEGER from GCMParameters (Exchange/Outlook omit it)."""
    def parse_tlv(b, i):
        t = b[i]
        i += 1
        ln = b[i]
        i += 1
        if ln & 0x80:
            n = ln & 0x7f
            ln = int.from_bytes(b[i:i + n], 'big')
            i += n
        return t, ln, i

    def enc_len(n):
        if n < 0x80:
            return bytes([n])
        s = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return bytes([0x80 | len(s)]) + s

    count = [0]

    def walk(b):
        out = b''
        i = 0
        while i < len(b):
            t, ln, j = parse_tlv(b, i)
            v = b[j:j + ln]
            if t & 0x20:
                v = walk(v)
                if t == 0x30 and len(v) == 17 and v[0] == 0x04 and v[1] == 12 and v[14:17] == b'\x02\x01\x10':
                    v = v[:14]
                    count[0] += 1
            out += bytes([t]) + enc_len(len(v)) + v
            i = j + ln
        return out
    res = walk(der)
    check(count[0] == 1, 'aes-ICVlen not found/stripped (%d)' % count[0])
    return res


def p7m_entity(der, smime_type):
    b64 = base64.encodebytes(der).replace(b'\n', b'\r\n')
    return (b'MIME-Version: 1.0\r\nContent-Type: application/pkcs7-mime; smime-type=' + smime_type.encode()
            + b'; name="smime.p7m"\r\nContent-Disposition: attachment; filename="smime.p7m"\r\n'
            b'Content-Transfer-Encoding: base64\r\n\r\n' + b64)


@case('I7 Exchange: AuthEnvelopedData AES-256-GCM without aes-ICVlen')
def ci7():
    der = smime_encrypt(inner_text('GCM without ICVlen I7'), ['alice'], cipher='-aes-256-gcm', outform='DER')
    der = strip_icvlen(der)
    entity = p7m_entity(der, 'authEnveloped-data')
    msg, uid, page = interop_show(entity, 'interop I7 gcm')
    lvl, txt = status(page)
    check(T_DECRYPTED in txt and 'AES-256-GCM' in txt, 'status: %s' % txt[:300])
    check('GCM without ICVlen I7' in page, 'body')
    check('authenticated' not in txt.lower() or 'unauthenticated' not in txt.lower(), 'GCM must not get the unauthenticated warning')


@case('I8 RSA-OAEP key transport')
def ci8():
    entity = smime_encrypt(inner_text('OAEP I8'), ['alice'], extra=['-keyopt', 'rsa_padding_mode:oaep'])
    check(decryptable_by(mail({'From': addr('bob')}, entity), 'alice'), 'openssl roundtrip')
    msg, uid, page = interop_show(entity, 'interop I8 oaep')
    lvl, txt = status(page)
    check(T_DECRYPTED in txt and 'OAEP I8' in page, 'status: %s' % txt[:300])


@case('I9 BER / indefinite length (openssl -stream)')
def ci9():
    der = smime_encrypt(inner_text('BER indefinite I9'), ['alice'], extra=['-stream'], outform='DER')
    check(der[1] == 0x80, 'fixture is not indefinite-length BER')
    entity = p7m_entity(der, 'enveloped-data')
    msg, uid, page = interop_show(entity, 'interop I9 ber')
    lvl, txt = status(page)
    check(T_DECRYPTED in txt and 'BER indefinite I9' in page, 'status: %s' % txt[:300])
    # opaque signed + -stream: indefinite length signed-data
    crt, key = keypair('bob')
    r = ossl(['cms', '-sign', '-nodetach', '-stream', '-signer', crt, '-inkey', key, '-certfile', os.path.join(PKI, 'int.crt'),
              '-outform', 'DER'], inner_text('BER signed I9b'))
    check(r.returncode == 0 and r.stdout[1] == 0x80, 'signed BER fixture')
    msg, uid, page = interop_show(p7m_entity(r.stdout, 'signed-data'), 'interop I9b ber signed')
    lvl, txt = status(page)
    eq(lvl, 'warning', 'BER signed-data level (%s)' % txt[:200])
    check('BER signed I9b' in page, 'body')


# =========================================================================== final aggregate checks

@case('42 reply to an encrypted message, signed + encrypted (quoted text inside, verified by openssl)')
def c42():
    uid = E.state.get('enc19_uid') or newest_uid('bob', subject='e2e 19 enc')
    r, mark = send('bob', to=addr('alice'), subject='Re: e2e 19 enc', body='Reply 42\n> Top secret 19 for Bob only.',
                   sign=True, encrypt=True, compose_params={'_reply_uid': uid, '_mbox': 'INBOX'})
    assert_sent(r)
    m = sink_one(mark, [addr('alice')])
    plain, err = cms_decrypt(m['data'], 'alice')
    check(plain is not None, 'alice cannot decrypt: %s' % err)
    ok, content, pem, err = cms_verify(plain)
    check(ok, 'inner signature: %s' % err)
    check(b'Top secret 19' in content.replace(b'=\r\n', b''), 'quoted text missing')
    check(re.search(r'^In-Reply-To:', header_block(m['data']), re.M), 'In-Reply-To header missing')


@case('43 forward of an encrypted message: inline (signed) and as attachment (original stays encrypted)')
def c43():
    uid = E.state.get('enc19_uid') or newest_uid('bob', subject='e2e 19 enc')
    r, mark = send('bob', to=addr('carol'), subject='Fwd: e2e 19 enc', body='Forward 43\n-------- Original Message --------\nTop secret 19 for Bob only.',
                   sign=True, compose_params={'_forward_uid': uid, '_mbox': 'INBOX'})
    assert_sent(r)
    m = sink_one(mark, [addr('carol')])
    ok, content, pem, err = cms_verify(m['data'])
    check(ok, 'forward signature: %s' % err)
    r, mark = send('bob', to=addr('carol'), subject='Fwd att: e2e 19 enc', body='Forward as attachment 43',
                   sign=True, compose_params={'_forward_uid': uid, '_mbox': 'INBOX', '_attachment': 1})
    assert_sent(r)
    m = sink_one(mark, [addr('carol')])
    ok, content, pem, err = cms_verify(m['data'])
    check(ok, 'forward-as-attachment signature: %s' % err)
    check(b'message/rfc822' in content and b'pkcs7-mime' in content, 'original encrypted message must be attached unchanged')
    check(b'Top secret 19' not in content, 'attached original must stay encrypted')


@case('44 contact certificate replaced: fingerprint-change confirmation, preferred certificate selection')
def c44():
    # a second certificate for bob (TEST int CA, shorter validity) imported by alice
    d = os.path.join(E.tmp, 'bobnew')
    os.makedirs(d, exist_ok=True)
    with open(d + '/x.cnf', 'w') as f:
        f.write('[x]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=emailProtection\n'
                'subjectAltName=email:bob@example.test\n')
    ossl(['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', d + '/b.key', '-out', d + '/b.csr', '-subj', '/CN=bob new (TEST ONLY)'])
    r = ossl(['x509', '-req', '-in', d + '/b.csr', '-CA', PKI + '/int.crt', '-CAkey', PKI + '/int.key', '-CAcreateserial',
              '-out', d + '/b.crt', '-days', '100', '-extfile', d + '/x.cnf', '-extensions', 'x'])
    check(r.returncode == 0, 'cert generation: %s' % r.stderr.decode())
    with open(d + '/bundle.pem', 'w') as f:
        f.write(open(d + '/b.crt').read() + open(PKI + '/int.crt').read())
    a = session('alice')
    r = a.import_cert(d + '/bundle.pem')
    check('fingerprint changed' in r.text or 'different certificate' in r.text, 'confirmation expected: %s' % Roundcube.text_of(r.text)[:300])
    ids_before, _ = a.cert_ids()
    r = a.import_cert(None, confirm=True)
    check(any('imported' in t for t, _ in messages_of(r)) or 'Certificate details' in r.text or 'certimported' in r.text, 'confirm import failed')
    ids_after, page = a.cert_ids()
    check(len(ids_after) == len(ids_before) + 1, 'both certificates must be stored')
    code, resp = a.ajax('mail', 'plugin.mimeshield-recipients', {'_addresses[]': [addr('bob')]})
    st = Roundcube.callbacks(resp, 'plugin.mimeshield_recipients')[0]['recipients'][addr('bob')]
    check(st['status'] == 'ok', 'new cert usable: %r' % st)
    new_until = st['until']
    # prefer the original certificate again
    old_id = [i for i in ids_after if i not in set(ids_after) - set(ids_before)]
    new_id = [i for i in ids_after if i not in ids_before][0]
    ok_old = None
    for cid in ids_before:
        rr = a.post_action('plugin.mimeshield-certprefer', {'_id': cid, '_email': addr('bob')}, task='settings', header=True)
        code, resp = a.ajax('mail', 'plugin.mimeshield-recipients', {'_addresses[]': [addr('bob')]})
        st2 = Roundcube.callbacks(resp, 'plugin.mimeshield_recipients')[0]['recipients'][addr('bob')]
        if st2.get('until') and st2['until'] != new_until:
            ok_old = cid
            break
    check(ok_old, 'preferring the old certificate did not change the selection')
    # remove the runtime certificate again (keeps later cases decryptable with the fixture key)
    a.post_action('plugin.mimeshield-certdelete', {'_id': new_id}, task='settings', header=True)
    ids_final, _ = a.cert_ids()
    check(new_id not in ids_final, 'certificate delete failed')


@case('45 sender certificate from an untrusted chain is saved as "observed" and not used for encryption')
def c45():
    b = session('bob')
    uid = newest_uid('bob', subject='e2e 17 untrusted')
    rr = b.post_action('plugin.mimeshield-savecert', {'_uid': uid, '_mbox': 'INBOX'}, task='mail', header=True)
    if 'mimeshield_savecert_confirm' in rr.text:
        rr = b.post_action('plugin.mimeshield-savecert', {'_uid': uid, '_mbox': 'INBOX', '_confirm': 1}, task='mail', header=True)
    check('Sender certificate saved.' in rr.text, 'savecert: %s' % rr.text[:300])
    ids, page = b.cert_ids()
    check('observed (not verified)' in page, 'observed badge missing')


@case('46 decrypted HTML: scripts removed, remote content blocked (show, preview, _safe=1, get)')
def c46():
    html = ('<html><body><p>EFAIL 46</p><img src="http://tracker.example.test/x.png">'
            '<script>alert(1)</script><img src="x" onerror="alert(2)"></body></html>')
    entity = ('Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n%s\r\n' % html).encode()
    msg = mail({'From': addr('alice'), 'To': addr('bob'), 'Subject': 'e2e 46 efail'}, smime_encrypt(entity, ['bob']))
    uid, page = deliver_and_show('bob', msg)
    b = session('bob')
    for name, pg in (('show', page), ('preview', b.show(uid, action='preview')),
                     ('safe', b.get(_task='mail', _action='show', _uid=uid, _mbox='INBOX', _safe=1).text)):
        check('EFAIL 46' in pg, '%s: decrypted body missing' % name)
        check(not re.search(r'src="http://tracker\.example\.test', pg), '%s: remote image not blocked' % name)
        check('<script>alert(1)' not in pg and 'onerror="alert(2)"' not in pg, '%s: active content not removed' % name)
    links = re.findall(r'_part=([0-9.]+)', page)
    for part in set(links):
        g = b.get(_task='mail', _action='get', _uid=uid, _mbox='INBOX', _part=part, _safe=1).text
        check(not re.search(r'src="http://tracker\.example\.test', g) and '<script>alert(1)' not in g, 'get part %s not sanitised' % part)


@case('41 CLI: diag, keygen (no overwrite, missing parent dir), master key rotation, check-keystore; mail still decrypts')
def c41():
    tool = os.path.join(E.rc_dir, 'plugins', 'mimeshield', 'bin', 'mimeshield.sh')
    env = dict(os.environ, ROUNDCUBE_CONFIG_DIR=E.run + '/')
    def cli(*a):
        return subprocess.run([E.args.php, tool] + list(a), cwd=E.rc_dir, env=env, capture_output=True, text=True)
    r = cli('diag')
    eq(r.returncode, 0, 'diag exit code: ' + r.stdout[-800:])
    check('Result: OK' in r.stdout, 'diag result')
    check(not re.search(r'[A-Za-z0-9+/]{43}=', r.stdout), 'diag must not print key material')
    # a stored key alone does not say whether an identity signs with it: bindings are counted separately
    m = re.search(r'stored identity bindings\s+(\d+)', r.stdout)
    check(m and int(m.group(1)) >= 1, 'diag does not show the identity bindings: ' + r.stdout[-800:])
    keyfile = os.path.join(E.run, 'keys', 'master.key')
    r = cli('keygen', '--file=' + keyfile)
    check(r.returncode != 0 and 'Refusing to overwrite' in r.stdout, 'keygen must not overwrite')
    # missing parent directory: precise message, nothing created; explicit --create-parent creates it (0700)
    newdir = os.path.join(E.run, 'keys', 'new', 'sub')
    r = cli('keygen', '--file=' + os.path.join(newdir, 'master.key'))
    check(r.returncode != 0 and 'does not exist' in r.stdout and 'install -d' in r.stdout, 'missing parent: ' + r.stdout)
    check(not os.path.exists(os.path.join(E.run, 'keys', 'new')), 'keygen created a directory without --create-parent')
    r = cli('keygen', '--file=' + os.path.join(newdir, 'master.key'), '--create-parent')
    eq(r.returncode, 0, 'keygen --create-parent: ' + r.stdout)
    eq(os.stat(newdir).st_mode & 0o7777, 0o700, 'created parent mode')
    eq(os.stat(os.path.join(newdir, 'master.key')).st_mode & 0o777, 0o400, 'key file mode')
    r = cli('keygen', '--file=' + keyfile, '--append', '--kid=k9')
    eq(r.returncode, 0, 'keygen --append: ' + r.stdout)
    with open(os.path.join(E.run, 'config.inc.php'), 'a') as fh:
        fh.write("\n$config['mimeshield_master_key_active'] = 'k9';\n")
    r = cli('rotate')
    eq(r.returncode, 0, 'rotate: ' + r.stdout)
    check(re.search(r'Done: \d+ re-encrypted', r.stdout), 'rotate output')
    r = cli('rotate')
    check(' 0 re-encrypted' in r.stdout, 'second rotate is a no-op: ' + r.stdout)
    os.chmod(keyfile, 0o600)
    with open(keyfile) as fh:
        lines = [l for l in fh if not l.startswith('k1 ')]
    with open(keyfile, 'w') as fh:
        fh.writelines(lines)
    os.chmod(keyfile, 0o400)
    r = cli('check-keystore')
    eq(r.returncode, 0, 'check-keystore after removing the old key: ' + r.stdout)
    uid = E.state.get('enc19_uid') or newest_uid('bob', subject=E.state.get('enc19_subject', 'e2e 19 enc'))
    page = session('bob').show(uid)
    check(T_DECRYPTED in status(page)[1], 'decryption after rotation')


@case('48 plugin schema outdated + encryption locked by the administrator: send and draft refused (fail closed)')
def c48():
    # audit MS-01: without the plugin tables S/MIME cannot be applied; a send or draft that must be
    # protected is refused instead of being delivered / stored in plaintext
    env = dict(os.environ, ROUNDCUBE_CONFIG_DIR=E.run + '/')
    def sql_version(value=None):
        code = ('define("INSTALL_PATH", %r); require INSTALL_PATH . "program/include/clisetup.php";'
                '$db = rcmail::get_instance()->get_dbh(); $t = $db->table_name("system", true);'
                '$v = $argv[1] ?? ""; if ($v !== "") { $db->query("UPDATE $t SET value = ? WHERE name = ?", $v, "mimeshield-version"); }'
                '$r = $db->fetch_assoc($db->query("SELECT value FROM $t WHERE name = ?", "mimeshield-version")); echo $r["value"] ?? "";'
                ) % (E.rc_dir + '/')
        r = subprocess.run([E.args.php, '-r', code, '--'] + ([value] if value else []), cwd=E.rc_dir, env=env, capture_output=True, text=True)
        eq(r.returncode, 0, 'schema version query: ' + r.stdout + r.stderr)
        return r.stdout.strip()
    cfg = os.path.join(E.run, 'config.inc.php')
    with open(cfg) as fh:
        orig_cfg = fh.read()
    orig_version = sql_version()
    check(orig_version != '', 'schema version not installed')
    subj = 'e2e 48 must not leave'
    try:
        sql_version('2000010100')
        with open(cfg, 'a') as fh:
            fh.write("\n$config['mimeshield_encrypt_default'] = true;\n$config['mimeshield_options_lock'] = ['encrypt'];\n")
        restart_php()          # the built-in server caches compiled files (opcache revalidate_freq)
        a = relogin('alice')   # new session: the cached positive schema check is gone
        r, mark = send('alice', to=addr('bob'), subject=subj, body='Plaintext 48 must not leave')
        check(not Roundcube.sent_ok(r), 'send must be refused: %r' % messages_of(r))
        check(has_message(r, 'S/MIME protection is required', 'error'), 'missing error message: %r' % messages_of(r))
        sink_nothing(mark)
        r = a.send(to=addr('bob'), subject=subj, body='Plaintext 48 draft', draft=True, identity=ident_id('alice'))
        check(not has_message(r, 'Message saved to Drafts.'), 'draft must not be saved: %r' % messages_of(r))
        check(not imap_fetch_all('alice', 'Drafts', ('header', 'subject', subj)), 'plaintext draft stored on IMAP')
        check(not imap_fetch_all('alice', 'Sent', ('header', 'subject', subj)), 'plaintext Sent copy stored on IMAP')
        # without any expected protection a plain message is still sent (no availability regression);
        # the plaintext capture is removed again (case 30 requires S/MIME for every suite send)
        with open(cfg, 'w') as fh:
            fh.write(orig_cfg)
        restart_php()
        relogin('alice')
        r, mark = send('alice', to=addr('bob'), subject='e2e 48 plain ok', body='plain 48')
        assert_sent(r)
        got = sink_one(mark)
        os.remove(got['path'])
        os.remove(got['path'][:-4] + '.json')
    finally:
        with open(cfg, 'w') as fh:
            fh.write(orig_cfg)
        sql_version(orig_version)
        restart_php()
        relogin('alice')


@case('37 private key material never appears in any HTTP response', always=True)
def c37():
    check(not E.leaks, 'private key in responses: %r' % E.leaks[:5])


@case('30 every captured SMTP DATA verifies/decrypts with the independent openssl CLI', always=True)
def c30():
    files = sorted(glob.glob(os.path.join(E.smtp_dir, '*.eml')))
    if not files and E.args.only:
        raise Skip('no messages captured in this --only run')
    check(files, 'no messages captured')
    signed = enc = 0
    problems = []
    for f in files:
        data = open(f, 'rb').read()
        meta = json.load(open(f[:-4] + '.json'))
        hdr = header_block(data)
        if re.search(r'Content-Type:\s*multipart/signed', hdr, re.I):
            signed += 1
            ok, _, signer, err = cms_verify(data)
            if not ok or not cert_emails(signer):
                problems.append('%s: verify failed %s' % (os.path.basename(f), err[:200]))
            elif meta['from'] not in cert_emails(signer):
                problems.append('%s: signer %r != envelope sender %s' % (os.path.basename(f), cert_emails(signer), meta['from']))
        elif re.search(r'Content-Type:\s*application/(x-)?pkcs7-mime', hdr, re.I):
            enc += 1
            for rcpt in meta['rcpt']:
                user = rcpt.split('@')[0]
                plain, err = cms_decrypt(data, user)
                if plain is None:
                    problems.append('%s: %s cannot decrypt (%s)' % (os.path.basename(f), rcpt, err[:200]))
                    continue
                if re.search(rb'^Content-Type:\s*multipart/signed', plain, re.M | re.I):
                    if not cms_verify(plain)[0]:
                        problems.append('%s: inner signature invalid' % os.path.basename(f))
        else:
            problems.append('%s: unprotected message captured (all suite sends use S/MIME)' % os.path.basename(f))
    check(not problems, '\n'.join(problems))
    check(E.args.only or (signed >= 8 and enc >= 6), 'too few protected messages (%d signed, %d encrypted)' % (signed, enc))
    print('     (%d messages: %d clear-signed, %d enveloped - all verified by openssl)' % (len(files), signed, enc))


# =========================================================================== main

def main():
    global E
    ap = argparse.ArgumentParser()
    ap.add_argument('--rc', default='/opt/rcrun/1.7.4')
    ap.add_argument('--php', default='php8.4')
    ap.add_argument('--db', default='sqlite')
    ap.add_argument('--port', type=int, default=8081)
    ap.add_argument('--smtp', type=int, default=2526)
    ap.add_argument('--prefix', default='', help='db_prefix (mysql/pgsql only)')
    ap.add_argument('--no-setup', action='store_true')
    ap.add_argument('--only', default='')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()
    E = Env(args)
    passed = failed = skipped = 0
    t0 = time.time()
    setup_failed = False
    try:
        for name, fn, always in CASES:
            if args.only and not always and not re.search(args.only, name):
                continue
            if setup_failed:
                print('SKIP %s (setup failed)' % name)
                skipped += 1
                continue
            t = time.time()
            try:
                fn()
                print('PASS %s (%.1fs)' % (name, time.time() - t))
                passed += 1
            except Skip as e:
                print('SKIP %s: %s' % (name, e))
                skipped += 1
            except Exception as e:  # noqa: BLE001 - report every failure and continue
                failed += 1
                print('FAIL %s: %s' % (name, str(e).strip().replace('\n', '\n     ')))
                if args.verbose or not isinstance(e, AssertionError):
                    traceback.print_exc()
                if name.startswith('00'):
                    setup_failed = True
            sys.stdout.flush()
    finally:
        E.cleanup()
    print('E2E: %d passed, %d failed, %d skipped (%.0fs)' % (passed, failed, skipped, time.time() - t0))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
