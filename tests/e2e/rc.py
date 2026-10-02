"""
MIME Shield E2E - minimal Roundcube HTTP client (TEST ONLY).

Drives a real Roundcube instance exactly like the browser does: login form, request tokens,
framed send requests, AJAX actions (X-Roundcube-Request header), file uploads.
"""
import html
import json
import re

import requests


class RcError(Exception):
    pass


class Roundcube:
    # every response body of every session is offered to these callbacks (e.g. secret leak checks)
    response_observers = []

    def __init__(self, base, user, password='testpass'):
        self.base = base.rstrip('/') + '/'
        self.user = user
        self.password = password
        self.s = requests.Session()
        self.s.hooks['response'].append(self._observe)
        self.token = None

    def _observe(self, r, *args, **kwargs):
        for cb in Roundcube.response_observers:
            cb(self.user, r)
        return r

    # ---------------------------------------------------------------- helpers
    def url(self, **params):
        return self.base + '?' + '&'.join('%s=%s' % (k, requests.utils.quote(str(v), safe='')) for k, v in params.items())

    @staticmethod
    def env_token(text):
        m = re.search(r'"request_token":"([^"]+)"', text)
        if m:
            return m.group(1)
        m = re.search(r'name="_token" value="([^"]+)"', text)
        return m.group(1) if m else None

    @staticmethod
    def env_all(text):
        m = re.search(r'rcmail\.set_env\((\{.*?\})\);\s*\n', text, re.S)
        if not m:
            return {}
        dec = json.JSONDecoder()
        try:
            obj, _ = dec.raw_decode(m.group(1))
            return obj
        except ValueError:
            return {}

    @classmethod
    def env(cls, text, name):
        return cls.env_all(text).get(name)

    def login(self):
        r = self.s.get(self.base + '?_task=login')
        tok = self.env_token(r.text)
        r = self.s.post(self.base + '?_task=login', data={
            '_token': tok, '_task': 'login', '_action': 'login', '_timezone': 'Europe/Warsaw',
            '_url': '', '_user': self.user, '_pass': self.password,
        }, allow_redirects=True)
        if 'rcmloginuser' in r.text and 'loginform' in r.text and '_task=logout' not in r.text:
            raise RcError('login failed for %s' % self.user)
        r = self.s.get(self.base + '?_task=mail&_mbox=INBOX')
        self.token = self.env_token(r.text)
        if not self.token:
            raise RcError('no request token after login')
        return self

    def logout(self):
        self.s.get(self.url(_task='logout', _token=self.token))
        self.token = None

    def framed_token(self, action, task='settings'):
        r = self.get(_task=task, _action=action, _framed=1)
        return self.env_token(r.text) or self.token

    def post_action(self, action, data, task='settings', token=True, header=False):
        """POST to a plugin action like the settings JS does (form post or AJAX with header)."""
        d = dict(data)
        headers = {}
        if header:
            headers = {'X-Roundcube-Request': self.token, 'X-Requested-With': 'XMLHttpRequest'}
            d.setdefault('_remote', '1')
        elif token is True:
            d['_token'] = self.token
        elif token:
            d['_token'] = token
        return self.s.post(self.url(_task=task, _action=action), data=d, headers=headers)

    def download(self, uid, part, mbox='INBOX'):
        return self.get(_task='mail', _action='get', _uid=uid, _mbox=mbox, _part=part, _download=1, _token=self.token)

    @staticmethod
    def part_links(page):
        """(part id, link text/name context) of attachment links in a show page."""
        out = []
        for m in re.finditer(r'href="([^"]*_action=get[^"]*_part=([0-9.]+)[^"]*)"', page):
            out.append(m.group(2))
        return list(dict.fromkeys(out))

    def get(self, **params):
        r = self.s.get(self.url(**params))
        return r

    def ajax(self, task, action, data=None, method='POST'):
        headers = {'X-Roundcube-Request': self.token, 'X-Requested-With': 'XMLHttpRequest'}
        u = self.url(_task=task, _action=action)
        if method == 'POST':
            d = dict(data or {})
            d.setdefault('_remote', '1')
            r = self.s.post(u, data=d, headers=headers)
        else:
            r = self.s.get(u + '&' + '&'.join('%s=%s' % (k, v) for k, v in (data or {}).items()) + '&_remote=1', headers=headers)
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, {'raw': r.text}

    @staticmethod
    def callbacks(resp, name):
        return [c[1] for c in (resp.get('callbacks') or []) if c and c[0] == name]

    @staticmethod
    def messages(text):
        """display_message("...", "type") calls in framed HTML or JSON exec."""
        out = []
        for m in re.finditer(r'display_message\("((?:[^"\\]|\\.)*)","(\w+)"', text):
            out.append((json.loads('"' + m.group(1) + '"'), m.group(2)))
        return out

    # ---------------------------------------------------------------- identities
    def identities(self):
        r = self.get(_task='mail', _action='compose')
        ids = self.env(r.text, 'identities') or {}
        return {str(k): v for k, v in ids.items()} if isinstance(ids, dict) else {}

    def add_identity(self, name, email):
        r = self.get(_task='settings', _action='add-identity', _framed=1)
        tok = self.env_token(r.text) or self.token
        r = self.s.post(self.url(_task='settings', _action='save-identity'), data={
            '_token': tok, '_task': 'settings', '_action': 'save-identity', '_framed': '1',
            '_name': name, '_email': email, '_organization': '', '_reply-to': '', '_bcc': '', '_signature': '',
        })
        return r

    # ---------------------------------------------------------------- settings
    def import_key(self, path, password, filename=None):
        r = self.get(_task='settings', _action='plugin.mimeshield-keyimport', _framed=1)
        tok = self.env_token(r.text) or self.token
        with open(path, 'rb') as f:
            files = {'_file': (filename or path.split('/')[-1], f.read(), 'application/x-pkcs12')}
        r = self.s.post(self.url(_task='settings', _action='plugin.mimeshield-keyimport', _framed=1),
                        data={'_token': tok, '_password': password}, files=files)
        return r

    def import_cert(self, path, confirm=False, filename=None):
        r = self.get(_task='settings', _action='plugin.mimeshield-certimport', _framed=1)
        tok = self.env_token(r.text) or self.token
        if confirm:
            return self.s.post(self.url(_task='settings', _action='plugin.mimeshield-certimport', _framed=1),
                               data={'_token': tok, '_confirm': '1'})
        with open(path, 'rb') as f:
            files = {'_file': (filename or path.split('/')[-1], f.read(), 'application/pkix-cert')}
        return self.s.post(self.url(_task='settings', _action='plugin.mimeshield-certimport', _framed=1),
                           data={'_token': tok}, files=files)

    def key_ids(self):
        r = self.get(_task='settings', _action='plugin.mimeshield')
        return re.findall(r'id="rcmrow(\d+)"', r.text), r.text

    def cert_ids(self):
        r = self.get(_task='settings', _action='plugin.mimeshield-contacts')
        return re.findall(r'id="rcmrow(\d+)"', r.text), r.text

    # ---------------------------------------------------------------- compose / send
    def compose(self, **params):
        p = {'_task': 'mail', '_action': 'compose'}
        p.update(params)
        r = self.s.get(self.url(**p), allow_redirects=True)
        cid = self.env(r.text, 'compose_id')
        if not cid:
            raise RcError('no compose id')
        return cid, r.text

    def upload(self, cid, name, content, mimetype='application/octet-stream'):
        u = self.url(_task='mail', _action='upload', _id=cid, _uploadid='upload%d' % (abs(hash(name)) % 100000), _from='compose')
        r = self.s.post(u, files={'_attachments[]': (name, content, mimetype)},
                        headers={'X-Roundcube-Request': self.token}, data={'_remote': '1'})
        return r

    def send(self, to='', subject='test', body='hello', cc='', bcc='', identity=None, sign=False, encrypt=False,
             html_body=False, draft=False, attachments=None, compose_params=None, extra=None):
        cid, text = self.compose(**(compose_params or {}))
        if identity is None:
            ids = self.env(text, 'identities') or {}
            identity = list(ids.keys())[0] if ids else ''
        for att in attachments or []:
            self.upload(cid, *att)
        data = {
            '_token': self.token, '_task': 'mail', '_action': 'send', '_id': cid, '_attachments': '',
            '_from': str(identity), '_to': to, '_cc': cc, '_bcc': bcc, '_replyto': '', '_followupto': '',
            '_subject': subject, '_message': body, '_is_html': '1' if html_body else '0', '_framed': '1',
            '_priority': '0', '_store_target': 'Sent', '_draft': '1' if draft else '',
            '_mimeshield_sign': '1' if sign else '', '_mimeshield_encrypt': '1' if encrypt else '',
        }
        data.update(extra or {})
        r = self.s.post(self.url(_task='mail', _action='send'), data=data)
        return r

    @staticmethod
    def sent_ok(r):
        return 'sent_successfully' in r.text

    # ---------------------------------------------------------------- reading
    def list_uids(self, mbox='INBOX'):
        code, resp = self.ajax('mail', 'list', {'_mbox': mbox, '_page': '1', '_search': ''}, method='GET')
        uids = re.findall(r'add_message_row\((\d+),', resp.get('exec', ''))
        return [int(u) for u in uids]

    def show(self, uid, mbox='INBOX', action='show'):
        return self.get(_task='mail', _action=action, _uid=uid, _mbox=mbox).text

    @staticmethod
    def status_html(page):
        m = re.search(r'(<div class="part-notice [^"]*mimeshield-status[^"]*".*?</div>)\s*(?:<div|$)', page, re.S)
        return m.group(1) if m else ''

    @staticmethod
    def status_level(page):
        m = re.search(r'mimeshield-status mimeshield-level-(\w+)', page)
        return m.group(1) if m else None

    @staticmethod
    def text_of(fragment):
        return html.unescape(re.sub(r'<[^>]+>', ' ', fragment))
