#!/usr/bin/env python3
"""
MIME Shield E2E - SMTP sink (TEST ONLY).

Accepts every message, stores the raw SMTP DATA (exact bytes after dot-unstuffing) as
<outdir>/<seq>-<rcpt>.eml plus a JSON envelope file, and delivers a copy into the local Dovecot
mailbox of each recipient via IMAP APPEND (so Roundcube can read it).

Usage: smtpsink.py --port 2525 --outdir DIR [--imap-host 127.0.0.1] [--imap-pass testpass]
"""
import argparse
import asyncio
import imaplib
import json
import os
import time

from aiosmtpd.controller import Controller


class Handler:
    def __init__(self, outdir, imap_host, imap_pass):
        self.outdir = outdir
        self.imap_host = imap_host
        self.imap_pass = imap_pass
        self.seq = 0

    async def handle_DATA(self, server, session, envelope):
        self.seq += 1
        data = envelope.original_content or envelope.content
        if isinstance(data, str):
            data = data.encode('utf-8', 'surrogateescape')
        base = os.path.join(self.outdir, '%04d-%d' % (self.seq, int(time.time() * 1000)))
        with open(base + '.eml', 'wb') as f:
            f.write(data)
        with open(base + '.json', 'w') as f:
            json.dump({'from': envelope.mail_from, 'rcpt': envelope.rcpt_tos,
                       'mail_options': envelope.mail_options, 'size': len(data)}, f)
        for rcpt in envelope.rcpt_tos:
            try:
                m = imaplib.IMAP4(self.imap_host)
                m.login(rcpt, self.imap_pass)
                m.append('INBOX', None, None, data)
                m.logout()
            except Exception as e:  # noqa: BLE001 - test helper
                with open(base + '.deliver-error', 'a') as f:
                    f.write('%s: %s\n' % (rcpt, e))
        return '250 OK queued as %d' % self.seq


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, default=2525)
    ap.add_argument('--outdir', required=True)
    ap.add_argument('--imap-host', default='127.0.0.1')
    ap.add_argument('--imap-pass', default='testpass')
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    # decode_data=False keeps the exact bytes; Roundcube does not use BDAT/8BITMIME
    c = Controller(Handler(a.outdir, a.imap_host, a.imap_pass), hostname='127.0.0.1', port=a.port, decode_data=False)
    c.start()
    try:
        asyncio.get_event_loop().run_forever()
    finally:
        c.stop()


if __name__ == '__main__':
    main()
