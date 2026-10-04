/**
 * MIME Shield - S/MIME for Roundcube
 *
 * @licstart  The following is the entire license notice for the
 * JavaScript code in this file.
 *
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Original author: Marek Królikowski (TaKeN)
 * Original project: https://github.com/takenek/mimeshield
 * SPDX-License-Identifier: GPL-3.0-or-later
 * See LICENSE and COPYRIGHT for the license and GPL section 7 attribution terms.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * @licend  The above is the entire license notice
 * for the JavaScript code in this file.
 *
 * Security notes: no eval, no innerHTML with data (all dynamic text goes through jQuery.text()
 * or DOM text nodes), no secrets are ever sent to or kept in the browser.
 */

(function () {
    'use strict';

    if (!window.rcmail) {
        return;
    }

    var label = function (name, vars) {
        return rcmail.get_label(name, 'mimeshield', vars || null);
    };

    // ------------------------------------------------------------------ settings

    function settingsInit() {
        var table = rcmail.gui_objects.mimeshieldlist;
        var page = rcmail.env.mimeshield_page;

        if (table) {
            var list = new rcube_list_widget(table, { multiselect: false, draggable: false, keyboard: true });
            rcmail.mimeshield_list = list;
            list.addEventListener('select', function (o) {
                var id = o.get_single_selection();
                rcmail.enable_command('plugin.mimeshield-delete', !!id);
                if (id) {
                    loadFrame(page === 'keys' ? 'plugin.mimeshield-keyinfo' : 'plugin.mimeshield-certinfo', { _id: id });
                }
            });
            list.init();
            if (rcmail.env.mimeshield_select) {
                list.select(String(rcmail.env.mimeshield_select));
            }
            list.focus();

            rcmail.register_command('plugin.mimeshield-import', function () {
                list.clear_selection();
                loadFrame(page === 'keys' ? 'plugin.mimeshield-keyimport' : 'plugin.mimeshield-certimport', {});
            }, true);
            rcmail.register_command('plugin.mimeshield-delete', function () {
                var id = list.get_single_selection();
                if (id) {
                    confirmDelete(page === 'keys' ? 'key' : 'cert', id);
                }
            }, false);
        }

        // buttons inside the details frame
        $(document).on('click', 'button.mimeshield-delete', function (e) {
            e.preventDefault();
            confirmDelete($(this).data('type'), $(this).data('id'));
        });
        $(document).on('click', 'button.mimeshield-export', function (e) {
            e.preventDefault();
            // POST form: the request token stays out of URLs (server logs, browser history); a download
            // does not fire 'load', so no busy lock is set
            var form = $('<form method="post" style="display:none">').attr('action', rcmail.url('plugin.mimeshield-export'));
            $.each({ _type: String($(this).data('type')), _id: String($(this).data('id')), _token: rcmail.env.request_token }, function (k, v) {
                form.append($('<input type="hidden">').attr('name', k).val(v));
            });
            form.appendTo(document.body);
            form.get(0).submit();
            form.remove();
        });
        $(document).on('click', 'button.mimeshield-bind', function (e) {
            e.preventDefault();
            if (this.disabled) {
                return;
            }
            rcmail.http_post('plugin.mimeshield-bind', { _id: String($(this).data('id')), _identities: boundIdentities() },
                rcmail.set_busy(true, 'mimeshield.saving'));
        });

        // identity bindings: show the "not saved yet" notice and enable Save only while the selection
        // differs from the stored one (after saving, the list and this frame are reloaded with the stored
        // state, which becomes the new baseline)
        var bindings = $('fieldset.mimeshield-bindings');
        if (bindings.length) {
            var saved = boundIdentities().join(',');
            var markDirty = function () {
                var dirty = boundIdentities().join(',') !== saved;
                bindings.toggleClass('mimeshield-dirty', dirty);
                bindings.find('button.mimeshield-bind').prop('disabled', !dirty);
            };
            bindings.on('change', 'input[name="_identities[]"]', markDirty);
            markDirty();
        }
        $(document).on('click', 'a.mimeshield-prefer', function (e) {
            e.preventDefault();
            rcmail.http_post('plugin.mimeshield-certprefer', { _id: String($(this).data('id')), _email: String($(this).data('email')) },
                rcmail.set_busy(true, 'mimeshield.saving'));
        });

        rcmail.addEventListener('plugin.mimeshield_list_reload', function (data) {
            rcmail.mimeshield_list_reload(data && data.id ? data.id : 0);
        });
    }

    function boundIdentities() {
        var ids = [];
        $('input[name="_identities[]"]:checked').each(function () {
            ids.push(String(this.value));
        });
        return ids.sort();
    }

    function loadFrame(action, params) {
        var win = rcmail.get_frame_window(rcmail.env.contentframe);
        if (!win) {
            return;
        }
        params._framed = 1;
        rcmail.env.frame_lock = rcmail.set_busy(true, 'loading');
        win.location.href = rcmail.url(action, params);
    }

    function confirmDelete(type, id) {
        var text = type === 'key' ? label('confirmdeletekey') : label('confirmdeletecert');
        var content = $('<div>').append($('<p>').text(text));
        rcmail.confirm_dialog(content, 'delete', function () {
            rcmail.http_post(type === 'key' ? 'plugin.mimeshield-keydelete' : 'plugin.mimeshield-certdelete',
                { _id: String(id) }, rcmail.set_busy(true, 'mimeshield.saving'));
        });
    }

    // reload the list page (called from the details frame or AJAX responses)
    rcube_webmail.prototype.mimeshield_list_reload = function (id) {
        var target = window;
        if (rcmail.is_framed() && parent.rcmail && parent.rcmail.mimeshield_list_reload) {
            return parent.rcmail.mimeshield_list_reload(id);
        }
        var action = rcmail.env.mimeshield_page === 'contacts' ? 'plugin.mimeshield-contacts' : 'plugin.mimeshield';
        var params = {};
        if (id) {
            params._sel = String(id);
        }
        target.location.href = rcmail.url(action, params);
    };

    // ------------------------------------------------------------------ compose

    var compose = {
        cache: {},         // address -> {status, until, time}
        pending: null,
        timer: null,
        lastQuery: '',

        init: function () {
            var sign = $('#mimeshield-sign'), enc = $('#mimeshield-encrypt');
            if (!sign.length && !enc.length) {
                return;
            }
            this.sign = sign;
            this.enc = enc;

            var restore = rcmail.env.mimeshield_restore;
            if (rcmail.env.mimeshield_force_encrypt && enc.length && !enc.prop('disabled')) {
                enc.prop('checked', true).trigger('change');
            }
            if (restore && typeof restore === 'object') {
                if (sign.length && !sign.prop('disabled')) {
                    sign.prop('checked', !!restore.sign).trigger('change');
                }
                if (enc.length && !enc.prop('disabled')) {
                    enc.prop('checked', !!restore.encrypt || !!rcmail.env.mimeshield_force_encrypt).trigger('change');
                }
            }

            sign.add(enc).on('change', function () {
                compose.exclusiveWithEnigma(this);
                compose.update();
            });
            $('#enigmasignopt, #enigmaencryptopt').on('change', function () {
                if (this.checked && (sign.prop('checked') || enc.prop('checked'))) {
                    sign.prop('checked', false).trigger('change');
                    enc.prop('checked', false).trigger('change');
                    rcmail.display_message(label('enigmaconflict'), 'warning');
                }
            });

            rcmail.addEventListener('change_identity', function () {
                compose.update();
            });
            rcmail.addEventListener('autocomplete_insert', function () {
                compose.schedule();
            });
            rcmail.addEventListener('add-recipient', function () {
                compose.schedule();
            });
            $(document).on('input change', '.recipient-input input, #_to, #_cc, #_bcc', function () {
                compose.schedule();
            });
            if (window.MutationObserver) {
                var obs = new MutationObserver(function () {
                    compose.schedule();
                });
                $('.recipient-input').each(function () {
                    obs.observe(this, { childList: true, subtree: true });
                });
            }

            rcmail.addEventListener('beforesend', function (props) {
                return compose.beforeSend(props);
            });
            rcmail.addEventListener('plugin.mimeshield_recipients', function (data) {
                compose.received(data);
            });
            rcmail.addEventListener('plugin.mimeshield_send_error', function (data) {
                compose.sendError(data);
            });

            // option changes must mark the draft as changed (otherwise it is not re-saved)
            var origHash = rcmail.compose_field_hash;
            rcmail.compose_field_hash = function (save) {
                var h = String(origHash.call(rcmail, save)) + (sign.prop('checked') ? 'S' : 's') + (enc.prop('checked') ? 'E' : 'e');
                if (save) {
                    // core stores its own hash in cmp_hash; store the extended one so comparisons match
                    rcmail.cmp_hash = h;
                }
                return h;
            };

            this.update();
            // the core computed its "unchanged" baseline before this wrapper existed
            rcmail.cmp_hash = rcmail.compose_field_hash();
        },

        exclusiveWithEnigma: function (el) {
            if (el.checked && ($('#enigmasignopt').prop('checked') || $('#enigmaencryptopt').prop('checked'))) {
                $('#enigmasignopt, #enigmaencryptopt').prop('checked', false).trigger('change');
                rcmail.display_message(label('enigmaconflict'), 'warning');
            }
        },

        identity: function () {
            var id = $('[name="_from"]').val() || rcmail.env.identity;
            var map = rcmail.env.mimeshield_identities || {};
            return map[id] || null;
        },

        update: function () {
            var box = $('#mimeshield-status').empty();
            var ident = this.identity();

            if (this.sign.length) {
                var canSign = ident && ident.sign;
                if (!canSign && this.sign.prop('checked') && !this.sign.prop('disabled')) {
                    // the selected identity has no usable certificate: do not keep a requested signature silently
                    this.sign.prop('checked', false).trigger('change');
                    rcmail.display_message(label('signdisabledidentity'), 'warning');
                }
                if (!this.sign.data('locked')) {
                    this.sign.prop('disabled', !canSign || $.inArray('sign', rcmail.env.mimeshield_locks || []) >= 0);
                }
                var info = $('<div>');
                if (canSign) {
                    info.addClass(ident.soon ? 'warning' : 'ok')
                        .append($('<div>').text((ident.soon ? '⚠ ' : '✔ ') + ident.cert))
                        .append($('<div class="mimeshield-sub">').text(ident.issuer))
                        .append($('<div class="mimeshield-sub">').text(label('expiresat', { date: ident.until })));
                } else {
                    info.addClass('warning').append($('<div>').text('⚠ ' + (ident && ident.reason ? ident.reason : label('nocertificate'))));
                }
                box.append($('<div class="mimeshield-cert">').append($('<div class="mimeshield-label">').text(label('signingcert'))).append(info));
            }

            if (this.enc.length && this.enc.prop('checked')) {
                if (rcmail.env.mimeshield_force_encrypt === false) {
                    // nothing
                }
                if ($.trim($('#_bcc').val() || '') !== '' && rcmail.env.mimeshield_bcc_mode === 'single') {
                    box.append($('<div class="warning">').text(label('bccwarning')));
                }
                this.schedule(true);
            } else {
                if (this.enc.length && rcmail.env.mimeshield_force_encrypt) {
                    box.append($('<div class="warning">').text(label('forceencryptwarning')));
                }
                $('#mimeshield-recipients').empty();
            }
        },

        addresses: function () {
            var out = [], seen = {};
            $.each(['_to', '_cc', '_bcc'], function (i, f) {
                var v = $('#' + f).val() || '';
                var re = /<([^<>\s]+@[^<>\s]+)>|([^\s,;<>"]+@[^\s,;<>"]+)/g, m;
                while ((m = re.exec(v)) !== null) {
                    var a = String(m[1] || m[2]).toLowerCase();
                    if (!seen[a]) {
                        seen[a] = true;
                        out.push(a);
                    }
                }
            });
            return out.slice(0, 100);
        },

        schedule: function (now) {
            if (!this.enc || !this.enc.prop('checked')) {
                return;
            }
            clearTimeout(this.timer);
            this.timer = setTimeout(function () {
                compose.query();
            }, now ? 50 : 800);
        },

        query: function () {
            var all = this.addresses(), missing = [], t = Date.now();
            $.each(all, function (i, a) {
                var c = compose.cache[a];
                if (!c || t - c.time > 300000) {
                    missing.push(a);
                }
            });
            this.render(all);
            if (!missing.length) {
                return;
            }
            var key = missing.join(',');
            if (key === this.lastQuery && this.pending && t - this.pending < 15000) {
                return; // same request still in flight (a failed request is retried after 15 s)
            }
            this.lastQuery = key;
            $.each(missing, function (i, a) {
                compose.cache[a] = compose.cache[a] || { status: 'checking', time: 0 };
            });
            this.pending = t;
            rcmail.http_post('plugin.mimeshield-recipients', { _addresses: missing });
        },

        received: function (data) {
            var t = Date.now();
            this.pending = null;
            $.each((data && data.recipients) || {}, function (addr, r) {
                compose.cache[String(addr)] = { status: String(r.status), until: r.until ? String(r.until) : '', revunknown: r.revocation === 'unknown', time: t };
            });
            // addresses as typed (e.g. IDN in Unicode) -> normalised address used by the server
            $.each((data && data.aliases) || {}, function (typed, norm) {
                var r = compose.cache[String(norm)];
                if (r) {
                    compose.cache[String(typed)] = r;
                }
            });
            this.render(this.addresses());
        },

        render: function (all) {
            var box = $('#mimeshield-recipients').empty();
            if (!this.enc.prop('checked') || !all.length) {
                return;
            }
            var ul = $('<ul>');
            $.each(all, function (i, a) {
                var c = compose.cache[a] || { status: 'checking' };
                var li = $('<li>');
                // certificate usable, but its revocation status could not be determined (CRL checking on)
                var warn = c.status === 'untrusted' || (c.status === 'ok' && c.revunknown);
                var cls = warn ? 'warning' : (c.status === 'ok' ? 'ok' : (c.status === 'checking' ? '' : 'error'));
                var mark = warn ? '⚠ ' : (c.status === 'ok' ? '✔ ' : (c.status === 'checking' ? '… ' : '✖ '));
                li.addClass(cls).text(mark + a + ' – ' + label(c.status === 'ok' && c.revunknown ? 'recipient_revocationunknown' : 'recipient_' + c.status));
                ul.append(li);
            });
            box.append($('<div class="mimeshield-label">').text(label('recipientsstatus'))).append(ul);
        },

        beforeSend: function (props) {
            if (!this.enc || !this.enc.prop('checked')) {
                return;
            }
            var bad = {};
            $.each(this.addresses(), function (i, a) {
                var c = compose.cache[a];
                if (c && c.time && c.status !== 'ok' && c.status !== 'untrusted') {
                    bad[a] = c.status;
                }
            });
            if (!$.isEmptyObject(bad)) {
                this.missingDialog(bad);
                return false;
            }
            // unknown statuses are decided by the server (which blocks sending when needed)
        },

        sendError: function (data) {
            if (data && data.recipients) {
                var t = Date.now(), map = {};
                $.each(data.recipients, function (addr, st) {
                    var s = String(st).split(':')[0];
                    compose.cache[String(addr)] = { status: s, time: t };
                    map[String(addr)] = s;
                });
                this.render(this.addresses());
                this.missingDialog(map);
            }
        },

        missingDialog: function (map) {
            var content = $('<div class="mimeshield-dialog">');
            content.append($('<p>').text(label('missingintro')));
            var ul = $('<ul>');
            $.each(map, function (addr, st) {
                ul.append($('<li>').text(addr + ' – ' + label('recipient_' + st)));
            });
            content.append(ul);
            var locked = $.inArray('encrypt', rcmail.env.mimeshield_locks || []) >= 0 || compose.enc.prop('disabled')
                || !!rcmail.env.mimeshield_require_encrypt;
            var buttons = [];
            if (!locked) {
                if (rcmail.env.mimeshield_force_encrypt) {
                    // the quoted / forwarded content was encrypted: say so before it is sent in clear
                    content.append($('<p class="mimeshield-warning">').text(label('decryptedwarning')));
                }
                content.append($('<p>').text(label('sendwithoutencrypt')));
                buttons.push({
                    text: label('sendunencrypted'),
                    'class': 'mainaction send',
                    click: function (e, ui, dialog) {
                        // explicit, conscious user decision: switch encryption off (visibly) and send
                        compose.enc.prop('checked', false).trigger('change');
                        (rcmail.is_framed() ? parent.$ : $)(this).dialog('close');
                        // the compose input was already validated by the first send attempt
                        rcmail.command('send', { nocheck: true });
                    }
                });
            } else {
                content.append($('<p>').text(label('encryptlocked')));
            }
            buttons.push({
                text: label('cancel'),
                'class': 'cancel',
                click: function () {
                    (rcmail.is_framed() ? parent.$ : $)(this).dialog('close');
                }
            });
            rcmail.show_popup_dialog(content, label('missingtitle'), buttons);
        }
    };

    // ------------------------------------------------------------------ message view

    function messageInit() {
        $(document).on('click', 'a.mimeshield-savecert', function (e) {
            e.preventDefault();
            saveCert(false);
        });
        rcmail.addEventListener('plugin.mimeshield_savecert_confirm', function (data) {
            var changes = (data && data.changes) || [], fp = '', replace = false, untrusted = false;
            var ul = $('<ul>');
            $.each(changes, function (i, ch) {
                fp = String(ch.new || '');
                replace = replace || (ch.old || []).length > 0;
                untrusted = untrusted || !!ch.untrusted;
                // fingerprints of the stored and of the new certificate (audit F-15)
                var li = $('<li>').text(String(ch.email));
                $.each(ch.old || [], function (j, old) {
                    li.append($('<div class="mimeshield-fp">').text(label('fingerprintold') + ' ' + formatFp(old)));
                });
                li.append($('<div class="mimeshield-fp">').text(label('fingerprintnew') + ' ' + formatFp(fp)));
                ul.append(li);
            });
            var content = $('<div class="mimeshield-dialog">');
            if (replace) {
                content.append($('<p>').text(label('confirmreplace')));
            }
            if (untrusted) {
                content.append($('<p class="mimeshield-warning">').text(label('confirmuntrusted')));
            }
            content.append(ul);
            rcmail.confirm_dialog(content, 'mimeshield.replacebutton', function () {
                saveCert(true, fp);
            });
        });
        rcmail.addEventListener('plugin.mimeshield_savecert_done', function () {
            $('a.mimeshield-savecert').closest('p').remove();
        });
    }

    function formatFp(hex) {
        return String(hex).toUpperCase().replace(/(..)(?!$)/g, '$1:');
    }

    function saveCert(confirm, fingerprint) {
        var params = { _uid: String(rcmail.env.uid || ''), _mbox: String(rcmail.env.mailbox || '') };
        if (confirm) {
            params._confirm = 1;
            params._fingerprint = String(fingerprint || '');
        }
        rcmail.http_post('plugin.mimeshield-savecert', params, rcmail.set_busy(true, 'mimeshield.saving'));
    }

    // ------------------------------------------------------------------ init

    rcmail.addEventListener('init', function () {
        if (rcmail.env.task === 'settings') {
            settingsInit();
        } else if (rcmail.env.task === 'mail') {
            if (rcmail.env.action === 'compose') {
                compose.init();
            } else {
                messageInit();
            }
        }
    });
})();
