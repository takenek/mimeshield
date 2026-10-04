-- Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
-- Original author: Marek Królikowski (TaKeN)
-- Original project: https://github.com/takenek/mimeshield
-- SPDX-License-Identifier: GPL-3.0-or-later
-- See LICENSE and COPYRIGHT for the license and GPL section 7 attribution terms.

-- MIME Shield (mimeshield) - database schema for SQLite
-- Install:  bin/initdb.sh --dir=plugins/mimeshield/SQL
-- Update:   bin/updatedb.sh --package=mimeshield --dir=plugins/mimeshield/SQL
-- Table names are prefixed automatically with $config['db_prefix'] by Roundcube.

CREATE TABLE mimeshield_keys (
  key_id integer NOT NULL PRIMARY KEY,
  user_id integer NOT NULL
    REFERENCES users (user_id) ON DELETE CASCADE ON UPDATE CASCADE,
  fingerprint varchar(64) NOT NULL,
  serial varchar(128) NOT NULL default '',
  subject text NOT NULL default '',
  issuer text NOT NULL default '',
  emails text NOT NULL default '',
  not_before datetime NOT NULL default '0000-00-00 00:00:00',
  not_after datetime NOT NULL default '0000-00-00 00:00:00',
  cert_pem text NOT NULL,
  chain_pem text NOT NULL default '',
  key_blob text NOT NULL,
  key_kid varchar(16) NOT NULL,
  key_format smallint NOT NULL default '1',
  key_type varchar(16) NOT NULL default '',
  key_bits integer NOT NULL default '0',
  created datetime NOT NULL default '0000-00-00 00:00:00',
  changed datetime NOT NULL default '0000-00-00 00:00:00'
);

CREATE UNIQUE INDEX ix_mimeshield_keys_user_fp ON mimeshield_keys(user_id, fingerprint);

CREATE TABLE mimeshield_bindings (
  user_id integer NOT NULL
    REFERENCES users (user_id) ON DELETE CASCADE ON UPDATE CASCADE,
  identity_id integer NOT NULL
    REFERENCES identities (identity_id) ON DELETE CASCADE ON UPDATE CASCADE,
  key_id integer NOT NULL
    REFERENCES mimeshield_keys (key_id) ON DELETE CASCADE ON UPDATE CASCADE,
  changed datetime NOT NULL default '0000-00-00 00:00:00',
  PRIMARY KEY (user_id, identity_id)
);

CREATE INDEX ix_mimeshield_bindings_key ON mimeshield_bindings(key_id);

CREATE TABLE mimeshield_certs (
  cert_id integer NOT NULL PRIMARY KEY,
  user_id integer NOT NULL
    REFERENCES users (user_id) ON DELETE CASCADE ON UPDATE CASCADE,
  fingerprint varchar(64) NOT NULL,
  serial varchar(128) NOT NULL default '',
  subject text NOT NULL default '',
  issuer text NOT NULL default '',
  emails text NOT NULL default '',
  not_before datetime NOT NULL default '0000-00-00 00:00:00',
  not_after datetime NOT NULL default '0000-00-00 00:00:00',
  cert_pem text NOT NULL,
  chain_pem text NOT NULL default '',
  source varchar(16) NOT NULL default 'import',
  trust varchar(16) NOT NULL default 'observed',
  created datetime NOT NULL default '0000-00-00 00:00:00',
  changed datetime NOT NULL default '0000-00-00 00:00:00'
);

CREATE UNIQUE INDEX ix_mimeshield_certs_user_fp ON mimeshield_certs(user_id, fingerprint);

CREATE TABLE mimeshield_cert_emails (
  user_id integer NOT NULL
    REFERENCES users (user_id) ON DELETE CASCADE ON UPDATE CASCADE,
  cert_id integer NOT NULL
    REFERENCES mimeshield_certs (cert_id) ON DELETE CASCADE ON UPDATE CASCADE,
  email varchar(255) NOT NULL,
  preferred tinyint NOT NULL default '0',
  PRIMARY KEY (cert_id, email)
);

CREATE INDEX ix_mimeshield_cert_emails_lookup ON mimeshield_cert_emails(user_id, email);

INSERT INTO system (name, value) VALUES ('mimeshield-version', '2026100200');
