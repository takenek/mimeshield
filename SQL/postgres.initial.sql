-- MIME Shield (mimeshield) - database schema for PostgreSQL
-- Install:  bin/initdb.sh --dir=plugins/mimeshield/SQL
-- Update:   bin/updatedb.sh --package=mimeshield --dir=plugins/mimeshield/SQL
-- Table names are prefixed automatically with $config['db_prefix'] by Roundcube.

CREATE SEQUENCE mimeshield_keys_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;

CREATE TABLE mimeshield_keys (
    key_id integer DEFAULT nextval('mimeshield_keys_seq'::text) PRIMARY KEY,
    user_id integer NOT NULL
        REFERENCES users (user_id) ON DELETE CASCADE ON UPDATE CASCADE,
    fingerprint varchar(64) NOT NULL,
    serial varchar(128) DEFAULT '' NOT NULL,
    subject text NOT NULL,
    issuer text NOT NULL,
    emails text NOT NULL,
    not_before timestamp without time zone NOT NULL,
    not_after timestamp without time zone NOT NULL,
    cert_pem text NOT NULL,
    chain_pem text NOT NULL,
    key_blob text NOT NULL,
    key_kid varchar(16) NOT NULL,
    key_format smallint DEFAULT 1 NOT NULL,
    key_type varchar(16) DEFAULT '' NOT NULL,
    key_bits integer DEFAULT 0 NOT NULL,
    created timestamp without time zone NOT NULL,
    changed timestamp without time zone NOT NULL,
    CONSTRAINT mimeshield_keys_user_fp UNIQUE (user_id, fingerprint)
);

CREATE TABLE mimeshield_bindings (
    user_id integer NOT NULL
        REFERENCES users (user_id) ON DELETE CASCADE ON UPDATE CASCADE,
    identity_id integer NOT NULL
        REFERENCES identities (identity_id) ON DELETE CASCADE ON UPDATE CASCADE,
    key_id integer NOT NULL
        REFERENCES mimeshield_keys (key_id) ON DELETE CASCADE ON UPDATE CASCADE,
    changed timestamp without time zone NOT NULL,
    PRIMARY KEY (user_id, identity_id)
);

CREATE INDEX mimeshield_bindings_key_idx ON mimeshield_bindings (key_id);

CREATE SEQUENCE mimeshield_certs_seq
    START WITH 1
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;

CREATE TABLE mimeshield_certs (
    cert_id integer DEFAULT nextval('mimeshield_certs_seq'::text) PRIMARY KEY,
    user_id integer NOT NULL
        REFERENCES users (user_id) ON DELETE CASCADE ON UPDATE CASCADE,
    fingerprint varchar(64) NOT NULL,
    serial varchar(128) DEFAULT '' NOT NULL,
    subject text NOT NULL,
    issuer text NOT NULL,
    emails text NOT NULL,
    not_before timestamp without time zone NOT NULL,
    not_after timestamp without time zone NOT NULL,
    cert_pem text NOT NULL,
    chain_pem text NOT NULL,
    source varchar(16) DEFAULT 'import' NOT NULL,
    trust varchar(16) DEFAULT 'observed' NOT NULL,
    created timestamp without time zone NOT NULL,
    changed timestamp without time zone NOT NULL,
    CONSTRAINT mimeshield_certs_user_fp UNIQUE (user_id, fingerprint)
);

CREATE TABLE mimeshield_cert_emails (
    user_id integer NOT NULL
        REFERENCES users (user_id) ON DELETE CASCADE ON UPDATE CASCADE,
    cert_id integer NOT NULL
        REFERENCES mimeshield_certs (cert_id) ON DELETE CASCADE ON UPDATE CASCADE,
    email varchar(255) NOT NULL,
    preferred smallint DEFAULT 0 NOT NULL,
    PRIMARY KEY (cert_id, email)
);

CREATE INDEX mimeshield_cert_emails_lookup_idx ON mimeshield_cert_emails (user_id, email);

INSERT INTO "system" (name, value) VALUES ('mimeshield-version', '2026100200');
