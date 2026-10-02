#!/usr/bin/env bash
#
# MIME Shield - E2E environment (TEST ONLY).
#
# Prepares a Roundcube instance with the plugin, a database, a master key, the test PKI trust
# store, an SMTP sink and the PHP built-in web server.
#
#   setup.sh <roundcube_dir> <php_binary> <db: sqlite|mysql|pgsql> <http_port> <smtp_port> [db_prefix]
#
# Requirements: Dovecot with the test users alice/bob/mallory/carol@example.test (password
# "testpass"), python3-aiosmtpd, MariaDB/PostgreSQL servers for mysql/pgsql runs.
set -euo pipefail

RC="$(realpath "$1")"; PHP="$2"; DB="$3"; PORT="$4"; SMTP_PORT="$5"; PREFIX="${6:-}"
PLUGIN="$(cd "$(dirname "$0")/../.." && pwd)"
RUN="$PLUGIN/tests/e2e/run/$(basename "$RC")-$(basename "$PHP")-$DB"
rm -rf "$RUN"; mkdir -p "$RUN"/{temp,logs,smtp,keys}
chmod 0755 "$RUN"

# plugin link
rm -f "$RC/plugins/mimeshield"
ln -s "$PLUGIN" "$RC/plugins/mimeshield"

# master key (test only)
KEYFILE="$RUN/keys/master.key"
printf '# TEST ONLY master key\nk1 %s\n' "$(head -c32 /dev/urandom | base64)" > "$KEYFILE"
chmod 0400 "$KEYFILE"

case "$DB" in
  sqlite)
    DSN="sqlite:///$RUN/roundcube.db?mode=0640" ;;
  mysql)
    NAME="rcms_$(basename "$RC" | tr -dc 'a-z0-9')_$(basename "$PHP" | tr -dc 'a-z0-9')"
    mariadb -u root -e "DROP DATABASE IF EXISTS $NAME; CREATE DATABASE $NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER IF NOT EXISTS 'rcms'@'localhost' IDENTIFIED BY 'rcms'; GRANT ALL ON $NAME.* TO 'rcms'@'localhost';"
    DSN="mysql://rcms:rcms@localhost/$NAME" ;;
  pgsql)
    NAME="rcms_$(basename "$RC" | tr -dc 'a-z0-9')_$(basename "$PHP" | tr -dc 'a-z0-9')"
    su postgres -c "psql -q -c \"DROP DATABASE IF EXISTS $NAME\"" >/dev/null
    su postgres -c "psql -q -c \"DO \\\$\\\$BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='rcms') THEN CREATE ROLE rcms LOGIN PASSWORD 'rcms'; END IF; END\\\$\\\$;\"" >/dev/null
    su postgres -c "psql -q -c \"CREATE DATABASE $NAME OWNER rcms ENCODING 'UTF8' TEMPLATE template0\"" >/dev/null
    DSN="pgsql://rcms:rcms@127.0.0.1/$NAME" ;;
  *) echo "unknown db $DB"; exit 1 ;;
esac

cat > "$RUN/config.inc.php" <<EOF
<?php
\$config = [];
\$config['db_dsnw'] = '$DSN';
\$config['db_prefix'] = '$PREFIX';
\$config['imap_host'] = '127.0.0.1:143';
\$config['smtp_host'] = '127.0.0.1:$SMTP_PORT';
\$config['smtp_user'] = '';
\$config['smtp_pass'] = '';
\$config['support_url'] = '';
\$config['des_key'] = 'TESTONLY-$(head -c12 /dev/urandom | base64 | tr -dc A-Za-z0-9 | head -c18)';
\$config['cipher_method'] = 'AES-256-CBC';
\$config['plugins'] = ['mimeshield'];
\$config['skin'] = 'elastic';
\$config['temp_dir'] = '$RUN/temp/';
\$config['log_dir'] = '$RUN/logs/';
\$config['log_driver'] = 'file';
\$config['session_lifetime'] = 60;
\$config['create_default_folders'] = true;
\$config['enable_installer'] = false;
\$config['smtp_log'] = true;
\$config['login_rate_limit'] = 0;
\$config['mimeshield_master_key_file'] = '$KEYFILE';
\$config['mimeshield_ca_bundle'] = ['$PLUGIN/tests/fixtures/pki/root.crt'];
\$config['mimeshield_use_system_ca'] = false;
\$config['mimeshield_debug'] = true;
EOF
if [ -n "${MIMESHIELD_EXTRA_CONFIG:-}" ]; then echo "$MIMESHIELD_EXTRA_CONFIG" >> "$RUN/config.inc.php"; fi

export ROUNDCUBE_CONFIG_DIR="$RUN/"
cp "$RC/config/defaults.inc.php" "$RUN/defaults.inc.php" 2>/dev/null || true

# schema: core + plugin
cd "$RC"
if [ "$DB" = sqlite ]; then
  # an empty sqlite file is initialised by the driver itself (core schema, no prefix)
  [ -n "$PREFIX" ] && { echo "db_prefix with sqlite auto-init is not supported by this script"; exit 1; }
  "$PHP" -r 'define("INSTALL_PATH", getcwd()."/"); require "program/include/clisetup.php"; rcube::get_instance()->get_dbh()->query("SELECT 1");' >/dev/null
else
  "$PHP" bin/initdb.sh --dir="$RC/SQL" >/dev/null
fi
"$PHP" bin/initdb.sh --dir="$RC/plugins/mimeshield/SQL"
"$PHP" bin/updatedb.sh --package=mimeshield --dir="$RC/plugins/mimeshield/SQL"

# SMTP sink
pkill -f "smtpsink.py --port $SMTP_PORT" 2>/dev/null || true
nohup python3 "$PLUGIN/tests/e2e/smtpsink.py" --port "$SMTP_PORT" --outdir "$RUN/smtp" > "$RUN/smtpsink.log" 2>&1 &
# web server
pkill -f "127.0.0.1:$PORT " 2>/dev/null || true
nohup env ROUNDCUBE_CONFIG_DIR="$RUN/" "$PHP" -d variables_order=EGPCS -d upload_max_filesize=8M -S "127.0.0.1:$PORT" -t "$RC/public_html" > "$RUN/php-server.log" 2>&1 &
sleep 1.5
echo "RUN=$RUN"
echo "URL=http://127.0.0.1:$PORT/"
