#!/usr/bin/env bash
#
# MIME Shield - CMS interoperability with independent S/MIME implementations (TEST ONLY):
#   * NSS cmsutil  (Mozilla NSS = the crypto library of Thunderbird)
#   * GnuPG gpgsm  (S/MIME engine of KMail / Kleopatra / Evolution)
#   * OpenSSL CLI
# Both directions: plugin -> tool (verify + decrypt) and tool -> plugin (verify + decrypt).
#
# Requires: libnss3-tools, gpgsm, openssl, php.   Usage: run.sh [php-binary]
set -uo pipefail
PHP="${1:-php}"
HERE="$(cd "$(dirname "$0")" && pwd)"
P="$HERE/../fixtures/pki"
PASS='test-password-Zażółć'
W="$(mktemp -d)"; trap 'GNUPGHOME="$W/gnupg" gpgconf --kill gpg-agent 2>/dev/null; rm -rf "$W"' EXIT
cd "$W"
pass=0; fail=0
ok()   { echo "PASS  $1"; pass=$((pass+1)); }
bad()  { echo "FAIL  $1"; fail=$((fail+1)); }
chk()  { if (set +o pipefail; eval "$2") >/dev/null 2>&1; then ok "$1"; else bad "$1"; fi; }  # pipelines judged by their last command

"$PHP" "$HERE/plugin_cms.php" make "$W" || { echo "cannot create plugin messages"; exit 1; }
sed 's/Za=C5/Zb=C5/' content.txt > tampered.txt

# ---------------------------------------------------------------- OpenSSL
chk "openssl verifies plugin detached signature" \
  "openssl cms -verify -binary -inform DER -in plugin-sig.der -content content.txt -CAfile $P/root.crt -purpose smimesign -out /dev/null"
chk "openssl detects tampered content" \
  "! openssl cms -verify -binary -inform DER -in plugin-sig.der -content tampered.txt -CAfile $P/root.crt -out /dev/null"
chk "openssl decrypts plugin envelope (bob)" \
  "openssl cms -decrypt -binary -inform DER -in plugin-enc.der -recip $P/bob.crt -inkey $P/bob.key | cmp -s - content.txt"

# ---------------------------------------------------------------- NSS (Thunderbird)
echo -n pw > pw.txt; mkdir nss
certutil -N -d sql:nss -f pw.txt
certutil -A -d sql:nss -n root -t "C,C,C" -f pw.txt -i "$P/root.crt"
certutil -A -d sql:nss -n int -t ",," -f pw.txt -i "$P/int.crt"
pk12util -i "$P/bob.p12" -d sql:nss -k pw.txt -W "$PASS" >/dev/null
certutil -A -d sql:nss -n alice -t ",," -f pw.txt -i "$P/alice.crt"
chk "NSS verifies plugin detached signature" "cmsutil -D -d sql:nss -i plugin-sig.der -c content.txt -u 5 | grep -q 'Za=C5'"
chk "NSS detects tampered content" "! cmsutil -D -d sql:nss -i plugin-sig.der -c tampered.txt -u 5"
chk "NSS decrypts plugin envelope (bob)" "cmsutil -D -d sql:nss -f pw.txt -i plugin-enc.der | cmp -s - content.txt"
cmsutil -S -d sql:nss -f pw.txt -N "bob TEST ONLY" -T -G -P -H SHA256 -i content.txt -o nss-sig.der >/dev/null 2>&1
cmsutil -E -d sql:nss -f pw.txt -r alice@example.test -i content.txt -o nss-enc.der >/dev/null 2>&1
chk "plugin verifies NSS signature and decrypts NSS envelope" "\"$PHP\" \"$HERE/plugin_cms.php\" check content.txt nss-sig.der nss-enc.der bob@example.test"

# ---------------------------------------------------------------- GnuPG gpgsm
export GNUPGHOME="$W/gnupg"; mkdir -m 700 gnupg
printf "allow-loopback-pinentry\n" > gnupg/gpg-agent.conf
printf "disable-crl-checks\n" > gnupg/gpgsm.conf
echo "$(openssl x509 -in "$P/root.crt" -noout -fingerprint -sha1 | cut -d= -f2) S" > gnupg/trustlist.txt
gpgsm --batch --import "$P/root.crt" "$P/int.crt" "$P/alice.crt" >/dev/null 2>&1
cat "$P/bob.crt" "$P/bob.key" > bob.pem
openssl pkcs12 -export -legacy -in bob.pem -passout pass:abc -out bob-legacy.p12 2>/dev/null   # gpgsm 2.4 PKCS#12 parser
echo abc | gpgsm --batch --pinentry-mode loopback --passphrase-fd 0 --import bob-legacy.p12 >/dev/null 2>&1
chk "gpgsm verifies plugin detached signature" "gpgsm --batch --status-fd 1 --verify plugin-sig.der content.txt 2>/dev/null | grep -q GOODSIG"
chk "gpgsm detects tampered content" "gpgsm --batch --status-fd 1 --verify plugin-sig.der tampered.txt 2>/dev/null | grep -q BADSIG"
chk "gpgsm decrypts plugin envelope (bob)" "echo abc | gpgsm --batch --pinentry-mode loopback --passphrase-fd 0 --decrypt plugin-enc.der 2>/dev/null | cmp -s - content.txt"
echo abc | gpgsm --batch --pinentry-mode loopback --passphrase-fd 0 -u bob@example.test --detach-sign --output gpgsm-sig.der content.txt >/dev/null 2>&1
gpgsm --batch -r alice@example.test --encrypt --output gpgsm-enc.der content.txt >/dev/null 2>&1
chk "plugin verifies gpgsm signature and decrypts gpgsm envelope" "\"$PHP\" \"$HERE/plugin_cms.php\" check content.txt gpgsm-sig.der gpgsm-enc.der bob@example.test"

echo "INTEROP: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
