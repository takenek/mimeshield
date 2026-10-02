#!/usr/bin/env bash
#
# MIME Shield - E2E compatibility matrix (TEST ONLY). Runs tests/e2e/test_e2e.py sequentially
# (the Dovecot test mailboxes are shared) for Roundcube 1.7.x x PHP x database combinations.
#
#   matrix.sh [rc_base_dir]     (default /opt/rcrun containing 1.7.0 .. 1.7.4 with vendor/)
set -u
BASE="${1:-/opt/rcrun}"
HERE="$(cd "$(dirname "$0")" && pwd)"
LOG="$HERE/run/matrix-$(date +%Y%m%d-%H%M%S)"; mkdir -p "$LOG"
runs=(
  # rc     php     db      prefix
  "1.7.4 php8.1 sqlite"
  "1.7.4 php8.2 sqlite"
  "1.7.4 php8.3 sqlite"
  "1.7.4 php8.4 sqlite"
  "1.7.4 php8.5 sqlite"
  "1.7.0 php8.4 sqlite"
  "1.7.1 php8.4 sqlite"
  "1.7.2 php8.4 sqlite"
  "1.7.3 php8.4 sqlite"
  "1.7.0 php8.1 sqlite"
  "1.7.4 php8.4 mysql"
  "1.7.4 php8.4 pgsql"
  "1.7.4 php8.1 mysql rc_"
  "1.7.4 php8.5 pgsql rc_"
)
total=0; bad=0
for r in "${runs[@]}"; do
  set -- $r
  name="$1-$2-$3${4:+-prefix}"
  python3 "$HERE/test_e2e.py" --rc "$BASE/$1" --php "$2" --db "$3" --port 8090 --smtp 2590 ${4:+--prefix "$4"} > "$LOG/$name.log" 2>&1
  res=$(tail -1 "$LOG/$name.log")
  printf '%-28s %s\n' "$name" "$res" | tee -a "$LOG/summary.txt"
  total=$((total+1)); case "$res" in *" 0 failed"*) ;; *) bad=$((bad+1));; esac
done
echo "MATRIX: $((total-bad))/$total combinations green (logs: $LOG)" | tee -a "$LOG/summary.txt"
[ "$bad" -eq 0 ]
