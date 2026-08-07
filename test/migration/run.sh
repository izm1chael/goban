#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT_DIR"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/fail2ban/jail.d"
cat > "$TMP/fail2ban/jail.conf" <<'CFG'
[DEFAULT]
bantime = 3600
findtime = 10m
maxretry = 5
ignoreip = 127.0.0.1

[sshd]
enabled = true
backend = systemd
maxretry = 3

[nginx-http-auth]
enabled = true
logpath = /var/log/nginx/error.log

[custom-console]
enabled = true
filter = local-console
logpath = /var/log/custom-console.log
action = custom-shell[name=unsafe]
CFG

bin/goban-client migrate fail2ban \
  --root "$TMP/fail2ban" \
  --out "$TMP/out" \
  --rules-available examples/rules.d

bin/goban-client config validate \
  --config "$TMP/out/goban.yaml" \
  --rules-dir "$TMP/out/rules.d"

grep -q 'status: unsupported' "$TMP/out/migration-report.yaml"
grep -q 'dry_run: true' "$TMP/out/goban.yaml"
test -f "$TMP/out/rules.d/sshd.yaml"
test -f "$TMP/out/rules.d/nginx.yaml"
echo "PASS: Fail2Ban migration produces valid reviewable staging output"
