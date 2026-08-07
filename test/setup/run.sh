#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT_DIR"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/root/etc" "$TMP/root/var/log/nginx" "$TMP/root/var/log/goban" "$TMP/root/proc/net" "$TMP/root/usr/sbin"
printf 'ID=ubuntu\nVERSION_ID=26.04\n' > "$TMP/root/etc/os-release"
: > "$TMP/root/var/log/auth.log"
: > "$TMP/root/var/log/nginx/access.log"
: > "$TMP/root/var/log/goban/audit.log"
: > "$TMP/root/proc/net/if_inet6"
: > "$TMP/root/usr/sbin/nft"

bin/goban-client setup \
  --root "$TMP/root" \
  --write \
  --out "$TMP/out" \
  --rules-available examples/rules.d

bin/goban-client config validate \
  --config "$TMP/out/goban.yaml" \
  --rules-dir "$TMP/out/rules.d"

grep -q 'dry_run: true' "$TMP/out/goban.yaml"
grep -q 'backend: nftables' "$TMP/out/goban.yaml"
test -f "$TMP/out/rules.d/sshd.yaml"
test -f "$TMP/out/rules.d/nginx.yaml"
test -f "$TMP/out/rules.d/recidive.yaml"
echo "PASS: setup detection writes a valid dry-run staging configuration"
