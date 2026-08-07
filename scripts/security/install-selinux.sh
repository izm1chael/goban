#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)
if [[ -d "$ROOT_DIR/deploy/selinux" ]]; then
  POLICY_DIR="$ROOT_DIR/deploy/selinux"
else
  POLICY_DIR=$(cd "$SCRIPT_DIR/../selinux" && pwd)
fi
[[ $(id -u) -eq 0 ]] || { echo "run as root" >&2; exit 77; }
command -v semodule >/dev/null || { echo "SELinux semodule not installed" >&2; exit 77; }
[[ -f /usr/share/selinux/devel/Makefile ]] || { echo "selinux-policy-devel is required" >&2; exit 77; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cp "$POLICY_DIR/goban.te" "$POLICY_DIR/goban.fc" "$tmp/"
make -s -C "$tmp" -f /usr/share/selinux/devel/Makefile goban.pp
semodule -i "$tmp/goban.pp"
restorecon -RF /usr/bin/goban-daemon /usr/bin/goban-enforcer /etc/goban /var/lib/goban /var/log/goban /run/goban /run/goban-enforcer 2>/dev/null || true
echo "PASS: GoBan SELinux policy installed"
