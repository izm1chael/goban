#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)
if [[ -d "$ROOT_DIR/deploy/apparmor" ]]; then
  POLICY_DIR="$ROOT_DIR/deploy/apparmor"
else
  POLICY_DIR=$(cd "$SCRIPT_DIR/../apparmor" && pwd)
fi
[[ $(id -u) -eq 0 ]] || { echo "run as root" >&2; exit 77; }
command -v apparmor_parser >/dev/null || { echo "apparmor_parser not installed" >&2; exit 77; }
for profile in usr.bin.goban-daemon usr.bin.goban-enforcer; do
  apparmor_parser -Q "$POLICY_DIR/$profile"
  install -m 0644 "$POLICY_DIR/$profile" "/etc/apparmor.d/$profile"
  apparmor_parser -r "/etc/apparmor.d/$profile"
done
install -d -m 0755 /etc/systemd/system/goban.service.d /etc/systemd/system/goban-enforcer.service.d
cat >/etc/systemd/system/goban.service.d/30-apparmor.conf <<'DROPIN'
[Service]
AppArmorProfile=/usr/bin/goban-daemon
DROPIN
cat >/etc/systemd/system/goban-enforcer.service.d/30-apparmor.conf <<'DROPIN'
[Service]
AppArmorProfile=/usr/bin/goban-enforcer
DROPIN
systemctl daemon-reload
echo "PASS: GoBan AppArmor profiles installed and bound to systemd services"
