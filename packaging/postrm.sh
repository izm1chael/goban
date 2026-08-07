#!/bin/sh
# postrm — runs after package removal. The pre-remove hook has already stopped
# and disabled GoBan on a real removal. Deliberately preserve the `goban` user,
# config, saved state, audit log, and kernel ban sets: removing the package is
# not the same as asking GoBan to forget its evidence or actively unban peers.
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

# nFPM invokes the old package's post-remove hook during an upgrade too
# (dpkg: "upgrade", rpm: 1). Do not tell the operator GoBan was removed when
# the new package is already installed and, if previously active, restarted.
case "${1:-}" in
    1|upgrade) exit 0 ;;
esac

cat <<'EOF'
GoBan removed.

The following are intentionally NOT deleted:
  /etc/goban/            — your config and rule bundles
  /var/lib/goban/        — persisted strike state
  /var/log/goban/        — audit log
  goban system user/group
  Existing GoBan kernel ban entries (until expiry, firewall reset, or reboot)

To purge everything:
  sudo rm -rf /etc/goban /var/lib/goban /var/log/goban
  sudo ipset destroy goban-ban-v4 2>/dev/null || true
  sudo ipset destroy goban-ban-v6 2>/dev/null || true
  sudo nft delete table inet goban 2>/dev/null || true
  sudo userdel goban && sudo groupdel goban
EOF

exit 0
