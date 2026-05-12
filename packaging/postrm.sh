#!/bin/sh
# postrm — runs after package removal. Deliberately conservative: we do NOT
# delete the `goban` user, the config in /etc/goban/, the saved strike
# state in /var/lib/goban/, or the kernel ipset bans. Bans persist in the
# kernel until next reboot regardless; the operator removed the package,
# they didn't ask us to "forget everything."
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

cat <<'EOF'
GoBan removed.

The following are intentionally NOT deleted:
  /etc/goban/            — your config and rule bundles
  /var/lib/goban/        — persisted strike state
  /var/log/goban/        — audit log
  goban system user/group
  Active kernel ipset entries (existing bans remain until kernel restart)

To purge everything:
  sudo rm -rf /etc/goban /var/lib/goban /var/log/goban
  sudo ipset destroy goban-ban-v4 2>/dev/null || true
  sudo ipset destroy goban-ban-v6 2>/dev/null || true
  sudo userdel goban && sudo groupdel goban
EOF

exit 0
