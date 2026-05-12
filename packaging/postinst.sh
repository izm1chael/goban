#!/bin/sh
# postinst — runs after `apt install ./goban.deb` or `dnf install goban.rpm`.
# Idempotent: re-running on upgrade does the right thing.
set -e

# 1. System user/group for the daemon. GoBan still runs as root because it
# needs CAP_NET_ADMIN to talk to ipset over netlink, but the `goban` group
# is used as the owner of the control unix socket (mode 0660) so operators
# can use goban-client without sudo by being in the group.
if ! getent group goban >/dev/null 2>&1; then
    groupadd --system goban
fi
if ! getent passwd goban >/dev/null 2>&1; then
    useradd --system --gid goban --no-create-home \
            --shell /usr/sbin/nologin --comment "GoBan daemon" goban
fi

# 2. Make sure systemd sees the new unit. Best-effort — works on systemd
# hosts, silently no-ops elsewhere.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

# 3. Don't auto-enable. Operators have varying opinions on whether a
# package install should start a service on its own; the conservative
# default is "no, you decide."
cat <<'EOF'
GoBan installed successfully.

Next steps:
  1. Review and edit /etc/goban/goban.yaml for your environment
  2. Drop rule bundles into /etc/goban/rules.d/ (or use the bundled ones)
  3. Enable and start the daemon:
       sudo systemctl enable --now goban

Test a rule offline before deploying:
  sudo goban-client test --rule sshd /var/log/auth.log

Docs: https://github.com/izm1chael/goban
EOF

exit 0
