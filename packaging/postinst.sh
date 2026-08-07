#!/bin/sh
# postinst — runs after package installation/upgrade. Idempotent.
set -e

# Dedicated identity for the unprivileged parser/rule engine and the private
# enforcer socket. Unlike pre-privsep releases, goban-daemon now runs as this
# user under the packaged systemd unit.
if ! getent group goban >/dev/null 2>&1; then
    groupadd --system goban
fi
if ! getent passwd goban >/dev/null 2>&1; then
    useradd --system --gid goban --no-create-home \
            --shell /usr/sbin/nologin --comment "GoBan daemon" goban
fi
if ! getent passwd goban-enforcer >/dev/null 2>&1; then
    useradd --system --gid goban --no-create-home \
            --shell /usr/sbin/nologin --comment "GoBan firewall enforcer" goban-enforcer
fi

# Read-only log access where the distribution exposes conventional groups.
# Docker is deliberately NOT added automatically: membership in the docker
# group is effectively root-equivalent. Operators enabling Docker-socket
# sources must make that trust decision explicitly.
for grp in adm systemd-journal; do
    if getent group "$grp" >/dev/null 2>&1; then
        usermod -a -G "$grp" goban >/dev/null 2>&1 || true
    fi
done

# The unprivileged daemon must be able to read its root-managed config.
if [ -d /etc/goban ]; then
    chgrp -R goban /etc/goban
    chmod -R g+rX /etc/goban
fi
if [ -f /etc/goban/goban.yaml ]; then
    chmod 0640 /etc/goban/goban.yaml
fi
# Migrate files created by pre-privilege-separation root daemons. These
# directories are GoBan-owned state/evidence namespaces, so handing them to
# the dedicated daemon identity is intentional and required for seamless
# upgrades.
for dir in /var/lib/goban /var/log/goban; do
    if [ -d "$dir" ]; then
        chown -R goban:goban "$dir"
    fi
done

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    # A clean install remains stopped. goban-enforcer.service is PartOf the
    # detector unit, so restarting goban.service atomically cycles the active
    # package pair and the Requires/After dependency restores the helper first.
    if systemctl is-active --quiet goban.service >/dev/null 2>&1; then
        if ! systemctl restart goban.service; then
            echo "GoBan package installed, but the split service pair failed to restart." >&2
            echo "Inspect: systemctl status goban.service goban-enforcer.service" >&2
            exit 1
        fi
    fi
fi

cat <<'EOF2'
GoBan installed successfully.

Packaged systemd deployments use privilege separation by default:
  goban-daemon    — unprivileged log parsing / rule evaluation
  goban-enforcer  — separate non-root user with only CAP_NET_ADMIN

Next steps:
  1. Generate a reviewable proposal:
       sudo goban-client setup --write --out /root/goban-setup
  2. Review /etc/goban/goban.yaml and enable required rule bundles
  3. Enable and start GoBan:
       sudo systemctl enable --now goban
  4. Verify the complete split path:
       sudo goban-client doctor --probe

If using Docker-socket log sources, explicitly grant the goban user access only
if you accept that Docker daemon access is root-equivalent.
EOF2

exit 0
