#!/bin/sh
# prerm — stop GoBan only on a real package removal. Package upgrades execute
# the old package's pre-remove hook after the new package's post-install hook,
# so stopping unconditionally here would take a freshly upgraded daemon down.
set -e

action=${1:-}
case "$action" in
    0|remove)
        if command -v systemctl >/dev/null 2>&1; then
            # Disable first while the unit file still exists. Best-effort for
            # non-systemd/chroot package operations where systemctl is present
            # but there is no running manager.
            systemctl disable --now goban.service >/dev/null 2>&1 || true
            systemctl disable --now goban-persist.service >/dev/null 2>&1 || true
        fi
        ;;
    *)
        # rpm uses 1 for an upgrade; dpkg uses "upgrade". Unknown actions are
        # deliberately treated as non-removal so package transitions cannot
        # accidentally stop protection.
        ;;
esac

exit 0
