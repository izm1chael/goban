#!/bin/sh
# prerm — stop GoBan only on real package removal. Upgrade transitions must
# keep the freshly installed/restarted services alive.
set -e

action=${1:-}
case "$action" in
    0|remove)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl disable --now goban.service >/dev/null 2>&1 || true
            systemctl disable --now goban-enforcer.service >/dev/null 2>&1 || true
            systemctl disable --now goban-persist.service >/dev/null 2>&1 || true
        fi
        ;;
    *) ;;
esac

exit 0
