#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
MOCKBIN="$TMP/bin"
LOG="$TMP/systemctl.log"
mkdir -p "$MOCKBIN"

cat > "$MOCKBIN/getent" <<'SH'
#!/bin/sh
exit 0
SH
cat > "$MOCKBIN/groupadd" <<'SH'
#!/bin/sh
exit 0
SH
cat > "$MOCKBIN/useradd" <<'SH'
#!/bin/sh
exit 0
SH
cat > "$MOCKBIN/systemctl" <<'SH'
#!/bin/sh
: "${MOCK_SYSTEMCTL_LOG:?}"
printf '%s\n' "$*" >> "$MOCK_SYSTEMCTL_LOG"
if [ "${1:-}" = "is-active" ]; then
    [ "${MOCK_ACTIVE:-no}" = "yes" ] && exit 0
    exit 3
fi
if [ "${1:-}" = "restart" ] && [ "${MOCK_RESTART_FAIL:-no}" = "yes" ]; then
    exit 1
fi
exit 0
SH
chmod +x "$MOCKBIN"/*

run_hook() {
    env PATH="$MOCKBIN:/usr/bin:/bin" MOCK_SYSTEMCTL_LOG="$LOG" "$@"
}

: > "$LOG"
MOCK_ACTIVE=no run_hook "$ROOT_DIR/packaging/postinst.sh" >/dev/null
grep -Fxq 'daemon-reload' "$LOG"
! grep -Fq 'restart goban.service' "$LOG"

: > "$LOG"
MOCK_ACTIVE=yes run_hook "$ROOT_DIR/packaging/postinst.sh" >/dev/null
grep -Fxq 'restart goban.service' "$LOG"

: > "$LOG"
run_hook "$ROOT_DIR/packaging/prerm.sh" upgrade
! grep -Fq 'disable --now goban.service' "$LOG"

: > "$LOG"
run_hook "$ROOT_DIR/packaging/prerm.sh" 1
! grep -Fq 'disable --now goban.service' "$LOG"

: > "$LOG"
run_hook "$ROOT_DIR/packaging/prerm.sh" remove
grep -Fxq 'disable --now goban.service' "$LOG"
grep -Fxq 'disable --now goban-persist.service' "$LOG"

: > "$LOG"
run_hook "$ROOT_DIR/packaging/prerm.sh" 0
grep -Fxq 'disable --now goban.service' "$LOG"

: > "$LOG"
upgrade_output=$(run_hook "$ROOT_DIR/packaging/postrm.sh" upgrade)
[[ -z $upgrade_output ]] || { echo "postrm upgrade emitted misleading removal text: $upgrade_output" >&2; exit 1; }

: > "$LOG"
remove_output=$(run_hook "$ROOT_DIR/packaging/postrm.sh" remove)
grep -Fq 'GoBan removed.' <<<"$remove_output"

: > "$LOG"
set +e
MOCK_ACTIVE=yes MOCK_RESTART_FAIL=yes run_hook "$ROOT_DIR/packaging/postinst.sh" >/dev/null 2>&1
rc=$?
set -e
[[ $rc -ne 0 ]] || { echo 'postinst must fail when an active daemon cannot restart' >&2; exit 1; }

echo 'PASS: package lifecycle hooks preserve upgrades and stop real removals'
