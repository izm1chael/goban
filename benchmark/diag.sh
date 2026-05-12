#!/usr/bin/env bash
# Minimal diagnostic: run goban-daemon manually under sudo, drive 1000 lines
# at it, then ask it how many it saw. Bypasses every layer of accuracy.sh.
#
# Usage:
#   sudo bash benchmark/diag.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "must run as root" >&2
  exit 1
fi

cd "$(dirname "$0")"

LOG=/tmp/diag-auth.log
SOCK=/tmp/goban-bench.sock
DAEMON_OUT=/tmp/diag-goban.out
DAEMON_LOG=/tmp/diag-goban.log

# Clean slate
killall -q -TERM goban-daemon 2>/dev/null || true
sleep 1
killall -q -KILL goban-daemon 2>/dev/null || true
ipset destroy goban-bench-v4 2>/dev/null || true
ipset destroy goban-bench-v6 2>/dev/null || true
rm -f "$LOG" "$DAEMON_OUT" "$DAEMON_LOG" "$SOCK" \
      /tmp/bench-goban.log /tmp/bench-goban.stdout 2>/dev/null || true
touch "$LOG"
chmod 666 "$LOG"

# Custom config — points at /tmp/diag-auth.log and uses fresh state paths
CFG=$(mktemp)
cat >"$CFG" <<EOF
log_level: debug
log_file: $DAEMON_LOG
sock_path: $SOCK
dry_run: false
ipv6: false
ipset_name_v4: goban-bench-v4
ipset_name_v6: goban-bench-v6
allowlist:
  - 127.0.0.0/8
defaults:
  max_retries: 5
  findtime: 10m
  bantime: 1h
sources:
  - type: file
    name: auth
    path: $LOG
rules:
  - name: sshd
    source: auth
    regex: 'Failed password for (?:invalid user )?\S+ from (?P<ip>\S+) port'
    max_retries: 5
    findtime: 10m
    bantime: 1h
EOF

echo "=== Step 1: starting daemon ==="
../bin/goban-daemon --config "$CFG" >"$DAEMON_OUT" 2>&1 &
DPID=$!
sleep 2

if ! kill -0 "$DPID" 2>/dev/null; then
  echo "DAEMON DIED. Stdout:"
  cat "$DAEMON_OUT"
  exit 1
fi
echo "daemon alive, pid=$DPID"

if [[ ! -S "$SOCK" ]]; then
  echo "SOCKET MISSING at $SOCK"
  echo "Daemon stdout:"; cat "$DAEMON_OUT"
  echo "Daemon log:";    cat "$DAEMON_LOG" 2>/dev/null
  kill -TERM "$DPID" 2>/dev/null || true
  exit 1
fi
echo "socket exists at $SOCK"

echo
echo "=== Step 2: writing 1000 ssh-fail lines at 100/sec ==="
./gen/gen --target "$LOG" --rate 100 --duration 10s --unique-ips 50 2>&1
sleep 2

echo
echo "=== Step 3: querying daemon ==="
../bin/goban-client --sock "$SOCK" status
echo
../bin/goban-client --sock "$SOCK" rules
echo
../bin/goban-client --sock "$SOCK" list

echo
echo "=== Step 4: daemon log tail ==="
tail -30 "$DAEMON_LOG" 2>/dev/null || echo "(no log file)"

echo
echo "=== Step 5: ipset entries ==="
ipset list goban-bench-v4 2>&1 | head -20

# Cleanup
kill -TERM "$DPID" 2>/dev/null || true
wait "$DPID" 2>/dev/null || true
ipset destroy goban-bench-v4 2>/dev/null || true
rm -f "$CFG"
