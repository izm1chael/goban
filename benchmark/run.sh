#!/usr/bin/env bash
# Benchmark harness: runs one scenario for one daemon and writes CSV samples.
#
# Usage:
#   ./run.sh <daemon> <action> <rate> <duration_sec> <unique_ips> <cell>
#
# Outputs:
#   results/<daemon>-<cell>-<action>-<rate>.csv         (timeseries)
#   results/<daemon>-<cell>-<action>-<rate>.summary     (one-line summary)
set -euo pipefail

DAEMON="${1:?daemon required (goban|fail2ban)}"
ACTION="${2:?action required (dry|iptables)}"
RATE="${3:?rate required}"
DURATION="${4:?duration required}"
UNIQUE_IPS="${5:?unique_ips required}"
CELL="${6:?cell required (native|container)}"

cd "$(dirname "$0")"
mkdir -p results

CSV="results/${DAEMON}-${CELL}-${ACTION}-${RATE}.csv"
SUM="results/${DAEMON}-${CELL}-${ACTION}-${RATE}.summary"
LOG=/tmp/bench-auth.log

DAEMON_PID=""
SAMPLER_PID=""

cleanup() {
  set +e
  if [[ -n "$DAEMON_PID" ]]; then
    kill -TERM "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
  fi
  if [[ -n "$SAMPLER_PID" ]]; then
    kill -INT "$SAMPLER_PID" 2>/dev/null
    wait "$SAMPLER_PID" 2>/dev/null
  fi
  if [[ "$ACTION" == "iptables" ]]; then
    ipset destroy goban-bench-v4 2>/dev/null
    ipset destroy goban-bench-v6 2>/dev/null
    ipset destroy f2b-sshd-bench 2>/dev/null
  fi
}
trap cleanup EXIT

# Bullet-proof fresh log: delete (regardless of owner), create new, world-rw.
# Must work whether called as root or as the user; if not root, rely on the
# file being our own or already world-writable.
# Defensively delete any stale outputs from prior runs. Newer kernels enforce
# fs.protected_regular which blocks O_CREAT (the `>` redirect) on files in
# sticky dirs that are owned by a different user — even for root. Removing
# first sidesteps that entirely.
rm -f "$LOG" \
      /tmp/bench-goban.stdout /tmp/bench-goban.log \
      /tmp/bench-fail2ban.log /tmp/bench-f2b-container.log \
      /tmp/bench-f2b-container.cid /tmp/bench-goban-container.cid \
      /tmp/fail2ban-bench.sock /tmp/fail2ban-bench.pid 2>/dev/null || true
touch "$LOG"
chmod 666 "$LOG"

case "$DAEMON" in
  goban)
    CONFIG="configs/goban-${ACTION}.yaml"
    BIN="../bin/goban-daemon"
    "$BIN" --config "$CONFIG" >/tmp/bench-goban.stdout 2>&1 &
    DAEMON_PID=$!
    ;;
  fail2ban)
    CFG_DIR="configs/fail2ban-${ACTION}"
    SCRATCH=$(mktemp -d)
    cp -r /etc/fail2ban/. "$SCRATCH/"
    cp "$CFG_DIR/jail.local" "$SCRATCH/jail.local"
    mkdir -p "$SCRATCH/filter.d"
    cp "$CFG_DIR/filter.d/sshd-bench.conf" "$SCRATCH/filter.d/sshd-bench.conf"
    rm -f /tmp/fail2ban-bench.sock /tmp/fail2ban-bench.pid /tmp/bench-fail2ban.log
    fail2ban-server -c "$SCRATCH" -s /tmp/fail2ban-bench.sock -p /tmp/fail2ban-bench.pid -x &
    for _ in $(seq 1 50); do
      if [[ -f /tmp/fail2ban-bench.pid ]]; then break; fi
      sleep 0.1
    done
    DAEMON_PID=$(cat /tmp/fail2ban-bench.pid 2>/dev/null || echo 0)
    if [[ "$DAEMON_PID" == "0" ]]; then
      echo "fail2ban failed to start (check /tmp/bench-fail2ban.log)" >&2
      exit 1
    fi
    ;;
  *)
    echo "unknown daemon: $DAEMON" >&2; exit 1;;
esac

# Let the daemon finish opening the log file before we generate load.
sleep 2

./sampler/sampler --pid "$DAEMON_PID" --out "$CSV" --interval 200ms --duration "${DURATION}s" 2>"$SUM" &
SAMPLER_PID=$!

./gen/gen --target "$LOG" --rate "$RATE" --duration "${DURATION}s" --unique-ips "$UNIQUE_IPS"

sleep 1
kill -INT "$SAMPLER_PID" 2>/dev/null || true
wait "$SAMPLER_PID" 2>/dev/null || true

echo "[$DAEMON/$CELL/$ACTION/${RATE}/sec] $(cat "$SUM")"
