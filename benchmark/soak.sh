#!/usr/bin/env bash
# Single-cell soak test with phased chaos injection.
#
# Usage:
#   sudo bash soak.sh <daemon> <cell> [duration_sec]
#
# daemon:   goban | fail2ban
# cell:     native | container
# duration: total seconds (default 1800 = 30 min). Phases scale proportionally.
#
# Phase structure (defaults below are for duration=1800):
#   1. steady     (5min) — baseline measurement, no chaos
#   2. rotation   (5min) — rotate log file every 60s (5 rotations)
#   3. burst      (5min) — alternate 30s @ 10x rate / 30s @ baseline
#   4. restart    (5min) — kill daemon every 60s, restart, brief sampler gap
#   5. cardinality(5min) — grow unique IP pool by 1000/min (5K total added)
#   6. cooldown   (5min) — steady again; metrics should return to baseline
#
# Outputs in results/:
#   soak-<daemon>-<cell>.csv          — sampler timeseries (1s interval)
#   soak-<daemon>-<cell>.events       — chaos event log
#   soak-<daemon>-<cell>.gen.csv      — generator output rate over time
#   soak-<daemon>-<cell>.summary      — final stats
set -euo pipefail

DAEMON="${1:?daemon required}"
CELL="${2:?cell required}"
TOTAL="${3:-1800}"

if [[ $EUID -ne 0 ]]; then
  echo "must run as root" >&2
  exit 1
fi

cd "$(dirname "$0")"
mkdir -p results

LOG=/tmp/soak-auth.log
FIFO=/tmp/soak-gen.fifo
PHASE=$((TOTAL / 6))
BASE_RATE=5000
BASE_IPS=10000
BURST_RATE=$((BASE_RATE * 10))
GOBAN_IMG="goban:latest"
F2B_IMG="crazymax/fail2ban:1.0.2"

CSV="results/soak-${DAEMON}-${CELL}.csv"
EVT="results/soak-${DAEMON}-${CELL}.events"
GENCSV="results/soak-${DAEMON}-${CELL}.gen.csv"
SUM="results/soak-${DAEMON}-${CELL}.summary"

DAEMON_PID=""
SAMPLER_PID=""
GEN_PID=""
CONTAINER_NAME=""

cleanup() {
  set +e
  echo "$(date +%s),cleanup" >> "$EVT"
  [[ -n "$GEN_PID" ]] && { echo "quit" >"$FIFO" 2>/dev/null; kill -TERM "$GEN_PID" 2>/dev/null; wait "$GEN_PID" 2>/dev/null; }
  [[ -n "$SAMPLER_PID" ]] && { kill -INT "$SAMPLER_PID" 2>/dev/null; wait "$SAMPLER_PID" 2>/dev/null; }
  [[ -n "$DAEMON_PID" ]] && { kill -TERM "$DAEMON_PID" 2>/dev/null; }
  [[ -n "$CONTAINER_NAME" ]] && { docker stop "$CONTAINER_NAME" 2>/dev/null; }
  # Iptables cleanup
  ipset destroy goban-bench-v4 2>/dev/null
  ipset destroy goban-bench-v6 2>/dev/null
  ipset destroy f2b-sshd-bench 2>/dev/null
  rm -f "$FIFO" "$LOG" "$LOG".[0-9] /tmp/soak-*.cid /tmp/soak-*.pid /tmp/soak-*.sock
}
trap cleanup EXIT

reset_state() {
  rm -f "$LOG" "$LOG".[0-9] "$CSV" "$CSV".* "$EVT" "$GENCSV" "$SUM" "$FIFO" \
        /tmp/soak-*.pid /tmp/soak-*.sock /tmp/soak-*.cid /tmp/soak-*.fifo \
        /tmp/soak-goban.stdout /tmp/soak-goban.log /tmp/soak-fail2ban.log 2>/dev/null || true
  touch "$LOG"
  chmod 666 "$LOG"
  mkfifo "$FIFO"
  chmod 666 "$FIFO"
  : >"$EVT"
}

start_daemon() {
  case "$DAEMON" in
    goban)
      case "$CELL" in
        native)
          ../bin/goban-daemon --config configs/goban-iptables-soak.yaml >/tmp/soak-goban.stdout 2>&1 &
          DAEMON_PID=$!
          ;;
        container)
          CONTAINER_NAME=goban-soak
          docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
          docker run -d --rm --name "$CONTAINER_NAME" \
            --network host --cap-add NET_ADMIN --cap-add NET_RAW \
            -v "$PWD/configs/goban-iptables-soak.yaml:/etc/goban/goban.yaml:ro" \
            -v "$LOG:$LOG:ro" \
            "$GOBAN_IMG" --config /etc/goban/goban.yaml >/dev/null
          sleep 3
          DAEMON_PID=$(docker top "$CONTAINER_NAME" -eo pid,comm,args 2>/dev/null \
                       | awk 'NR>1 && index($0, "goban-daemon") > 0 { print $1; exit }')
          if [[ -z "$DAEMON_PID" ]]; then
            echo "goban container did not produce a daemon PID" >&2
            docker logs "$CONTAINER_NAME" 2>&1 | tail -20 >&2
            return 1
          fi
          ;;
      esac
      ;;
    fail2ban)
      case "$CELL" in
        native)
          SCRATCH=$(mktemp -d)
          cp -r /etc/fail2ban/. "$SCRATCH/"
          cp configs/fail2ban-soak/jail.local "$SCRATCH/jail.local"
          mkdir -p "$SCRATCH/filter.d"
          cp configs/fail2ban-soak/filter.d/sshd-bench.conf "$SCRATCH/filter.d/sshd-bench.conf"
          fail2ban-server -c "$SCRATCH" -s /tmp/soak-f2b.sock -p /tmp/soak-f2b.pid -x &
          for _ in $(seq 1 50); do
            [[ -f /tmp/soak-f2b.pid ]] && break
            sleep 0.1
          done
          DAEMON_PID=$(cat /tmp/soak-f2b.pid 2>/dev/null || echo 0)
          ;;
        container)
          CONTAINER_NAME=f2b-soak
          docker rm -f "$CONTAINER_NAME" 2>/dev/null || true
          DATA=$(mktemp -d)
          mkdir -p "$DATA/jail.d" "$DATA/filter.d"
          cp configs/fail2ban-soak/jail.local             "$DATA/jail.d/bench.local"
          cp configs/fail2ban-soak/filter.d/sshd-bench.conf "$DATA/filter.d/sshd-bench.conf"
          docker run -d --rm --name "$CONTAINER_NAME" \
            --network host --cap-add NET_ADMIN --cap-add NET_RAW \
            -v "$DATA:/data" \
            -v "$LOG:$LOG:ro" \
            "$F2B_IMG" >/dev/null
          sleep 8
          DAEMON_PID=$(docker top "$CONTAINER_NAME" -eo pid,comm,args 2>/dev/null \
                       | awk 'NR>1 && index($0, "fail2ban-server") > 0 { print $1; exit }')
          if [[ -z "$DAEMON_PID" ]]; then
            echo "fail2ban container did not produce a server PID" >&2
            docker logs "$CONTAINER_NAME" 2>&1 | tail -20 >&2
            return 1
          fi
          ;;
      esac
      ;;
  esac
  if [[ "$DAEMON_PID" == "0" || -z "$DAEMON_PID" ]]; then
    echo "daemon failed to start" >&2
    return 1
  fi
}

stop_daemon() {
  if [[ -n "$DAEMON_PID" ]]; then
    if [[ "$CELL" == "container" ]]; then
      docker stop "$CONTAINER_NAME" 2>/dev/null || true
    else
      kill -TERM "$DAEMON_PID" 2>/dev/null || true
      wait "$DAEMON_PID" 2>/dev/null || true
    fi
    DAEMON_PID=""
  fi
}

start_sampler() {
  ./sampler/sampler --pid "$DAEMON_PID" --out "$CSV" --interval 1s --duration "${TOTAL}s" 2>/dev/null &
  SAMPLER_PID=$!
}

restart_sampler_with_new_pid() {
  if [[ -n "$SAMPLER_PID" ]]; then
    kill -INT "$SAMPLER_PID" 2>/dev/null || true
    wait "$SAMPLER_PID" 2>/dev/null || true
  fi
  # Append mode for the CSV would be nice — currently sampler truncates.
  # Workaround: spawn with a per-restart suffix and concatenate at end.
  local idx
  idx=$(ls "${CSV}".* 2>/dev/null | wc -l)
  ./sampler/sampler --pid "$DAEMON_PID" --out "${CSV}.${idx}" --interval 1s --duration "${TOTAL}s" 2>/dev/null &
  SAMPLER_PID=$!
}

event() {
  echo "$(date +%s),$1" >> "$EVT"
  echo "[$(date '+%H:%M:%S')] $1"
}

reset_state
event "phase=init"
start_daemon || exit 1
sleep 3
start_sampler

# Start generator in soak mode (FIFO control)
./gen/gen --target "$LOG" --rate "$BASE_RATE" --unique-ips "$BASE_IPS" \
  --control-fifo "$FIFO" --stats-out "$GENCSV" \
  --duration "${TOTAL}s" 2>/dev/null &
GEN_PID=$!
sleep 2

# -------- Phase 1: steady (no chaos) --------
event "phase=steady start"
sleep "$PHASE"
event "phase=steady end"

# Scale chaos-event cadence to the phase length so the soak is meaningful
# at any duration. Each phase fires roughly N events spread across its window.
# At duration=60 (smoke test), each phase has ~10s and fires 4 events at ~2.5s
# spacing — fast but covers the code path. At duration=1800 (full), each
# phase has 300s with events spaced 75s apart.
EVENTS_PER_PHASE=4
EVT_INTERVAL=$((PHASE / EVENTS_PER_PHASE))
if [[ "$EVT_INTERVAL" -lt 2 ]]; then
  EVT_INTERVAL=2
fi
BURST_LEN=$((EVT_INTERVAL / 2))
if [[ "$BURST_LEN" -lt 1 ]]; then
  BURST_LEN=1
fi
echo "phase=${PHASE}s, events/phase=${EVENTS_PER_PHASE}, interval=${EVT_INTERVAL}s, burst_len=${BURST_LEN}s"

# -------- Phase 2: log rotation --------
event "phase=rotation start"
for i in $(seq 1 "$EVENTS_PER_PHASE"); do
  sleep "$EVT_INTERVAL"
  mv "$LOG" "$LOG.1"
  touch "$LOG"; chmod 666 "$LOG"
  echo "rotate $LOG" > "$FIFO" 2>/dev/null || true
  event "rotation #$i"
done
event "phase=rotation end"

# -------- Phase 3: bursts --------
event "phase=burst start"
for i in $(seq 1 "$EVENTS_PER_PHASE"); do
  echo "burst $BURST_RATE $BURST_LEN" > "$FIFO" 2>/dev/null || true
  event "burst #$i (${BURST_RATE}/sec x ${BURST_LEN}s)"
  sleep "$EVT_INTERVAL"
done
event "phase=burst end"

# -------- Phase 4: daemon restart chaos --------
event "phase=restart start"
for i in $(seq 1 "$EVENTS_PER_PHASE"); do
  KILL_AT=$((EVT_INTERVAL - 2))
  [[ $KILL_AT -lt 1 ]] && KILL_AT=1
  sleep "$KILL_AT"
  event "killing daemon (restart #$i)"
  stop_daemon
  sleep 1
  start_daemon || { event "restart failed"; break; }
  restart_sampler_with_new_pid
  event "daemon restarted, pid=$DAEMON_PID"
  sleep 1
done
event "phase=restart end"

# -------- Phase 5: cardinality growth --------
event "phase=cardinality start"
STEPS=$EVENTS_PER_PHASE
CARD_STEP=$((EVT_INTERVAL))
TARGET_IPS=$BASE_IPS
for i in $(seq 1 "$STEPS"); do
  TARGET_IPS=$((TARGET_IPS + 1000))
  echo "ips $TARGET_IPS" > "$FIFO" 2>/dev/null || true
  event "cardinality grew to $TARGET_IPS"
  sleep "$CARD_STEP"
done
event "phase=cardinality end"

# -------- Phase 6: cooldown --------
event "phase=cooldown start"
sleep "$PHASE"
event "phase=cooldown end"

# Tell gen to exit
echo "quit" > "$FIFO" 2>/dev/null || true

# Wait for sampler/gen to finalize
sleep 2
kill -INT "$SAMPLER_PID" 2>/dev/null || true
wait "$SAMPLER_PID" 2>/dev/null || true
kill -TERM "$GEN_PID" 2>/dev/null || true
wait "$GEN_PID" 2>/dev/null || true

# Concatenate any restart-suffixed CSVs back into the main one
if ls "${CSV}".* 2>/dev/null; then
  for f in $(ls "${CSV}".* | sort -V); do
    tail -n +2 "$f" >> "$CSV"
    rm -f "$f"
  done
fi

# Summarize
python3 - <<PY > "$SUM"
import csv, statistics, os
path = "$CSV"
rss = []
cpu = []
samples = 0
if os.path.exists(path):
    with open(path) as f:
        r = csv.DictReader(f)
        for row in r:
            try:
                rss.append(float(row.get("rss_kb", 0)))
                c = float(row.get("cpu_pct", 0))
                if c > 0:
                    cpu.append(c)
                samples += 1
            except (ValueError, KeyError):
                pass
def stats(xs):
    if not xs: return ("0","0","0","0")
    return (f"{statistics.mean(xs):.2f}", f"{max(xs):.2f}", f"{statistics.median(xs):.2f}",
            f"{sorted(xs)[int(len(xs)*0.99)]:.2f}" if len(xs) > 1 else f"{xs[0]:.2f}")
cm, cmax, cmed, cp99 = stats(cpu)
rm_, rmax, rmed, rp99 = stats(rss)
print(f"daemon=$DAEMON cell=$CELL duration=$TOTAL samples={samples}")
print(f"cpu_mean_pct={cm} cpu_p99_pct={cp99} cpu_max_pct={cmax}")
print(f"rss_mean_kb={rm_} rss_p99_kb={rp99} rss_max_kb={rmax} rss_median_kb={rmed}")
PY

echo
echo "=== $DAEMON / $CELL summary ==="
cat "$SUM"
