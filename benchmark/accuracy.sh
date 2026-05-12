#!/usr/bin/env bash
# Line-accounting check: generate a known number of lines, then ask each
# daemon how many it actually processed. Anything below ~99% means the daemon
# is silently dropping lines.
#
# For each cell, generates `RATE * DURATION` synthetic ssh-fail lines, waits
# for the daemon to settle, then queries:
#   - GoBan: /rules endpoint → hits + misses (atomic counters, no log parsing)
#   - fail2ban: fail2ban-client status sshd-bench → "Total failed"
#
# Usage:
#   sudo bash accuracy.sh [duration_sec]    # default 30s
#
# Cells run (all native + container):
#   {goban,fail2ban} × {native,container} × {1000,5000,10000} lines/sec
set -euo pipefail

DURATION="${1:-30}"
RATES=(1000 5000 10000)
# LOG must match the source paths in configs/goban-iptables.yaml and
# configs/fail2ban-iptables/jail.local — both expect /tmp/bench-auth.log.
LOG=/tmp/bench-auth.log
GOBAN_IMG=goban:latest
F2B_IMG=crazymax/fail2ban:1.0.2

if [[ $EUID -ne 0 ]]; then
  echo "must run as root" >&2
  exit 1
fi

cd "$(dirname "$0")"
mkdir -p results

reset_log() {
  # Wipe any leftover state from prior runs. fs.protected_regular blocks
  # writes to files in /tmp owned by another uid, so we must rm them up
  # front rather than rely on the daemon's > redirect to truncate.
  rm -f "$LOG" \
        /tmp/acc-*.log /tmp/acc-*.stdout /tmp/acc-*.pid /tmp/acc-*.sock \
        /tmp/bench-goban.log /tmp/bench-goban.stdout \
        /tmp/bench-fail2ban.log \
        /tmp/goban-bench.sock 2>/dev/null || true
  touch "$LOG"
  chmod 666 "$LOG"
}

stop_all() {
  killall -q -TERM goban-daemon fail2ban-server 2>/dev/null || true
  docker rm -f acc-goban acc-f2b 2>/dev/null || true
  ipset destroy goban-bench-v4 2>/dev/null || true
  ipset destroy goban-bench-v6 2>/dev/null || true
  ipset destroy f2b-sshd-bench 2>/dev/null || true
  sleep 1
}

# ---- daemon controllers ----
start_goban_native() {
  reset_log
  ../bin/goban-daemon --config configs/goban-iptables.yaml >/tmp/acc-goban.stdout 2>&1 &
  GOBAN_PID=$!
  sleep 2
  # Sanity check: process must be alive AND socket must exist before we
  # declare the daemon ready. If either fails, dump stdout for diagnosis.
  if ! kill -0 "$GOBAN_PID" 2>/dev/null; then
    echo "[DIAG] goban-daemon native exited at startup; stdout:" >&2
    cat /tmp/acc-goban.stdout >&2 || true
    return 1
  fi
  if [[ ! -S /tmp/goban-bench.sock ]]; then
    echo "[DIAG] goban-daemon native running (pid=$GOBAN_PID) but socket missing; stdout:" >&2
    cat /tmp/acc-goban.stdout >&2 || true
    return 1
  fi
}

start_goban_container() {
  reset_log
  docker rm -f acc-goban 2>/dev/null || true
  docker run -d --rm --name acc-goban \
    --network host --cap-add NET_ADMIN --cap-add NET_RAW \
    -v "$PWD/configs/goban-iptables.yaml:/etc/goban/goban.yaml:ro" \
    -v "$LOG:$LOG:ro" \
    "$GOBAN_IMG" --config /etc/goban/goban.yaml >/dev/null
  sleep 3
  if ! docker ps -q -f name=acc-goban | grep -q .; then
    echo "[DIAG] goban-daemon container exited at startup; logs:" >&2
    docker logs acc-goban 2>&1 | tail -20 >&2 || true
    return 1
  fi
}

query_goban_native() {
  ../bin/goban-client --sock /tmp/goban-bench.sock --json rules | python3 -c "
import json,sys
rules = json.load(sys.stdin)
hits = sum(r['hits'] for r in rules)
misses = sum(r['misses'] for r in rules)
print(hits + misses)
"
}

query_goban_container() {
  docker exec acc-goban /usr/local/bin/goban-client --sock /tmp/goban-bench.sock --json rules 2>/dev/null | python3 -c "
import json,sys
try:
    rules = json.load(sys.stdin)
    hits = sum(r['hits'] for r in rules)
    misses = sum(r['misses'] for r in rules)
    print(hits + misses)
except: print(0)
"
}

start_f2b_native() {
  reset_log
  # Wipe persistent fail2ban state so Total-failed starts at zero.
  rm -f /var/lib/fail2ban/fail2ban.sqlite3 /tmp/acc-f2b.sqlite3 2>/dev/null || true
  SCRATCH=$(mktemp -d)
  cp -r /etc/fail2ban/. "$SCRATCH/"
  cp configs/fail2ban-iptables/jail.local "$SCRATCH/jail.local"
  mkdir -p "$SCRATCH/filter.d"
  cp configs/fail2ban-iptables/filter.d/sshd-bench.conf "$SCRATCH/filter.d/sshd-bench.conf"
  # Point fail2ban at a private db file. fail2ban natively merges
  # fail2ban.local into fail2ban.conf, so this overrides cleanly without
  # creating a duplicate [Definition] section.
  cat > "$SCRATCH/fail2ban.local" <<'EOF'
[Definition]
dbfile = /tmp/acc-f2b.sqlite3
EOF
  fail2ban-server -c "$SCRATCH" -s /tmp/acc-f2b.sock -p /tmp/acc-f2b.pid -x &
  for _ in $(seq 1 50); do
    [[ -f /tmp/acc-f2b.pid ]] && break
    sleep 0.1
  done
  F2B_SOCK=/tmp/acc-f2b.sock
  sleep 1
}

start_f2b_container() {
  reset_log
  docker rm -f acc-f2b 2>/dev/null || true
  DATA=$(mktemp -d)
  mkdir -p "$DATA/jail.d" "$DATA/filter.d"
  cp configs/fail2ban-iptables/jail.local "$DATA/jail.d/bench.local"
  cp configs/fail2ban-iptables/filter.d/sshd-bench.conf "$DATA/filter.d/sshd-bench.conf"
  docker run -d --rm --name acc-f2b \
    --network host --cap-add NET_ADMIN --cap-add NET_RAW \
    -v "$DATA:/data" \
    -v "$LOG:$LOG:ro" \
    "$F2B_IMG" >/dev/null
  sleep 8
}

query_f2b_native() {
  fail2ban-client -s /tmp/acc-f2b.sock status sshd-bench 2>/dev/null \
    | awk '/Total failed:/ { print $NF; exit }'
}

query_f2b_container() {
  docker exec acc-f2b fail2ban-client status sshd-bench 2>/dev/null \
    | awk '/Total failed:/ { print $NF; exit }'
}

# ---- main run ----
echo "Accuracy check: ${DURATION}s/cell at rates ${RATES[*]} lines/sec"
echo
printf "%-30s | %10s | %12s | %10s | %14s\n" "scenario" "generated" "processed" "ratio %" "throughput L/s"
echo "------------------------------------------------------------------------------------------------"

for rate in "${RATES[@]}"; do
  EXPECTED=$((rate * DURATION))

  # ---- goban native ----
  stop_all
  start_goban_native
  ./gen/gen --target "$LOG" --rate "$rate" --duration "${DURATION}s" --unique-ips 200 >/dev/null 2>&1
  sleep 3  # let nxadm/tail flush the last bytes through
  processed=$(query_goban_native || echo 0)
  ratio=$(python3 -c "print(f'{100*$processed/$EXPECTED:.2f}')")
  throughput=$(python3 -c "print(f'{$processed/$DURATION:.0f}')")
  printf "%-30s | %10d | %12s | %10s | %14s\n" "goban-native-$rate" "$EXPECTED" "$processed" "$ratio" "$throughput"

  # ---- goban container ----
  stop_all
  start_goban_container
  ./gen/gen --target "$LOG" --rate "$rate" --duration "${DURATION}s" --unique-ips 200 >/dev/null 2>&1
  sleep 3
  processed=$(query_goban_container || echo 0)
  ratio=$(python3 -c "print(f'{100*$processed/$EXPECTED:.2f}')")
  throughput=$(python3 -c "print(f'{$processed/$DURATION:.0f}')")
  printf "%-30s | %10d | %12s | %10s | %14s\n" "goban-container-$rate" "$EXPECTED" "$processed" "$ratio" "$throughput"

  # ---- fail2ban native ----
  stop_all
  start_f2b_native
  ./gen/gen --target "$LOG" --rate "$rate" --duration "${DURATION}s" --unique-ips 200 >/dev/null 2>&1
  sleep 5  # fail2ban polls every 1s by default
  processed=$(query_f2b_native || echo 0)
  ratio=$(python3 -c "print(f'{100*$processed/$EXPECTED:.2f}')" 2>/dev/null || echo "ERROR")
  throughput=$(python3 -c "print(f'{$processed/$DURATION:.0f}')" 2>/dev/null || echo "?")
  printf "%-30s | %10d | %12s | %10s | %14s\n" "fail2ban-native-$rate" "$EXPECTED" "$processed" "$ratio" "$throughput"

  # ---- fail2ban container ----
  stop_all
  start_f2b_container
  ./gen/gen --target "$LOG" --rate "$rate" --duration "${DURATION}s" --unique-ips 200 >/dev/null 2>&1
  sleep 5
  processed=$(query_f2b_container || echo 0)
  ratio=$(python3 -c "print(f'{100*$processed/$EXPECTED:.2f}')" 2>/dev/null || echo "ERROR")
  throughput=$(python3 -c "print(f'{$processed/$DURATION:.0f}')" 2>/dev/null || echo "?")
  printf "%-30s | %10d | %12s | %10s | %14s\n" "fail2ban-container-$rate" "$EXPECTED" "$processed" "$ratio" "$throughput"
done

stop_all
echo
echo "ratio ≈ 100% means the daemon kept up perfectly."
echo "ratio below ~95% indicates the daemon silently dropped lines."
