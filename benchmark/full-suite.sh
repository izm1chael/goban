#!/usr/bin/env bash
# Run the full GoBan vs fail2ban benchmark matrix.
#
# Cells: native + container × dry + iptables × 100/1000/10000 lines/sec
# Each scenario runs for $DURATION seconds at 200ms sampling interval.
#
# Invoke with sudo. DURATION as a positional arg (sudo strips env vars):
#
#   sudo bash benchmark/full-suite.sh             # default 30s/scenario
#   sudo bash benchmark/full-suite.sh 15          # 15s/scenario, ~half the time
#
# Output: benchmark/results/<daemon>-<cell>-<action>-<rate>.csv (+ .summary)
# Final summary is printed at the end.
set -euo pipefail

DURATION="${1:-30}"
RATES=(100 1000 10000)
ACTIONS=(dry iptables)

if [[ $EUID -ne 0 ]]; then
  echo "must run as root (sudo bash $0)" >&2
  exit 1
fi

cd "$(dirname "$0")"

GOBAN_IMG="goban:latest"
F2B_IMG="crazymax/fail2ban:1.0.2"
LOG=/tmp/bench-auth.log

# Kill any leftover daemons that might be holding the log file or socket.
killall -q -TERM goban-daemon fail2ban-server 2>/dev/null || true
sleep 1
killall -q -KILL goban-daemon fail2ban-server 2>/dev/null || true

echo "Stopping host fail2ban service (if running)..."
systemctl stop fail2ban 2>/dev/null || true

echo "Pulling fail2ban docker image (one-time)..."
docker pull "$F2B_IMG" >/dev/null 2>&1 || echo "warning: could not pull $F2B_IMG, fail2ban container cells will be skipped"

mkdir -p results
rm -f results/*.csv results/*.summary

run_native() {
  local daemon="$1" action="$2" rate="$3"
  bash run.sh "$daemon" "$action" "$rate" "$DURATION" 200 native
}

reset_log() {
  rm -f "$LOG" \
        /tmp/bench-goban.stdout /tmp/bench-goban.log \
        /tmp/bench-fail2ban.log /tmp/bench-f2b-container.log \
        /tmp/bench-f2b-container.cid /tmp/bench-goban-container.cid 2>/dev/null || true
  touch "$LOG"
  chmod 666 "$LOG"
}

# find_container_proc_pid: look up the host PID of a specific binary running
# inside a container, NOT the container's PID 1 (which may be an init shim
# like s6-overlay that uses near-zero CPU).
#
# Usage: pid=$(find_container_proc_pid <container_name> <comm_substring>)
# Returns empty string if no matching process is found.
find_container_proc_pid() {
  local cname="$1" needle="$2"
  # docker top prints host PIDs (the host can see all processes in the
  # container's pid namespace, with the host PID values).
  # Format: UID PID PPID C STIME TTY TIME CMD
  docker top "$cname" -eo pid,comm,args 2>/dev/null \
    | awk -v n="$needle" 'NR>1 && index($0, n) > 0 { print $1; exit }'
}

# dump_and_fail: print container logs and return failure. Used when a
# container exited prematurely or its target process didn't appear.
dump_and_fail() {
  local cname="$1" label="$2"
  echo "$label: container did not produce a usable PID" >&2
  docker ps -a --filter "name=$cname" --format 'state={{.State}} status={{.Status}}' >&2 || true
  docker logs "$cname" 2>&1 | tail -30 | sed "s/^/  $cname: /" >&2 || true
  docker rm -f "$cname" >/dev/null 2>&1 || true
}

run_goban_container() {
  local action="$1" rate="$2"
  reset_log

  local docker_args=(
    --rm -d
    --name goban-bench
    -v "$PWD/configs/goban-${action}.yaml:/etc/goban/goban.yaml:ro"
    -v "$LOG:$LOG:ro"
  )
  if [[ "$action" == "iptables" ]]; then
    docker_args+=(--network host --cap-add NET_ADMIN --cap-add NET_RAW)
  fi

  docker rm -f goban-bench 2>/dev/null || true
  if ! docker run "${docker_args[@]}" "$GOBAN_IMG" --config /etc/goban/goban.yaml >/tmp/bench-goban-container.cid 2>&1; then
    echo "goban container failed to start: $(cat /tmp/bench-goban-container.cid)" >&2
    return 1
  fi
  sleep 3
  local host_pid
  host_pid=$(find_container_proc_pid goban-bench goban-daemon)
  if [[ -z "$host_pid" ]]; then
    dump_and_fail goban-bench "[goban/container/$action/${rate}/sec]"
    return 1
  fi

  local csv="results/goban-container-${action}-${rate}.csv"
  local sum="results/goban-container-${action}-${rate}.summary"
  ./sampler/sampler --pid "$host_pid" --out "$csv" --interval 200ms --duration "${DURATION}s" 2>"$sum" &
  local sampler_pid=$!

  ./gen/gen --target "$LOG" --rate "$rate" --duration "${DURATION}s" --unique-ips 200
  sleep 1
  kill -INT "$sampler_pid" 2>/dev/null || true
  wait "$sampler_pid" 2>/dev/null || true

  docker stop goban-bench >/dev/null 2>&1 || true
  if [[ "$action" == "iptables" ]]; then
    ipset destroy goban-bench-v4 2>/dev/null || true
    ipset destroy goban-bench-v6 2>/dev/null || true
  fi
  echo "[goban/container/$action/${rate}/sec] $(cat "$sum")"
}

run_f2b_container() {
  local action="$1" rate="$2"
  if ! docker image inspect "$F2B_IMG" >/dev/null 2>&1; then
    echo "[fail2ban/container/$action/${rate}/sec] SKIPPED (image not available)"
    return
  fi
  reset_log

  # crazymax/fail2ban expects jail snippets under /data/jail.d/, NOT
  # /data/jail.local — the root jail.local is ignored by the image's startup
  # script. Filters go under /data/filter.d/ as expected.
  local data_dir
  data_dir=$(mktemp -d)
  mkdir -p "$data_dir/jail.d" "$data_dir/filter.d"
  cp "configs/fail2ban-${action}/jail.local"             "$data_dir/jail.d/bench.local"
  cp "configs/fail2ban-${action}/filter.d/sshd-bench.conf" "$data_dir/filter.d/sshd-bench.conf"

  local docker_args=(
    --rm -d
    --name f2b-bench
    -v "$data_dir:/data"
    -v "$LOG:$LOG:ro"
    -e F2B_LOG_LEVEL=WARNING
  )
  if [[ "$action" == "iptables" ]]; then
    docker_args+=(--network host --cap-add NET_ADMIN --cap-add NET_RAW)
  fi

  docker rm -f f2b-bench 2>/dev/null || true
  docker run "${docker_args[@]}" "$F2B_IMG" >/tmp/bench-f2b-container.cid 2>&1 || true
  # fail2ban container has an s6-overlay init wrapper. We need the fail2ban-
  # server PID, not PID 1 — give it longer to settle since the python startup
  # is slow.
  sleep 8
  local host_pid
  host_pid=$(find_container_proc_pid f2b-bench fail2ban-server)
  if [[ -z "$host_pid" ]]; then
    dump_and_fail f2b-bench "[fail2ban/container/$action/${rate}/sec]"
    return 1
  fi

  local csv="results/fail2ban-container-${action}-${rate}.csv"
  local sum="results/fail2ban-container-${action}-${rate}.summary"
  ./sampler/sampler --pid "$host_pid" --out "$csv" --interval 200ms --duration "${DURATION}s" 2>"$sum" &
  local sampler_pid=$!

  ./gen/gen --target "$LOG" --rate "$rate" --duration "${DURATION}s" --unique-ips 200
  sleep 1
  kill -INT "$sampler_pid" 2>/dev/null || true
  wait "$sampler_pid" 2>/dev/null || true

  docker stop f2b-bench >/dev/null 2>&1 || true
  if [[ "$action" == "iptables" ]]; then
    ipset destroy f2b-sshd-bench 2>/dev/null || true
  fi
  echo "[fail2ban/container/$action/${rate}/sec] $(cat "$sum")"
}

echo "=== NATIVE ==="
for action in "${ACTIONS[@]}"; do
  for rate in "${RATES[@]}"; do
    run_native goban "$action" "$rate" || echo "FAILED: goban/native/$action/$rate"
    run_native fail2ban "$action" "$rate" || echo "FAILED: fail2ban/native/$action/$rate"
  done
done

echo
echo "=== CONTAINER ==="
for action in "${ACTIONS[@]}"; do
  for rate in "${RATES[@]}"; do
    run_goban_container "$action" "$rate" || echo "FAILED: goban/container/$action/$rate"
    run_f2b_container "$action" "$rate" || echo "FAILED: fail2ban/container/$action/$rate"
  done
done

echo
echo "=== SUMMARY TABLE ==="
printf "%-40s | %12s | %12s | %12s\n" "scenario" "mean_cpu%" "peak_cpu%" "peak_rss_kb"
echo "---------------------------------------------------------------------------------------"
for f in results/*.summary; do
  [[ -f "$f" ]] || continue
  name=$(basename "$f" .summary)
  line=$(cat "$f")
  mean=$(echo "$line" | sed -n 's/.*mean_cpu=\([0-9.]*\).*/\1/p')
  peak=$(echo "$line" | sed -n 's/.*peak_cpu=\([0-9.]*\).*/\1/p')
  rss=$(echo "$line" | sed -n 's/.*peak_rss=\([0-9]*\).*/\1/p')
  printf "%-40s | %12s | %12s | %12s\n" "$name" "${mean:--}" "${peak:--}" "${rss:--}"
done
