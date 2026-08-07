#!/usr/bin/env bash
set -Eeuo pipefail

# Proves the complete path: synthetic hostile log -> rule threshold -> confirmed
# kernel decision -> connection blocked. Run as root on an expendable Linux
# host/VM. It deliberately uses network namespaces rather than the host's real
# interfaces.

BACKEND=${1:-iptables}   # iptables | nftables
PATH_MODE=${2:-input}    # input | forward
FAMILY=${3:-4}           # 4 | 6
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
DAEMON=${GOBAN_DAEMON:-$ROOT_DIR/bin/goban-daemon}
ENFORCER=${GOBAN_ENFORCER:-$ROOT_DIR/bin/goban-enforcer}
CLIENT=${GOBAN_CLIENT:-$ROOT_DIR/bin/goban-client}

[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 77; }
[[ $BACKEND == iptables || $BACKEND == nftables ]] || { echo "backend must be iptables or nftables" >&2; exit 2; }
[[ $PATH_MODE == input || $PATH_MODE == forward ]] || { echo "path must be input or forward" >&2; exit 2; }
[[ $FAMILY == 4 || $FAMILY == 6 ]] || { echo "family must be 4 or 6" >&2; exit 2; }
for cmd in ip python3 curl setpriv; do command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 77; }; done
id nobody >/dev/null 2>&1 || { echo "integration test requires an unprivileged 'nobody' account" >&2; exit 77; }
if [[ $BACKEND == iptables ]]; then
  for cmd in iptables ip6tables; do command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 77; }; done
else
  command -v nft >/dev/null || { echo "missing nft" >&2; exit 77; }
fi

if [[ ! -x $DAEMON || ! -x $ENFORCER || ! -x $CLIENT ]]; then
  (cd "$ROOT_DIR" && make build)
fi

suffix=$(( $$ % 200 + 20 ))
attacker_ns="goban-atk-$$"
victim_ns="goban-vic-$$"
tmp=$(mktemp -d)
daemon_pid=""
enforcer_pid=""
server_pid=""
old_forward4=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
old_forward6=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo 0)

cleanup() {
  set +e
  [[ -n $daemon_pid ]] && kill -TERM "$daemon_pid" 2>/dev/null
  [[ -n $daemon_pid ]] && wait "$daemon_pid" 2>/dev/null
  [[ -n $enforcer_pid ]] && kill -TERM "$enforcer_pid" 2>/dev/null
  [[ -n $enforcer_pid ]] && wait "$enforcer_pid" 2>/dev/null
  [[ -n $server_pid ]] && kill "$server_pid" 2>/dev/null
  ip netns del "$attacker_ns" 2>/dev/null
  ip netns del "$victim_ns" 2>/dev/null
  ip link del "ga-host-$$" 2>/dev/null
  ip link del "gv-host-$$" 2>/dev/null
  sysctl -q -w net.ipv4.ip_forward="$old_forward4" 2>/dev/null
  sysctl -q -w net.ipv6.conf.all.forwarding="$old_forward6" 2>/dev/null
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

ip netns add "$attacker_ns"
ip link add "ga-host-$$" type veth peer name ga-ns
ip link set ga-ns netns "$attacker_ns"
ip link set "ga-host-$$" up
ip -n "$attacker_ns" link set lo up
ip -n "$attacker_ns" link set ga-ns up

if [[ $FAMILY == 4 ]]; then
  host_addr="10.203.$suffix.1"
  attacker_addr="10.203.$suffix.2"
  victim_addr="10.204.$suffix.2"
  ip addr add "$host_addr/24" dev "ga-host-$$"
  ip -n "$attacker_ns" addr add "$attacker_addr/24" dev ga-ns
  ip -n "$attacker_ns" route add default via "$host_addr"
  url_host=$host_addr
else
  host_addr="fd00:203:$suffix::1"
  attacker_addr="fd00:203:$suffix::2"
  victim_addr="fd00:204:$suffix::2"
  ip -6 addr add "$host_addr/64" dev "ga-host-$$"
  ip -n "$attacker_ns" -6 addr add "$attacker_addr/64" dev ga-ns
  ip -n "$attacker_ns" -6 route add default via "$host_addr"
  url_host="[$host_addr]"
fi

if [[ $PATH_MODE == forward ]]; then
  ip netns add "$victim_ns"
  ip link add "gv-host-$$" type veth peer name gv-ns
  ip link set gv-ns netns "$victim_ns"
  ip link set "gv-host-$$" up
  ip -n "$victim_ns" link set lo up
  ip -n "$victim_ns" link set gv-ns up
  if [[ $FAMILY == 4 ]]; then
    victim_gw="10.204.$suffix.1"
    ip addr add "$victim_gw/24" dev "gv-host-$$"
    ip -n "$victim_ns" addr add "$victim_addr/24" dev gv-ns
    ip -n "$victim_ns" route add default via "$victim_gw"
    sysctl -q -w net.ipv4.ip_forward=1
    url_host=$victim_addr
  else
    victim_gw="fd00:204:$suffix::1"
    ip -6 addr add "$victim_gw/64" dev "gv-host-$$"
    ip -n "$victim_ns" -6 addr add "$victim_addr/64" dev gv-ns
    ip -n "$victim_ns" -6 route add default via "$victim_gw"
    sysctl -q -w net.ipv6.conf.all.forwarding=1
    url_host="[$victim_addr]"
  fi
  ip netns exec "$victim_ns" python3 -m http.server 18080 --bind "$victim_addr" >"$tmp/http.log" 2>&1 &
  server_pid=$!
else
  python3 -m http.server 18080 --bind "$host_addr" >"$tmp/http.log" 2>&1 &
  server_pid=$!
fi

cat >"$tmp/goban.yaml" <<CFG
log_level: debug
sock_path: $tmp/goban.sock
socket_mode: 0600
socket_group: ""
allowlist: [127.0.0.0/8, "::1/128"]
defaults: {max_retries: 3, findtime: 1m, bantime: 2m}
sources:
  - type: file
    name: auth
    path: $tmp/auth.log
rules:
  - name: integration-sshd
    source: auth
    regex: 'Failed password for root from (?P<ip>\S+) port'
    max_retries: 3
    findtime: 1m
    bantime: 2m
replay_on_start: false
flush_on_exit: true
ipv6: true
ipset_name_v4: goban-it-v4-$suffix
ipset_name_v6: goban-it-v6-$suffix
batch_bans: false
audit_log: $tmp/audit.log
state_path: $tmp/state.gob
state_save_interval: 1s
enforcer:
  mode: split
  socket_path: $tmp/enforcer.sock
  allowed_user: nobody
  reconcile_interval: 1s
banner:
  backend: $BACKEND
  iptables_chains: [INPUT, FORWARD]
  table: goban_it_$suffix
  set_v4: ban_v4
  set_v6: ban_v6
  chain: input
  forward_chain: forward
CFG
cp "$tmp/goban.yaml" "$tmp/enforcer.yaml"
: >"$tmp/auth.log"
detector_gid=$(id -g nobody)
chmod 0770 "$tmp"
chown nobody:"$detector_gid" "$tmp"
chown nobody:"$detector_gid" "${tmp}/auth.log"

# Launch the helper as a distinct non-root identity with exactly one effective
# capability. Its primary group matches the detector's group so the filesystem
# allows the 0660 Unix-socket connection; SO_PEERCRED still restricts the
# protocol to the detector UID itself.
helper_uid=1
start_enforcer() {
  rm -f "$tmp/enforcer.sock"
  setpriv --reuid="$helper_uid" --regid="$detector_gid" --clear-groups \
    --bounding-set=-all,+net_admin --inh-caps=+net_admin --ambient-caps=+net_admin --nnp \
    "$ENFORCER" --config "$tmp/enforcer.yaml" >"$tmp/enforcer.log" 2>&1 &
  enforcer_pid=$!
  for _ in $(seq 1 100); do [[ -S $tmp/enforcer.sock ]] && break; sleep 0.05; done
  [[ -S $tmp/enforcer.sock ]] || { cat "$tmp/enforcer.log"; echo "enforcer did not start" >&2; exit 1; }
  [[ $(awk '/^Uid:/{print $2}' "/proc/$enforcer_pid/status") == "$helper_uid" ]] || { echo "enforcer unexpectedly runs as root" >&2; exit 1; }
  for field in CapEff CapBnd CapAmb; do
    [[ $(awk -v f="$field:" '$1==f{print $2}' "/proc/$enforcer_pid/status") == 0000000000001000 ]] || {
      echo "enforcer $field is not exactly CAP_NET_ADMIN" >&2
      grep -E '^(Uid|Gid|CapEff|CapBnd|CapAmb|NoNewPrivs):' "/proc/$enforcer_pid/status" >&2 || true
      exit 1
    }
  done
  [[ $(awk '/^NoNewPrivs:/{print $2}' "/proc/$enforcer_pid/status") == 1 ]] || { echo "enforcer NoNewPrivs is not set" >&2; exit 1; }
}
start_enforcer

# The socket mode is the first barrier and SO_PEERCRED is the independent
# second barrier. Deliberately loosen the file mode and prove another UID still
# cannot reach the HTTP protocol.
[[ $(stat -c %a "$tmp/enforcer.sock") == 660 ]] || { echo "enforcer socket is not mode 0660" >&2; exit 1; }
[[ $(stat -c %u "$tmp/enforcer.sock") == "$helper_uid" ]] || { echo "enforcer socket is not owned by helper UID" >&2; exit 1; }
[[ $(stat -c %g "$tmp/enforcer.sock") == "$detector_gid" ]] || { echo "enforcer socket is not in detector group" >&2; exit 1; }
chmod 0666 "$tmp/enforcer.sock"
unauthorized_uid=2
if ! setpriv --reuid="$unauthorized_uid" --regid="$detector_gid" --clear-groups python3 - "$tmp/enforcer.sock" <<'PYEOF'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.settimeout(2)
    s.connect(sys.argv[1])
    try:
        s.sendall(b"GET /v1/health HTTP/1.1\r\nHost: enforcer\r\nConnection: close\r\n\r\n")
        data = s.recv(256)
    except (BrokenPipeError, ConnectionResetError, OSError):
        data = b""
finally:
    s.close()
sys.exit(1 if b" 200 " in data else 0)
PYEOF
then
  echo "unauthorized UID reached the enforcer protocol despite SO_PEERCRED" >&2
  exit 1
fi
chmod 0660 "$tmp/enforcer.sock"

# The parser/rule process must be genuinely unprivileged with no effective
# capabilities; packet enforcement still has to succeed through the helper.
setpriv --reuid="$(id -u nobody)" --regid="$(id -g nobody)" --clear-groups \
  --bounding-set=-all --inh-caps=-all --ambient-caps=-all --nnp \
  "$DAEMON" --config "$tmp/goban.yaml" >"$tmp/daemon.log" 2>&1 &
daemon_pid=$!
for _ in $(seq 1 100); do [[ -S $tmp/goban.sock ]] && break; sleep 0.05; done
[[ -S $tmp/goban.sock ]] || { cat "$tmp/daemon.log" "$tmp/enforcer.log"; echo "daemon did not start" >&2; exit 1; }
[[ $(awk '/^Uid:/{print $2}' "/proc/$daemon_pid/status") != 0 ]] || { echo "daemon unexpectedly runs as root" >&2; exit 1; }
for field in CapEff CapBnd CapAmb; do
  [[ $(awk -v f="$field:" '$1==f{print $2}' "/proc/$daemon_pid/status") == 0000000000000000 ]] || { echo "daemon $field is not zero" >&2; exit 1; }
done
[[ $(awk '/^NoNewPrivs:/{print $2}' "/proc/$daemon_pid/status") == 1 ]] || { echo "daemon NoNewPrivs is not set" >&2; exit 1; }

# Prove policy reload is a two-process transaction. Change the detector's
# root-managed config (allowlist + threshold) while leaving the helper's copy
# stale. SIGHUP must fail closed and retain the old threshold=3 graph. Once the
# helper receives the same root-managed config, the same SIGHUP must cut over
# to threshold=4.
python3 - "$tmp/goban.yaml" <<'PYRELOAD'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text()
s = s.replace('allowlist: [127.0.0.0/8, "::1/128"]', 'allowlist: [127.0.0.0/8, "::1/128", 198.51.100.200/32]', 1)
s = s.replace('    max_retries: 3\n    findtime: 1m\n    bantime: 2m', '    max_retries: 4\n    findtime: 1m\n    bantime: 2m', 1)
p.write_text(s)
PYRELOAD
if "$CLIENT" --sock "$tmp/goban.sock" reload >"$tmp/reload-mismatch.log" 2>&1; then
  cat "$tmp/reload-mismatch.log" >&2
  echo "split-policy mismatch was unexpectedly accepted" >&2
  exit 1
fi
kill -0 "$daemon_pid" || { echo "daemon exited after rejected split-policy reload" >&2; exit 1; }
reload_rejected_ip=192.0.2.210
for port in 52001 52002 52003; do
  printf 'sshd[1]: Failed password for root from %s port %s ssh2\n' "$reload_rejected_ip" "$port" >>"$tmp/auth.log"
done
for _ in $(seq 1 100); do
  "$CLIENT" --sock "$tmp/goban.sock" --json list 2>/dev/null | grep -Fq "\"$reload_rejected_ip\"" && break
  sleep 0.05
done
"$CLIENT" --sock "$tmp/goban.sock" --json list | grep -Fq "\"$reload_rejected_ip\"" || {
  cat "$tmp/daemon.log" "$tmp/enforcer.log" >&2
  echo "rejected policy reload did not preserve old threshold=3 graph" >&2
  exit 1
}
"$CLIENT" --sock "$tmp/goban.sock" unban "$reload_rejected_ip" >/dev/null

cp "$tmp/goban.yaml" "$tmp/enforcer.yaml"
"$CLIENT" --sock "$tmp/goban.sock" reload >"$tmp/reload-applied.log" 2>&1 || {
  cat "$tmp/reload-applied.log" "$tmp/daemon.log" "$tmp/enforcer.log" >&2
  echo "synchronized split-policy reload failed" >&2
  exit 1
}
reload_applied_ip=192.0.2.211
for port in 52101 52102 52103; do
  printf 'sshd[1]: Failed password for root from %s port %s ssh2\n' "$reload_applied_ip" "$port" >>"$tmp/auth.log"
done
sleep 0.75
if "$CLIENT" --sock "$tmp/goban.sock" --json list | grep -Fq "\"$reload_applied_ip\""; then
  cat "$tmp/daemon.log" >&2
  echo "successful split-policy reload did not apply new threshold=4 graph" >&2
  exit 1
fi
printf 'sshd[1]: Failed password for root from %s port 52104 ssh2\n' "$reload_applied_ip" >>"$tmp/auth.log"
for _ in $(seq 1 100); do
  "$CLIENT" --sock "$tmp/goban.sock" --json list 2>/dev/null | grep -Fq "\"$reload_applied_ip\"" && break
  sleep 0.05
done
"$CLIENT" --sock "$tmp/goban.sock" --json list | grep -Fq "\"$reload_applied_ip\"" || {
  cat "$tmp/daemon.log" "$tmp/enforcer.log" >&2
  echo "synchronized policy reload did not apply new threshold=4 graph" >&2
  exit 1
}
"$CLIENT" --sock "$tmp/goban.sock" unban "$reload_applied_ip" >/dev/null

curl_cmd=(curl --noproxy '*' -fsS --connect-timeout 2 "http://$url_host:18080/")
ip netns exec "$attacker_ns" "${curl_cmd[@]}" >/dev/null || { cat "$tmp/http.log"; echo "pre-ban connectivity failed" >&2; exit 1; }

for port in 51001 51002 51003 51004; do
  printf 'sshd[1]: Failed password for root from %s port %s ssh2\n' "$attacker_addr" "$port" >>"$tmp/auth.log"
done

banned=false
for _ in $(seq 1 100); do
  if "$CLIENT" --sock "$tmp/goban.sock" --json list 2>/dev/null | grep -Fq "\"$attacker_addr\""; then banned=true; break; fi
  sleep 0.05
done
$banned || { cat "$tmp/daemon.log"; echo "decision was not applied" >&2; exit 1; }

if ip netns exec "$attacker_ns" "${curl_cmd[@]}" >/dev/null 2>&1; then
  echo "FAIL: $BACKEND/$PATH_MODE/IPv$FAMILY reported a ban but traffic still passed" >&2
  "$CLIENT" --sock "$tmp/goban.sock" explain "$attacker_addr" || true
  exit 1
fi

# Simulate an external firewall manager deleting GoBan's packet-path hook. The
# helper must detect the drift, restore only its owned objects, preserve the
# active decision, and block the attacker again without restarting either
# process.
if [[ $BACKEND == iptables ]]; then
  hook_chain=INPUT; [[ $PATH_MODE == forward ]] && hook_chain=FORWARD
  hook_bin=iptables; hook_set="goban-it-v4-$suffix"
  if [[ $FAMILY == 6 ]]; then hook_bin=ip6tables; hook_set="goban-it-v6-$suffix"; fi
  "$hook_bin" -D "$hook_chain" -m set --match-set "$hook_set" src -j DROP
else
  nft flush chain inet "goban_it_$suffix" "$PATH_MODE"
fi
repaired=false
for _ in $(seq 1 120); do
  health=$(curl --silent --unix-socket "$tmp/enforcer.sock" http://localhost/v1/health || true)
  if python3 - "$health" <<'PYREPAIR' >/dev/null 2>&1
import json,sys
try: d=json.loads(sys.argv[1])
except Exception: raise SystemExit(1)
raise SystemExit(0 if d.get('repair_count',0) >= 1 and not d.get('last_repair_error') else 1)
PYREPAIR
  then
    if ! ip netns exec "$attacker_ns" "${curl_cmd[@]}" >/dev/null 2>&1; then repaired=true; break; fi
  fi
  sleep 0.05
done
$repaired || { cat "$tmp/enforcer.log" >&2; echo "automatic firewall drift repair did not restore enforcement" >&2; exit 1; }
"$CLIENT" --sock "$tmp/goban.sock" --json list | grep -Fq ""$attacker_addr"" || { echo "drift repair lost active ban metadata" >&2; exit 1; }

"$CLIENT" --sock "$tmp/goban.sock" doctor --probe --probe-ip "${GOBAN_PROBE_IP:-192.0.2.254}" >/dev/null
"$CLIENT" --sock "$tmp/goban.sock" explain "$attacker_addr"

# Verify that a repeated decision refreshes the kernel timeout while this
# backend's real test daemon/socket are still alive. This used to be invoked
# from matrix.sh after run.sh had already torn the socket down, so the claimed
# TTL gate could not execute correctly.
GOBAN_CLIENT="$CLIENT" test/integration/kernel/ttl-refresh.sh "$tmp/goban.sock" 192.0.2.240

# Crash only the privileged helper. The detector remains alive with zero caps.
# A fresh helper starts unready; the next decision must trigger idempotent setup
# and retry once without restarting or re-privileging the detector.
kill -KILL "$enforcer_pid"
wait "$enforcer_pid" 2>/dev/null || true
enforcer_pid=""
start_enforcer
restart_probe=192.0.2.241
"$CLIENT" --sock "$tmp/goban.sock" ban "$restart_probe" --rule helper-restart --ttl 1m >/dev/null
"$CLIENT" --sock "$tmp/goban.sock" --json list | grep -Fq "\"$restart_probe\"" || {
  cat "$tmp/daemon.log" "$tmp/enforcer.log" >&2
  echo "detector did not recover a restarted enforcer" >&2
  exit 1
}
"$CLIENT" --sock "$tmp/goban.sock" unban "$restart_probe" >/dev/null
for field in CapEff CapBnd CapAmb; do
  [[ $(awk -v f="$field:" '$1==f{print $2}' "/proc/$daemon_pid/status") == 0000000000000000 ]] || { echo "detector $field changed after helper recovery" >&2; exit 1; }
done

echo "PASS: $BACKEND $PATH_MODE IPv$FAMILY split enforcement + peer auth + transactional reload + drift self-heal + helper recovery + TTL refresh"
