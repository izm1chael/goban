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
CLIENT=${GOBAN_CLIENT:-$ROOT_DIR/bin/goban-client}

[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 77; }
[[ $BACKEND == iptables || $BACKEND == nftables ]] || { echo "backend must be iptables or nftables" >&2; exit 2; }
[[ $PATH_MODE == input || $PATH_MODE == forward ]] || { echo "path must be input or forward" >&2; exit 2; }
[[ $FAMILY == 4 || $FAMILY == 6 ]] || { echo "family must be 4 or 6" >&2; exit 2; }
for cmd in ip python3 curl; do command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 77; }; done
if [[ $BACKEND == iptables ]]; then
  for cmd in iptables ipset; do command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 77; }; done
else
  command -v nft >/dev/null || { echo "missing nft" >&2; exit 77; }
fi

if [[ ! -x $DAEMON || ! -x $CLIENT ]]; then
  (cd "$ROOT_DIR" && make build)
fi

suffix=$(( $$ % 200 + 20 ))
attacker_ns="goban-atk-$$"
victim_ns="goban-vic-$$"
tmp=$(mktemp -d)
daemon_pid=""
server_pid=""
old_forward4=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
old_forward6=$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || echo 0)

cleanup() {
  set +e
  [[ -n $daemon_pid ]] && kill -TERM "$daemon_pid" 2>/dev/null
  [[ -n $daemon_pid ]] && wait "$daemon_pid" 2>/dev/null
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
banner:
  backend: $BACKEND
  iptables_chains: [INPUT, FORWARD]
  table: goban_it_$suffix
  set_v4: ban_v4
  set_v6: ban_v6
  chain: input
  forward_chain: forward
CFG
: >"$tmp/auth.log"

"$DAEMON" --config "$tmp/goban.yaml" >"$tmp/daemon.log" 2>&1 &
daemon_pid=$!
for _ in $(seq 1 100); do [[ -S $tmp/goban.sock ]] && break; sleep 0.05; done
[[ -S $tmp/goban.sock ]] || { cat "$tmp/daemon.log"; echo "daemon did not start" >&2; exit 1; }

curl_cmd=(curl --noproxy '*' -fsS --connect-timeout 2 "http://$url_host:18080/")
ip netns exec "$attacker_ns" "${curl_cmd[@]}" >/dev/null || { cat "$tmp/http.log"; echo "pre-ban connectivity failed" >&2; exit 1; }

for port in 51001 51002 51003; do
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

"$CLIENT" --sock "$tmp/goban.sock" doctor --probe --probe-ip "${GOBAN_PROBE_IP:-192.0.2.254}" >/dev/null
"$CLIENT" --sock "$tmp/goban.sock" explain "$attacker_addr"
echo "PASS: $BACKEND $PATH_MODE IPv$FAMILY end-to-end enforcement"
