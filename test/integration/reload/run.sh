#!/usr/bin/env bash
set -Eeuo pipefail

# Unprivileged reload cutover stress. Every synthetic address emits exactly one
# threshold's worth of events while identical candidate graphs are repeatedly
# started and swapped. The audit stream must contain exactly one decision per
# address: fewer means loss, more means duplicate processing.
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
DAEMON=${GOBAN_DAEMON:-$ROOT_DIR/bin/goban-daemon}
CLIENT=${GOBAN_CLIENT:-$ROOT_DIR/bin/goban-client}
[[ -x $DAEMON && -x $CLIENT ]] || (cd "$ROOT_DIR" && make build)

tmp=$(mktemp -d)
daemon_pid=""
cleanup() {
  set +e
  [[ -n $daemon_pid ]] && kill -TERM "$daemon_pid" 2>/dev/null
  [[ -n $daemon_pid ]] && wait "$daemon_pid" 2>/dev/null
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

write_valid_config() {
cat >"$tmp/goban.yaml.new" <<CFG
log_level: debug
sock_path: $tmp/goban.sock
socket_mode: 0600
socket_group: ""
allowlist: [127.0.0.0/8, "::1/128"]
defaults: {max_retries: 3, findtime: 5m, bantime: 10m}
sources:
  - type: file
    name: auth
    path: $tmp/auth.log
rules:
  - name: reload-stress
    source: auth
    regex: 'Failed password from (?P<ip>\S+)'
    max_retries: 3
    findtime: 5m
    bantime: 10m
rules_dir: ""
replay_on_start: false
flush_on_exit: true
ipv6: true
dry_run: true
batch_bans: false
audit_log: $tmp/audit.log
state_path: $tmp/state.gob
state_save_interval: 1s
banner:
  backend: iptables
  iptables_chains: [INPUT, FORWARD]
CFG
mv "$tmp/goban.yaml.new" "$tmp/goban.yaml"
}

: >"$tmp/auth.log"
write_valid_config
"$DAEMON" --config "$tmp/goban.yaml" --log-level error >"$tmp/daemon.log" 2>&1 &
daemon_pid=$!
for _ in $(seq 1 100); do [[ -S $tmp/goban.sock ]] && break; sleep 0.05; done
[[ -S $tmp/goban.sock ]] || { cat "$tmp/daemon.log"; exit 1; }

python3 - "$tmp/auth.log" <<'PY' &
import sys,time
path=sys.argv[1]
with open(path,'a',buffering=1) as f:
    for host in range(1,41):
        ip=f"198.51.100.{host}"
        for _ in range(3):
            f.write(f"Failed password from {ip}\n")
            time.sleep(0.004)
PY
writer_pid=$!

for _ in $(seq 1 25); do
  "$CLIENT" --sock "$tmp/goban.sock" reload >/dev/null
  sleep 0.01
done
wait "$writer_pid"

# Allow the final source queue to drain.
for _ in $(seq 1 100); do
  count=$(grep -c '"action":"ban"' "$tmp/audit.log" 2>/dev/null || true)
  [[ $count -ge 40 ]] && break
  sleep 0.05
done

python3 - "$tmp/audit.log" <<'PY'
import json,sys,collections
items=[]
with open(sys.argv[1]) as f:
    for line in f:
        e=json.loads(line)
        if e.get('action')=='ban' and e.get('rule')=='reload-stress': items.append(e)
counts=collections.Counter(e['ip'] for e in items)
expected={f"198.51.100.{i}" for i in range(1,41)}
missing=sorted(expected-counts.keys())
duplicated=sorted(ip for ip,n in counts.items() if n != 1)
if missing or duplicated or len(items)!=40:
    raise SystemExit(f"reload cutover mismatch: decisions={len(items)} missing={missing} non_single={[(x,counts[x]) for x in duplicated]}")
print('PASS: reload cutover preserved exactly-once thresholds for 40 addresses')
PY

# Invalid candidate must fail without stopping the active graph.
cp "$tmp/goban.yaml" "$tmp/goban.valid"
python3 - "$tmp/goban.yaml" <<'PY'
import sys
p=sys.argv[1]
s=open(p).read().replace('source: auth\n    regex:', 'source: missing-source\n    regex:', 1)
open(p+'.new','w').write(s)
PY
mv "$tmp/goban.yaml.new" "$tmp/goban.yaml"
if "$CLIENT" --sock "$tmp/goban.sock" reload >/dev/null 2>&1; then
  echo "invalid reload unexpectedly succeeded" >&2
  exit 1
fi
mv "$tmp/goban.valid" "$tmp/goban.yaml"
for _ in 1 2 3; do echo 'Failed password from 203.0.113.200' >>"$tmp/auth.log"; done
for _ in $(seq 1 100); do
  grep -q '"ip":"203.0.113.200"' "$tmp/audit.log" 2>/dev/null && break
  sleep 0.05
done
grep -q '"ip":"203.0.113.200"' "$tmp/audit.log" || { cat "$tmp/daemon.log"; echo "active graph stopped after invalid reload" >&2; exit 1; }
echo "PASS: invalid candidate left active graph processing"
