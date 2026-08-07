#!/usr/bin/env bash
set -Eeuo pipefail
# Requires a running test daemon/socket. Verifies that a repeated decision
# refreshes, rather than merely preserving, the original kernel timeout.
SOCK=${1:?usage: ttl-refresh.sh /path/to/goban.sock [ip]}
IP=${2:-192.0.2.240}
CLIENT=${GOBAN_CLIENT:-goban-client}
$CLIENT --sock "$SOCK" ban "$IP" --rule ttl-refresh --ttl 12s
sleep 5
$CLIENT --sock "$SOCK" ban "$IP" --rule ttl-refresh --ttl 12s
json=$($CLIENT --sock "$SOCK" --json list)
python3 - "$IP" "$json" <<'PY'
import json,sys
ip=sys.argv[1]; bans=json.loads(sys.argv[2])
item=next((x for x in bans if x['ip']==ip),None)
if not item: raise SystemExit('refreshed ban not found')
# time.Duration is encoded as integer nanoseconds in the control JSON.
if item.get('ttl',0) < 8_000_000_000:
    raise SystemExit(f"TTL did not refresh: {item.get('ttl')}")
print('PASS: repeated ban refreshed TTL')
PY
$CLIENT --sock "$SOCK" unban "$IP"
