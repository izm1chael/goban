#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
cd "$ROOT_DIR"
[[ $(id -u) -eq 0 ]] || { echo "run as root on a disposable Linux VM" >&2; exit 77; }
for backend in iptables nftables; do
  for path in input forward; do
    for family in 4 6; do
      echo "=== $backend $path IPv$family ==="
      test/integration/kernel/run.sh "$backend" "$path" "$family"
    done
  done
done
for backend in iptables nftables; do
  test/integration/kernel/ttl-refresh.sh "$backend"
done
echo "PASS: full kernel enforcement and TTL matrix"
