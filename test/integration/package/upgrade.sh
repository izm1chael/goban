#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
cd "$ROOT_DIR"
for cmd in docker nfpm; do command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 77; }; done
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

make clean package VERSION=1.0.0-rc1
cp "$(find dist -maxdepth 1 -name '*.deb' -print -quit)" "$TMP/goban-v1.deb"
make clean package VERSION=1.0.0-rc2
cp "$(find dist -maxdepth 1 -name '*.deb' -print -quit)" "$TMP/goban-v2.deb"

docker run --rm \
  -v "$TMP/goban-v1.deb:/tmp/goban-v1.deb:ro" \
  -v "$TMP/goban-v2.deb:/tmp/goban-v2.deb:ro" \
  debian:bookworm-slim bash -euxc '
    apt-get update -qq
    apt-get install -y /tmp/goban-v1.deb
    printf "# operator sentinel\n" >> /etc/goban/goban.yaml
    mkdir -p /var/lib/goban /var/log/goban
    printf "state-sentinel" > /var/lib/goban/operator-state
    printf "audit-sentinel" > /var/log/goban/operator-audit
    apt-get install -y /tmp/goban-v2.deb
    grep -q "operator sentinel" /etc/goban/goban.yaml
    grep -q "state-sentinel" /var/lib/goban/operator-state
    grep -q "audit-sentinel" /var/log/goban/operator-audit
    goban-client config validate --config /etc/goban/goban.yaml
    goban-soak version
  '

echo "PASS: Debian upgrade preserves operator configuration and state"
