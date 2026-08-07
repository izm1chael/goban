#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT_DIR"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
# Report aggregation is unit-tested. This smoke gate checks CLI lifecycle and
# expected failure visibility against an absent daemon socket.
set +e
bin/goban-soak start --foreground --duration 2s --interval 1s --sock "$TMP/missing.sock" --out "$TMP/run"
rc=$?
set -e
[[ $rc -eq 0 ]] || { echo "soak runner failed unexpectedly" >&2; exit 1; }
test -f "$TMP/run/report.json"
grep -q '"verdict": "FAIL"' "$TMP/run/report.json"
echo "PASS: soak lifecycle and failure report"
