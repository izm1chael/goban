#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"
OUT=${1:-dist/release-evidence}
mkdir -p "$OUT"
{
  echo "generated_at=$(date -u +%FT%TZ)"
  echo "git_commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "go_version=$(go version)"
  echo "kernel=$(uname -srmo)"
} > "$OUT/environment.txt"

go version -m bin/goban-daemon > "$OUT/goban-daemon-buildinfo.txt" 2>/dev/null || true
sha256sum bin/goban-* > "$OUT/SHA256SUMS" 2>/dev/null || true
cp docs/RELEASE_CHECKLIST.md docs/THREAT_MODEL.md docs/EXTERNAL_REVIEW.md "$OUT/" 2>/dev/null || true
if [[ -n ${GOBAN_SOAK_RUN:-} ]]; then
  cp "$GOBAN_SOAK_RUN"/report.json "$GOBAN_SOAK_RUN"/report.md "$OUT/" 2>/dev/null || {
    echo "GOBAN_SOAK_RUN did not contain report.json/report.md" >&2
    exit 1
  }
fi
if [[ -f .cache/goban-corpus/FETCHED.json ]]; then
  cp .cache/goban-corpus/FETCHED.json "$OUT/corpus-FETCHED.json"
fi

echo "Release evidence written to $OUT"
