#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"
VERSION=${VERSION:-reproducible-test}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

build_once() {
  local out=$1
  mkdir -p "$out"
  for cmd in goban-daemon goban-client goban-corpus goban-soak; do
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$VERSION" \
      -o "$out/$cmd" "./cmd/$cmd"
  done
}

build_once "$TMP/a"
build_once "$TMP/b"
for file in "$TMP"/a/*; do
  name=$(basename "$file")
  cmp "$TMP/a/$name" "$TMP/b/$name" >/dev/null || {
    echo "NON-REPRODUCIBLE: $name" >&2
    sha256sum "$TMP/a/$name" "$TMP/b/$name" >&2
    exit 1
  }
done
echo "PASS: reproducible static linux/amd64 binaries"
