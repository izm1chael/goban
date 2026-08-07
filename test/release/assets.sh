#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/packages/dist" "$tmp/docker"

for arch in amd64 arm64; do
  for binary in goban-daemon goban-enforcer goban-client goban-corpus goban-soak; do
    printf '%s %s\n' "$binary" "$arch" > "$tmp/packages/${binary}-linux-${arch}"
  done
  printf 'deb %s\n' "$arch" > "$tmp/packages/dist/goban_1.0.0_${arch}.deb"
  printf 'rpm %s\n' "$arch" > "$tmp/packages/dist/goban-1.0.0-1.${arch}.rpm"
  printf 'arch %s\n' "$arch" > "$tmp/packages/dist/goban-1.0.0-1-${arch}.pkg.tar.zst"
  printf '{"arch":"%s"}\n' "$arch" > "$tmp/packages/dist/goban-1.0.0-${arch}.spdx.json"
done
printf '%s\n' 'ghcr.io/izm1chael/goban@sha256:0123456789abcdef' > "$tmp/docker/docker-image.txt"

scripts/stage-release-assets.sh \
  "$tmp/packages" "$tmp/docker/docker-image.txt" "$tmp/out" \
  v1.0.0 1.0.0 stable deadbeef

(
  cd "$tmp/out"
  sha256sum -c SHA256SUMS >/dev/null
  ! grep -Eq '(^|[[:space:]])(\./)?dist/' SHA256SUMS
)
grep -Fq 'GoBan release: v1.0.0' "$tmp/out/RELEASE-MANIFEST.txt"
grep -Fq 'Channel: stable' "$tmp/out/RELEASE-MANIFEST.txt"
grep -Fq 'goban-enforcer-linux-amd64' "$tmp/out/SHA256SUMS"
grep -Fq 'goban-enforcer-linux-arm64' "$tmp/out/SHA256SUMS"

# Duplicate basenames must fail before flattening.
printf duplicate > "$tmp/packages/dist/goban-daemon-linux-amd64"
if scripts/stage-release-assets.sh \
  "$tmp/packages" "$tmp/docker/docker-image.txt" "$tmp/dupe" \
  v1.0.0 1.0.0 stable deadbeef >/dev/null 2>&1; then
  echo 'duplicate release basename was not rejected' >&2
  exit 1
fi

echo 'release asset staging: PASS'
