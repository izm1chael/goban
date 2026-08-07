#!/usr/bin/env bash
# Flatten and validate GoBan release artifacts before checksum/signature/upload.
#
# Usage:
#   stage-release-assets.sh PACKAGE_ROOT DOCKER_REF_FILE OUT TAG VERSION CHANNEL COMMIT
set -euo pipefail

if (( $# != 7 )); then
  echo "usage: $0 PACKAGE_ROOT DOCKER_REF_FILE OUT TAG VERSION CHANNEL COMMIT" >&2
  exit 2
fi

packages_root=$1
docker_ref_file=$2
out=$3
tag=$4
version=$5
channel=$6
commit=$7

[[ -d "$packages_root/dist" ]] || { echo "missing package dist directory: $packages_root/dist" >&2; exit 1; }
[[ -f "$docker_ref_file" ]] || { echo "missing Docker reference file: $docker_ref_file" >&2; exit 1; }
[[ "$channel" == stable || "$channel" == prerelease ]] || { echo "invalid release channel: $channel" >&2; exit 2; }

rm -rf "$out"
mkdir -p "$out"

duplicates="$({
  find "$packages_root/dist" -maxdepth 1 -type f -printf '%f\n'
  find "$packages_root" -maxdepth 1 -type f -name 'goban-*' -printf '%f\n'
  printf '%s\n' "$(basename "$docker_ref_file")"
} | sort | uniq -d)"
if [[ -n "$duplicates" ]]; then
  echo "duplicate public release asset basenames:" >&2
  echo "$duplicates" >&2
  exit 1
fi

find "$packages_root/dist" -maxdepth 1 -type f -exec cp -v '{}' "$out/" \;
find "$packages_root" -maxdepth 1 -type f -name 'goban-*' -exec cp -v '{}' "$out/" \;
cp -v "$docker_ref_file" "$out/"

for arch in amd64 arm64; do
  for binary in goban-daemon goban-enforcer goban-client goban-corpus goban-soak; do
    [[ -f "$out/${binary}-linux-${arch}" ]] || {
      echo "missing release binary: ${binary}-linux-${arch}" >&2
      exit 1
    }
  done
done

shopt -s nullglob
debs=("$out"/*.deb)
rpms=("$out"/*.rpm)
archpkgs=("$out"/*.pkg.tar.zst)
sboms=("$out"/*.spdx.json)
(( ${#debs[@]} >= 2 )) || { echo 'expected at least two Debian packages' >&2; exit 1; }
(( ${#rpms[@]} >= 2 )) || { echo 'expected at least two RPM packages' >&2; exit 1; }
(( ${#archpkgs[@]} >= 2 )) || { echo 'expected at least two Arch packages' >&2; exit 1; }
(( ${#sboms[@]} >= 2 )) || { echo 'expected at least two SPDX SBOMs' >&2; exit 1; }

cat > "$out/RELEASE-MANIFEST.txt" <<EOF2
GoBan release: $tag
Version: $version
Channel: $channel
Commit: $commit
Docker: $(cat "$docker_ref_file")
EOF2

(
  cd "$out"
  find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' -printf '%f\0' \
    | sort -z \
    | xargs -0 sha256sum > SHA256SUMS
  sha256sum -c SHA256SUMS
)

echo "release assets staged: $out"
