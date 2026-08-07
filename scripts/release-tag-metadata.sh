#!/usr/bin/env bash
# Validate a GoBan release tag and emit GitHub-output-compatible metadata.
#
# Usage:
#   scripts/release-tag-metadata.sh v1.0.0
#   scripts/release-tag-metadata.sh v1.0.0-rc.1
#
# Output:
#   version=1.0.0[-...]
#   prerelease=true|false
#   channel=stable|prerelease
set -euo pipefail

tag="${1:-}"
if [[ -z "$tag" ]]; then
  echo "usage: $0 vMAJOR.MINOR.PATCH[-PRERELEASE]" >&2
  exit 2
fi

# Deliberately disallow semver build metadata (+foo). '+' is valid semver but
# is not a portable container-tag character and GoBan uses one Git tag to name
# GitHub, package, and GHCR release artifacts.
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]]; then
  echo "invalid GoBan release tag: $tag" >&2
  echo "expected vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-PRERELEASE" >&2
  exit 2
fi

version="${tag#v}"
if [[ "$version" == *-* ]]; then
  prerelease=true
  channel=prerelease
else
  prerelease=false
  channel=stable
fi

printf 'version=%s\nprerelease=%s\nchannel=%s\n' "$version" "$prerelease" "$channel"
