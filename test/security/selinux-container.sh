#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
command -v docker >/dev/null || { echo "docker is required" >&2; exit 77; }
docker run --rm -v "$ROOT_DIR:/src:ro" fedora:43 bash -lc '
  set -Eeuo pipefail
  dnf -q -y install make selinux-policy-devel selinux-policy-targeted >/dev/null
  tmp=$(mktemp -d)
  cp /src/deploy/selinux/goban.te /src/deploy/selinux/goban.fc "$tmp/"
  make -s -C "$tmp" -f /usr/share/selinux/devel/Makefile goban.pp
  test -s "$tmp/goban.pp"
'
echo "PASS: SELinux policy compiled in Fedora container"
