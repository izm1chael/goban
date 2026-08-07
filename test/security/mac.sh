#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT_DIR"

if command -v apparmor_parser >/dev/null 2>&1; then
  apparmor_parser -Q deploy/apparmor/usr.bin.goban-daemon
  apparmor_parser -Q deploy/apparmor/usr.bin.goban-enforcer
  echo "PASS: AppArmor profiles parse"
else
  echo "SKIP: apparmor_parser unavailable"
fi

if [[ -f /usr/share/selinux/devel/Makefile ]]; then
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  cp deploy/selinux/goban.te deploy/selinux/goban.fc "$tmp/"
  make -s -C "$tmp" -f /usr/share/selinux/devel/Makefile goban.pp
  echo "PASS: SELinux policy source compiles"
else
  echo "SKIP: SELinux policy-devel toolchain unavailable; validate on Fedora/RHEL release host"
fi
