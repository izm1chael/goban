#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
cd "$ROOT_DIR"
for cmd in docker nfpm; do command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 77; }; done

make clean package VERSION="${VERSION:-1.0.0-rc1}"
deb=$(find dist -maxdepth 1 -name '*.deb' -print -quit)
rpm=$(find dist -maxdepth 1 -name '*.rpm' -print -quit)
arch=$(find dist -maxdepth 1 -name '*.pkg.tar.zst' -print -quit)
[[ -n $deb && -n $rpm && -n $arch ]] || { echo "missing package artifacts" >&2; ls -la dist; exit 1; }

abs_deb=$(readlink -f "$deb")
abs_rpm=$(readlink -f "$rpm")
abs_arch=$(readlink -f "$arch")

docker run --rm -v "$abs_deb:/tmp/goban.deb:ro" debian:bookworm-slim bash -euxc '
  apt-get update -qq
  apt-get install -y /tmp/goban.deb
  goban-daemon --version
  goban-client config validate --config /etc/goban/goban.yaml
  test -f /usr/share/goban/rules-available/sshd.yaml
  test -f /etc/goban/rules.d/sshd.yaml
  test -f /etc/goban/rules.d/recidive.yaml
  test "$(stat -c %a /etc/goban/goban.yaml)" -le 640
'

docker run --rm -v "$abs_rpm:/tmp/goban.rpm:ro" rockylinux:9 bash -euxc '
  dnf install -y /tmp/goban.rpm
  goban-daemon --version
  goban-client config validate --config /etc/goban/goban.yaml
  test -f /usr/share/goban/rules-available/sshd.yaml
  test -f /etc/goban/rules.d/sshd.yaml
'

docker run --rm -v "$abs_arch:/tmp/goban.pkg.tar.zst:ro" archlinux:base bash -euxc '
  pacman -Sy --noconfirm
  pacman -U --noconfirm /tmp/goban.pkg.tar.zst
  goban-daemon --version
  goban-client config validate --config /etc/goban/goban.yaml
  test -f /usr/share/goban/rules-available/sshd.yaml
  test -f /etc/goban/rules.d/sshd.yaml
'

echo "PASS: deb, rpm, and Arch packages install and validate"
