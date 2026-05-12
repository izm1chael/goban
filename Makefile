SHELL := /bin/bash
BIN_DIR := bin
DIST_DIR := dist
DAEMON := $(BIN_DIR)/goban-daemon
CLIENT := $(BIN_DIR)/goban-client
LDFLAGS := -s -w
PKGS := ./...
VERSION ?= 1.0.0
ARCH    ?= amd64
export ARCH

.PHONY: all build build-journald test test-race vet lint docker-build docker-build-journald clean tidy package package-deb package-rpm package-apk package-arch man

all: build

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DAEMON) ./cmd/goban-daemon
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(CLIENT) ./cmd/goban-client

build-journald:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=1 go build -trimpath -tags=journald -ldflags="$(LDFLAGS)" -o $(DAEMON) ./cmd/goban-daemon
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(CLIENT) ./cmd/goban-client

test:
	go test $(PKGS)

test-race:
	go test -race $(PKGS)

vet:
	go vet $(PKGS)

lint:
	golangci-lint run

docker-build:
	docker build -f deploy/Dockerfile -t goban:latest .

docker-build-journald:
	docker build -f deploy/Dockerfile.journald -t goban:journald .

tidy:
	go mod tidy

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)

# Build gzipped man pages from the troff sources in man/. nfpm picks the
# .gz files up via packaging/nfpm.yaml. We gzip in-place rather than into
# DIST_DIR so the relative paths in nfpm.yaml stay stable across local
# `make package` and CI runs.
man:
	@gzip -fk man/goban-daemon.8
	@gzip -fk man/goban-client.1
	@echo "man pages → man/goban-daemon.8.gz, man/goban-client.1.gz"

# Build .deb, .rpm, and .pkg.tar.zst (Arch) via nfpm. Install nfpm with:
#   go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
# Then: make package VERSION=1.2.3
#
# NOTE: package-apk is intentionally NOT in the default `make package` target.
# nfpm-produced .apk files are rejected by current apk-tools as "package file
# format error" on Alpine 3.18+. Alpine users should use the goban:latest
# Docker image, or extract the static binary from a Release artifact directly.
# We still build apk on demand via `make package-apk` so the recipe is
# preserved for when nfpm/apk-tools alignment improves.
package: build man package-deb package-rpm package-arch

package-deb:
	@mkdir -p $(DIST_DIR)
	cd packaging && VERSION=$(VERSION) nfpm pkg --packager deb --config nfpm.yaml --target ../$(DIST_DIR)/

package-rpm:
	@mkdir -p $(DIST_DIR)
	cd packaging && VERSION=$(VERSION) nfpm pkg --packager rpm --config nfpm.yaml --target ../$(DIST_DIR)/

package-apk:
	@mkdir -p $(DIST_DIR)
	cd packaging && VERSION=$(VERSION) nfpm pkg --packager apk --config nfpm.yaml --target ../$(DIST_DIR)/

# Arch Linux .pkg.tar.zst, generated natively by nfpm — no makepkg / PKGBUILD
# required at build time. Maintainers who want this in AUR can still wrap the
# package in a PKGBUILD that just downloads + repackages, but for users who
# `pacman -U` the artifact directly this is the simplest path.
package-arch:
	@mkdir -p $(DIST_DIR)
	cd packaging && VERSION=$(VERSION) nfpm pkg --packager archlinux --config nfpm.yaml --target ../$(DIST_DIR)/
