SHELL := /bin/bash
BIN_DIR := bin
DIST_DIR := dist
DAEMON := $(BIN_DIR)/goban-daemon
CLIENT := $(BIN_DIR)/goban-client
CORPUS := $(BIN_DIR)/goban-corpus
SOAK := $(BIN_DIR)/goban-soak
PKGS := ./...
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)
ARCH    ?= amd64
export ARCH

.PHONY: all build build-journald version-smoke corpus corpus-generate corpus-external fuzz-short soak-smoke test-adoption reproducible test test-race vet lint verify-release test-fault test-reload test-kernel package-smoke package-hooks package-binaries-check docker-build docker-build-journald clean tidy package package-deb package-rpm package-apk package-arch man

all: build

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DAEMON) ./cmd/goban-daemon
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(CLIENT) ./cmd/goban-client
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(CORPUS) ./cmd/goban-corpus
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(SOAK) ./cmd/goban-soak

build-journald:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=1 go build -trimpath -tags=journald -ldflags="$(LDFLAGS)" -o $(DAEMON) ./cmd/goban-daemon
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(CLIENT) ./cmd/goban-client
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(CORPUS) ./cmd/goban-corpus
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(SOAK) ./cmd/goban-soak

version-smoke:
	$(MAKE) build VERSION=version-smoke
	@test "$$($(DAEMON) --version)" = "version-smoke"
	@test "$$($(CLIENT) version)" = "version-smoke"
	@test "$$($(CORPUS) version)" = "version-smoke"
	@test "$$($(SOAK) version)" = "version-smoke"

test:
	go test $(PKGS)

test-race:
	go test -race $(PKGS)

corpus:
	go run ./cmd/goban-corpus test

corpus-generate:
	test/corpus/generate.sh

corpus-external:
	test/corpus/external.sh

fuzz-short:
	go test ./internal/matcher -run '^$$' -fuzz FuzzMatcherNeverPanics -fuzztime 20s

vet:
	go vet $(PKGS)

lint:
	golangci-lint run

# Non-privileged release gate. Kernel and package verification remain separate
# because they need root/network namespaces and container/package tooling.
verify-release: vet test-race corpus reproducible soak-smoke test-adoption version-smoke package-hooks
	@test -z "$$(gofmt -l cmd internal benchmark)" || { echo "gofmt required:"; gofmt -l cmd internal benchmark; exit 1; }
	bash -n test/corpus/run.sh test/migration/run.sh test/setup/run.sh test/soak/smoke.sh scripts/reproducible-build.sh scripts/release-evidence.sh test/corpus/generate.sh test/corpus/external.sh test/integration/kernel/run.sh test/integration/kernel/ttl-refresh.sh test/integration/kernel/matrix.sh test/integration/reload/run.sh test/integration/package/run.sh test/integration/package/upgrade.sh test/integration/package/hooks.sh test/fault/run.sh
	go test -run TestCoreRuleFixtures ./internal/config

soak-smoke: build
	test/soak/smoke.sh

test-adoption: build
	test/migration/run.sh
	test/setup/run.sh

reproducible:
	scripts/reproducible-build.sh

# Extended lifecycle/fault repetition.
test-fault: build
	test/fault/run.sh

# End-to-end, unprivileged transactional reload stress.
test-reload: build
	test/integration/reload/run.sh

# Representative privileged kernel paths; run as root on a disposable VM.
test-kernel: build
	test/integration/kernel/run.sh iptables input 4
	test/integration/kernel/run.sh nftables forward 4

package-smoke:
	test/integration/package/run.sh

package-hooks:
	test/integration/package/hooks.sh

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
	@gzip -fk man/goban-soak.1
	@echo "man pages → daemon, client, and soak pages"

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
package:
	@test "$(VERSION)" != "dev" || { echo "VERSION must be set for packages (for example: make package VERSION=1.0.0-rc3)" >&2; exit 2; }
	$(MAKE) build VERSION=$(VERSION)
	$(MAKE) man
	$(MAKE) package-deb VERSION=$(VERSION)
	$(MAKE) package-rpm VERSION=$(VERSION)
	$(MAKE) package-arch VERSION=$(VERSION)

package-binaries-check:
	@test "$(VERSION)" != "dev" || { echo "VERSION must be set for package artifacts" >&2; exit 2; }
	@test -x "$(DAEMON)" -a -x "$(CLIENT)" -a -x "$(CORPUS)" -a -x "$(SOAK)" || { echo "package binaries are missing; run make build VERSION=$(VERSION)" >&2; exit 2; }
	@test "$$($(DAEMON) --version)" = "$(VERSION)" || { echo "$(DAEMON) does not report VERSION=$(VERSION)" >&2; exit 2; }
	@test "$$($(CLIENT) version)" = "$(VERSION)" || { echo "$(CLIENT) does not report VERSION=$(VERSION)" >&2; exit 2; }
	@test "$$($(CORPUS) version)" = "$(VERSION)" || { echo "$(CORPUS) does not report VERSION=$(VERSION)" >&2; exit 2; }
	@test "$$($(SOAK) version)" = "$(VERSION)" || { echo "$(SOAK) does not report VERSION=$(VERSION)" >&2; exit 2; }

package-deb: package-binaries-check
	@mkdir -p $(DIST_DIR)
	cd packaging && VERSION=$(VERSION) nfpm pkg --packager deb --config nfpm.yaml --target ../$(DIST_DIR)/

package-rpm: package-binaries-check
	@mkdir -p $(DIST_DIR)
	cd packaging && VERSION=$(VERSION) nfpm pkg --packager rpm --config nfpm.yaml --target ../$(DIST_DIR)/

package-apk: package-binaries-check
	@mkdir -p $(DIST_DIR)
	cd packaging && VERSION=$(VERSION) nfpm pkg --packager apk --config nfpm.yaml --target ../$(DIST_DIR)/

# Arch Linux .pkg.tar.zst, generated natively by nfpm — no makepkg / PKGBUILD
# required at build time. Maintainers who want this in AUR can still wrap the
# package in a PKGBUILD that just downloads + repackages, but for users who
# `pacman -U` the artifact directly this is the simplest path.
package-arch: package-binaries-check
	@mkdir -p $(DIST_DIR)
	cd packaging && VERSION=$(VERSION) nfpm pkg --packager archlinux --config nfpm.yaml --target ../$(DIST_DIR)/
