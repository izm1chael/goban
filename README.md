# GoBan

[![CI](https://github.com/izm1chael/goban/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/izm1chael/goban/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report](https://goreportcard.com/badge/github.com/izm1chael/goban)](https://goreportcard.com/report/github.com/izm1chael/goban)

GoBan is a fail2ban-style Linux log watcher and IP banner written in Go. It consumes file, Docker, or systemd-journal logs; runs strict per-rule matching; and applies confirmed kernel bans through either iptables + ipset or native nftables.

The current design emphasises truthful enforcement state:

- a rule records a ban only after the firewall backend confirms it;
- source failures, reconnects, queue depth, and dropped lines are visible;
- automatic and manual bans share one audit and attribution pipeline;
- configuration is strict YAML, so misspelled security settings fail startup;
- reload builds a candidate graph first and preserves the active graph on candidate-start failure;
- host-input and forwarded traffic are protected by default.

## Features

- Direct-netlink ipset and nftables hot paths
- IPv4 and IPv6 support
- Host `INPUT` and routed/bridged `FORWARD` enforcement
- Rotation-aware, bounded file follower
- Supervised Docker event and log streams with reconciliation and backoff
- Optional journald source built with `-tags journald`
- Per-rule sliding strike windows and kernel TTL expiry
- Strict rule/source validation and safe identifiers
- Exact local-address self-protection (`/32` and `/128`, not whole connected subnets)
- Rule-specific allowlists and trusted reverse-proxy validation
- Persistent strike state with semantic rule fingerprints
- Persistent ban attribution metadata
- Unix-socket control API and `goban-client`
- Debian/RPM/Arch packaging, systemd units, Docker images, and smoke stack

## Important operating model

GoBan can read an attack from a container log only if its firewall hook also sees the container's traffic. Defaults cover both host and forwarded traffic:

- iptables/ipset: rules are installed in `INPUT` and `FORWARD`;
- nftables: separate `input` and `forward` hook chains are created.

A host with a custom firewall manager may prefer `DOCKER-USER` or another dedicated chain. Configure `banner.iptables_chains` explicitly and verify traffic with the smoke stack before relying on it.

## Build

The module targets Go 1.26.

```bash
git clone https://github.com/izm1chael/goban
cd goban
make build
make test
make test-race
make corpus              # 99 curated production-pipeline compatibility cases
```

The default build is CGO-free and does not include journald support. For journald:

```bash
sudo apt install libsystemd-dev
make build-journald
```

Useful targets:

```text
make build                 CGO-free daemon and client
make build-journald        daemon with sdjournal support
make test                  go test ./...
make test-race             go test -race ./...
make verify-release        formatting, vet, race, fixtures, script syntax
make test-fault            repeated lifecycle/failure tests
make test-kernel           representative privileged end-to-end firewall tests
make corpus                curated rule corpus through the production pipeline
make corpus-generate       deterministic million-line mixed corpus
make corpus-external       opt-in pinned upstream compatibility corpora
make package-smoke         build/install deb, rpm, and Arch packages in clean containers
make docker-build          Alpine runtime image
make docker-build-journald Debian journald-capable image
make man                   regenerate compressed man pages
make package               deb, rpm, and Arch packages
```

## Package installation

Release packages install:

- `/usr/bin/goban-daemon`
- `/usr/bin/goban-client`
- `/etc/goban/goban.yaml`
- `/etc/goban/rules.d/` for enabled rule bundles
- `/usr/share/goban/rules-available/` for the complete rule library
- `goban.service`
- optional `goban-persist.service`

Only the `sshd` and `recidive` bundles are enabled by a fresh package. Other bundles are available but are not activated until their required sources exist.

```bash
# Debian / Ubuntu
sudo apt install ./goban_1.0.0_amd64.deb

# Fedora / RHEL family
sudo dnf install ./goban-1.0.0-1.x86_64.rpm

# Arch family
sudo pacman -U ./goban-1.0.0-1-x86_64.pkg.tar.zst
```

The package does not start the daemon automatically on first install:

```bash
sudo editor /etc/goban/goban.yaml
sudo goban-client config validate --config /etc/goban/goban.yaml
sudo goban-client config show-effective --config /etc/goban/goban.yaml
sudo systemctl enable --now goban
sudo goban-client status
sudo goban-client sources
sudo goban-client doctor --probe
```

Enable another bundle only after defining every source it references:

```bash
sudo cp /usr/share/goban/rules-available/nginx.yaml /etc/goban/rules.d/
sudo goban-client reload
```

## Container quickstart

Build and run the included smoke stack from the repository root:

```bash
docker compose -f deploy/docker-compose.yml up --build
```

The stack contains GoBan, an nginx victim, and a repeated requester. Inspect enforcement and source health with:

```bash
docker compose -f deploy/docker-compose.yml exec goban goban-client sources
docker compose -f deploy/docker-compose.yml exec goban goban-client list
```

For a standalone host-network container:

```bash
docker run --rm --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v /var/log:/var/log:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /etc/goban:/etc/goban:ro \
  -v /run/goban:/run/goban \
  -v /var/lib/goban:/var/lib/goban \
  -v /var/log/goban:/var/log/goban \
  goban:latest
```

`--network host` and `NET_ADMIN` are required for the container to modify the host network namespace. Mounting the Docker socket is required only for Docker log sources.

## Minimal configuration

```yaml
log_level: info
sock_path: /run/goban/goban.sock
socket_mode: 0o660
socket_group: goban

allowlist:
  - 127.0.0.0/8
  - ::1/128

defaults:
  max_retries: 5
  findtime: 10m
  bantime: 1h

sources:
  - type: file
    name: auth-log
    path: /var/log/auth.log

rules:
  - name: sshd
    source: auth-log
    regex: 'Failed password for (?:invalid user )?\S+ from (?P<ip>\S+) port'
    max_retries: 3
    findtime: 10m
    bantime: 24h

banner:
  backend: iptables
  iptables_chains: [INPUT, FORWARD]

state_path: /var/lib/goban/state.gob
state_save_interval: 30s
audit_log: /var/log/goban/audit.log
```

Configuration layers are applied in this order:

1. built-in defaults;
2. main YAML;
3. environment overrides;
4. rule files from `rules_dir`;
5. per-rule defaults;
6. strict validation.

Unknown YAML fields are rejected. Rule and source names must match `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`. Ban durations must be at least one second and fit the kernel timeout representation.

Supported environment overrides include:

```text
GOBAN_LOG_LEVEL
GOBAN_LOG_FILE
GOBAN_SOCKET_PATH
GOBAN_SOCKET_GROUP
GOBAN_SOCKET_MODE
GOBAN_REPLAY_ON_START
GOBAN_FLUSH_ON_EXIT
GOBAN_DRY_RUN
GOBAN_IPV6
GOBAN_IPSET_V4
GOBAN_IPSET_V6
GOBAN_ALLOWLIST
GOBAN_DEFAULT_MAX_RETRIES
GOBAN_DEFAULT_FINDTIME
GOBAN_DEFAULT_BANTIME
```

## Rule syntax

Every regex must include a named `ip` capture:

```yaml
regex: 'from (?P<ip>\S+) port'
```

Go uses RE2 syntax. Backreferences and lookarounds are not available.

### Timestamp-aware rules

A `datepattern` requires a named `time` capture. Supported presets include `sshd`, `syslog_traditional`, `iso8601`, `rfc3339`, `nginx_combined`, and `apache_combined`; a raw Go layout containing `2006` is also accepted.

```yaml
- name: sshd-dated
  source: auth-log
  regex: '^(?P<time>[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d).*Failed password.*from (?P<ip>\S+) port'
  datepattern: sshd
  timezone: Europe/London
  date_failure_policy: drop
```

Traditional syslog timestamps receive the nearest plausible year. Timezone-less values are parsed in `timezone` (`Local` by default).

Timestamp failure is fail-closed by default:

- `drop`: malformed or implausibly stale/future events do not register strikes;
- `source_time`: explicitly fall back to the source event/receipt time.

`goban-client rules` exposes parse failures, drift fallbacks, and dropped timestamp events.

### Exclusions

Every exclusion key must name an actual regex capture:

```yaml
regex: 'user=(?P<user>\S+) ip=(?P<ip>\S+)'
excludes:
  user: monitoring
```

### Reverse proxies

Do not trust a forwarded client address without also validating the direct peer. Capture both values and list the proxy networks that may supply the forwarded address:

```yaml
- name: app-auth
  source: app-access
  regex: '^peer=(?P<peer>\S+) forwarded=(?P<ip>\S+) status=401'
  trusted_proxy_capture: peer
  trusted_proxies:
    - 10.20.0.0/16
```

A forwarded IP is rejected when the direct peer is absent, invalid, or outside the configured trusted CIDRs. Universal trusted-proxy ranges such as `0.0.0.0/0` are refused.

## Firewall backends

### iptables + ipset

The setup path invokes fixed `iptables`/`ip6tables` binaries to attach set-match drop rules. Ban, refresh, list, and unban operations use the native ipset netlink client. Re-banning an existing address refreshes its timeout.

```yaml
banner:
  backend: iptables
  iptables_chains: [INPUT, FORWARD]
ipset_name_v4: goban-ban-v4
ipset_name_v6: goban-ban-v6
```

### nftables

The nftables backend uses netlink directly and creates timeout-bearing IPv4/IPv6 sets plus input and optional forward hook chains.

```yaml
banner:
  backend: nftables
  table: goban
  set_v4: goban-ban-v4
  set_v6: goban-ban-v6
  chain: input
  forward_chain: forward
```

Firewall/backend settings are restart-only. A hot reload rejects changes to them instead of partially applying a new configuration.

## Allowlisting

The configured global and per-rule allowlists are checked before strike registration. GoBan also adds each exact local interface address as `/32` or `/128`; it does not automatically trust the rest of the connected subnet.

Avoid broad private-network allowlists unless every host in those ranges is trusted. They can otherwise exempt LAN or Docker-originated attacks.

## Confirmed bans and batching

`batch_bans` may coalesce nearby requests, but `Ban` still waits for the underlying backend result. A failed batch does not:

- increment the rule's successful-ban counter;
- clear the attacker's strike history;
- write a successful audit event;
- claim the IP is protected.

## Source health and overload

```bash
goban-client status
goban-client sources
```

Source status reports:

- `starting`, `running`, `degraded`, or `stopped`;
- last event and last error;
- reconnect count;
- subscribers;
- delivered and dropped fan-out events;
- maximum observed queue depth.

Fan-out is deliberately bounded and non-blocking. A saturated rule queue therefore degrades visibly through the dropped counter rather than stalling every rule or failing silently.

File and Docker readers retain at most 16 KiB from one record before its delimiter. Journald builds set an sdjournal data threshold before entries are copied into Go memory.

## Transactional reload

Reload with either:

```bash
sudo goban-client reload
sudo systemctl reload goban
```

Rules, sources, defaults, and the global allowlist are hot-reloadable. Long-lived settings such as the socket, logging destination, persistence interval/path, audit path, and firewall backend/chains require a restart.

Reload behaviour:

1. load and strictly validate a complete candidate configuration;
2. build candidate sources, rules, allowlists, and subscriptions without replaying historical files (`replay_on_start` is process-start only);
3. load durable state before candidate processing starts;
4. pause active consumers;
5. start candidate sources while old producers remain available;
6. reconcile old and candidate bounded queues without gaps or duplicate strikes;
7. atomically publish the candidate graph;
8. relaunch the old consumers if candidate startup fails.

The active configuration is unchanged when candidate construction, validation, or startup fails.

## Persistence and auditing

Strike state is stored per rule using a semantic fingerprint. Changing a rule's source, regex, timing, allowlist, exclusions, timestamp policy, or trusted-proxy settings prevents incompatible historical strikes from loading into the new rule.

Ban attribution is stored separately so `goban-client list` can retain rule/source context across daemon restarts. Expired kernel entries are pruned from metadata during list/state maintenance.

The audit log receives one JSON line for every confirmed automatic or manual ban and every successful manual unban. The bundled `recidive` rule consumes this applied-event stream and automatically excludes its own ban events.

Kernel sets survive a daemon restart but not necessarily a host reboot. The optional `goban-persist.service` saves only GoBan's default ipsets and the default `inet goban` nftables table; it does not dump unrelated firewall sets. Custom set/table names require a matching unit override.

```bash
sudo systemctl enable --now goban-persist.service
```

## Control client

```text
goban-client status
goban-client doctor
goban-client doctor --probe
goban-client sources
goban-client rules
goban-client list
goban-client explain 198.51.100.7
goban-client ban 198.51.100.7 --rule manual --ttl 12h
goban-client unban 198.51.100.7
goban-client reload
goban-client rule test --rule sshd /var/log/auth.log
# Test an enabled or candidate rule without a running daemon:
goban-client rule test --rule sshd --config /etc/goban/goban.yaml /var/log/auth.log
goban-client config validate --config /etc/goban/goban.yaml
goban-client config show-effective --config /etc/goban/goban.yaml
```

The socket defaults to `/run/goban/goban.sock`, mode `0660`. When `socket_group: goban` is configured, GoBan resolves that group and applies socket ownership; an unknown group fails control-server startup rather than silently leaving `root:root` ownership.

`rule test` either fetches the complete effective rule from the daemon or, with `--config`/`--rules-dir`, loads the exact startup configuration offline. It runs the same matcher, date policy, exclusions, allowlists, trusted-proxy gate, tracker, and noop banner pipeline. Input is read with the same 16 KiB bounded-record semantics. The compatibility alias `goban-client test` remains available.

`doctor` reports `HEALTHY`, `DEGRADED`, or `NOT ENFORCING` from live source, storage, socket, and firewall state. `--probe` additionally inserts, observes, and removes a short-lived documentation address in the kernel set. That proves the backend write path; use the privileged network-namespace suite below to prove packets are actually blocked through INPUT and FORWARD.

`explain` accepts an active IP or decision ID. Confirmed automatic bans persist a decision ID, accepted-strike count, and first/last evidence timestamps alongside rule/source attribution. Manual bans are identified explicitly.

## Bundled rule library

The library under `examples/rules.d/` covers sshd, nginx, Apache, WordPress, Nextcloud, Postfix, Dovecot, vsftpd, Traefik, Portainer, and recidive scenarios.

Treat bundles as reviewed starting points, not universal log parsers. Before enabling one:

1. define its documented source;
2. run `goban-client rule test` against real local positive and negative samples;
3. verify IPv4 and IPv6 formats;
4. verify reverse-proxy attribution;
5. reload and inspect `goban-client sources` and `goban-client rules`.

CI validates all bundled YAML and runs the curated production-pipeline corpus in `testdata/corpus/manifest.yaml`. The current corpus covers the bundled SSH, web, mail, application, and recidive rules with positive, legitimate-negative, malformed, IPv4, IPv6, field-order, exclusion, and threshold cases. Optional pinned Fail2Ban and Loghub inputs stay outside the repository and are fetched only after explicit licence acceptance. See `docs/CORPUS_TESTING.md`, `docs/RULE_SUPPORT.md`, and `docs/CORE_RULES.md`; non-core bundles remain available/experimental until their compatibility evidence is promoted.

## Release verification

GoBan treats kernel truth and failure recovery as release requirements, not optional manual QA. The non-privileged gate is:

```bash
make verify-release
make test-fault
```

On an expendable Linux VM with root privileges, prove the complete log-to-packet path:

```bash
make build
sudo test/integration/kernel/run.sh iptables input 4
sudo test/integration/kernel/run.sh iptables forward 4
sudo test/integration/kernel/run.sh nftables input 6
sudo test/integration/kernel/run.sh nftables forward 6
```

The full release workflow runs all eight backend/path/family combinations plus package installation smoke tests. See `docs/RELEASE_CHECKLIST.md`. A kernel test passes only when a remote network namespace can connect before the threshold, the active decision is confirmed and explainable, and the same connection is blocked afterwards.

## Benchmarks

The `benchmark/` directory contains CPU/RSS and line-accounting harnesses. The generator writes its exact emitted-line count, and `accuracy.sh` uses that count rather than assuming `requested rate × duration`.

Run benchmarks on a dedicated Linux host with the intended firewall backend:

```bash
make build
sudo bash benchmark/full-suite.sh 60
sudo bash benchmark/accuracy.sh 30
```

No throughput percentage is published here until the corrected exact-accounting harness is rerun on a documented host. This avoids presenting derived saturation claims that the old requested-rate denominator could not prove.

## Security notes

- The daemon requires `CAP_NET_ADMIN`; the provided systemd unit bounds capabilities and applies filesystem/kernel hardening.
- Log data cannot choose an executable. The iptables setup runner permits fixed binaries and arguments generated from validated configuration.
- Matching uses Go's linear-time RE2 engine.
- Records are bounded before matching and, for file/Docker/journald sources, before an unbounded line allocation.
- Socket permissions are not an authorization substitute: membership permits manual bans, unbans, and reloads.
- Reading `/var/run/docker.sock` is highly privileged. Mount it only when Docker sources are required.
- A zero-width or universal allowlist/trusted-proxy range is rejected where it would disable protection.

## Project layout

```text
cmd/goban-daemon/        daemon binary
cmd/goban-client/        control client
internal/allowlist/      CIDR matching and exact local-address discovery
internal/banner/         confirmed firewall backends and batching
internal/config/         strict layered YAML/env loading and validation
internal/control/        Unix-socket API, client, and audit stream
internal/daemon/         lifecycle, transactional reload, persistence
internal/datepattern/    named and raw Go timestamp layouts
internal/ipset/          direct-netlink ipset client
internal/matcher/        regex captures and IP normalisation
internal/nftables/       direct-netlink nftables client
internal/rule/           production rule pipeline
internal/source/         bounded fan-out and record reader
internal/source/file/    bounded rotation/truncation-aware follower
internal/source/docker/  supervised Docker stream source
internal/source/journal/ build-tagged sdjournal source
internal/tracker/        sliding windows and fingerprinted state
deploy/                  containers, smoke stack, and systemd units
examples/                sample config and rules-available library
packaging/               nfpm and Arch packaging
man/                     daemon/client manual pages
benchmark/               load and exact-accounting harnesses
docs/                      threat model, rule support, release checklist
test/                      fault, privileged kernel, and package gates
testdata/rules/            compact core-rule compatibility fixtures
testdata/corpus/           full curated corpus + external source manifest
```

## License

MIT.
