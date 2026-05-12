# GoBan

[![CI](https://github.com/izm1chael/goban/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/izm1chael/goban/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report](https://goreportcard.com/badge/github.com/izm1chael/goban)](https://goreportcard.com/report/github.com/izm1chael/goban)

A fail2ban-style log watcher and IP banner, written in Go.

GoBan tails log streams from files, Docker container logs, or the systemd
journal; matches lines against per-rule regex; and bans offending IPs at the
kernel level via `iptables` + `ipset` (with `ip6tables` for IPv6). It ships a
control client (`goban-client`) for status, listing, and manual ban/unban.

Three things it does differently to classic fail2ban:

1. **Single-binary, statically linked Go.** No Python runtime, ~10 MB image.
2. **Container-native.** Run it inside a sibling container in a Portainer
   stack with `--cap-add NET_ADMIN --network host` and it protects everything
   else on the host.
3. **ipset-backed bans via direct netlink.** O(1) lookup at thousands of bans
   with kernel-side TTL expiry — no Go-side unban timer, no fork-and-exec per ban.

## Benchmarks

GoBan v1.1 vs fail2ban v1.0.2 on the same kernel, same workload, same rules
(`benchmark/` directory has the full reproducible harness — synthetic sshd-fail
generator, /proc-based sampler, 60-second steady-state per cell).

**Native, real iptables (production scenario):**

| line rate | GoBan CPU | fail2ban CPU | speedup | GoBan RSS | fail2ban RSS | RSS ratio |
|-----------|-----------|--------------|---------|-----------|--------------|-----------|
| 100/sec   | **0.08%** | 2.37%        | **30x** | 12.7 MB   | 51.3 MB      | 4.0x      |
| 1K/sec    | **0.75%** | 25.03%       | **33x** | 14.8 MB   | 51.1 MB      | 3.5x      |
| 10K/sec   | **7.49%** | 119.88% (saturated) | **16x** | 15.4 MB | 51.4 MB | 3.3x  |

**Container, real iptables (Docker, `--network host`):**

| line rate | GoBan CPU | fail2ban CPU | speedup |
|-----------|-----------|--------------|---------|
| 100/sec   | 0.08%     | 2.37%        | 30x     |
| 1K/sec    | 0.79%     | 7.96%        | 10x     |
| 10K/sec   | 7.68%     | 61.62%       | 8x      |

**Throughput accuracy at saturation (lines actually processed):**

CPU and RSS numbers alone are misleading because fail2ban silently drops log
lines when it can't keep up. `benchmark/accuracy.sh` measures the
fraction of generated lines each daemon actually saw.

| line rate | GoBan native | GoBan container | fail2ban native | fail2ban container |
|-----------|--------------|-----------------|-----------------|--------------------|
| 1K/sec    | 96.1%        | 98.4%           | 98.4%           | 98.4%              |
| 5K/sec    | 97.3%        | 98.3%           | 98.1%           | **86.6%**          |
| 10K/sec   | 97.2%        | 97.7%           | **54.2%**       | **43.8%**          |

GoBan stays at ~97-98% across every rate (the missing 2-3% is the last few
lines still in the pipeline when we sampled — extending the post-test settle
window closes that gap). fail2ban's "saturated 119% CPU at 10K" turns out to
be saturating while dropping nearly half the input.

What this means in practice:

- **GoBan processes ~80% more lines per second than fail2ban native at 10K/sec**,
  using ~16x less CPU (7.49% vs 119%). GoBan still has ~92% of a single core
  in reserve.
- **GoBan is ~28x more efficient** than fail2ban at the saturation point
  (lines-processed per CPU%): ~1300 lines/% for GoBan vs ~46 lines/% for
  fail2ban.
- **Memory: ~3-4x smaller resident set.** GoBan's RSS scales gently with load
  (more tracker state); fail2ban's flat ~51 MB is mostly Python runtime
  overhead — that's the floor even at idle.
- **iptables overhead is effectively zero** for GoBan since v1.1 — the
  netlink-direct ipset client added in this release replaced the per-ban
  fork-and-spawn of the `ipset` binary with one kernel syscall. At 1K bans/sec
  the iptables-mode CPU overhead dropped from 7.73 points (v1) to 0.03 points
  (v1.1).
- **Docker overhead is negligible for GoBan** — native vs container numbers
  overlap within sample noise. fail2ban container, by contrast, drops MORE
  lines than fail2ban native does at the same input rate.

Reproduce on your own box:

```bash
make build
sudo bash benchmark/full-suite.sh 60   # CPU/RSS matrix, ~30 min
sudo bash benchmark/accuracy.sh 30     # line-processing accuracy, ~10 min
```

## Install (Debian / Ubuntu / Fedora / RHEL / Arch)

Pre-built packages for the three major formats are attached to each release:

```bash
# Debian / Ubuntu / Mint / Raspbian / Kali
sudo apt install ./goban_1.0.0_amd64.deb

# Fedora / RHEL / Rocky / Alma / openSUSE
sudo dnf install ./goban-1.0.0-1.x86_64.rpm
# or: sudo rpm -i ./goban-1.0.0-1.x86_64.rpm

# Arch / Manjaro / EndeavourOS / SteamOS
sudo pacman -U ./goban-1.0.0-1-x86_64.pkg.tar.zst
```

The package installs:

- `/usr/local/bin/goban-daemon` and `/usr/local/bin/goban-client`
- `/etc/goban/goban.yaml` (sample config; preserved on upgrade)
- `/etc/goban/rules.d/*.yaml` (10 bundled rule files)
- `/usr/lib/systemd/system/goban.service` (and the optional `goban-persist.service` for ipset reboot persistence)
- A system `goban` user/group used for the control socket's ownership

`iptables` and `ipset` are declared as dependencies so the package manager pulls them automatically. The daemon is **not** auto-started — review the config first, then:

```bash
sudo systemctl enable --now goban
sudo systemctl status goban
```

**Other distros:** Alpine, Void, Gentoo, and similar — the static binary from
the GitHub Release works on any Linux kernel ≥3.x with `iptables` and `ipset`
installed. Drop `bin/goban-daemon` into `/usr/local/bin/` and copy the
systemd unit from `deploy/goban.service` (if applicable). Alpine users
running the daemon in a container should use `goban:latest` from the
container registry — there's currently a known incompatibility between
nfpm-generated `.apk` files and Alpine's `apk-tools` that we haven't
resolved.

## Build from source

```bash
git clone https://github.com/izm1chael/goban
cd goban
make build         # produces bin/goban-daemon, bin/goban-client (CGO-free)
make test-race     # all packages green with race detector
make docker-build  # alpine image with iptables + ipset baked in
```

For journald support (build tag `journald`, requires `libsystemd-dev` + CGO):

```bash
sudo apt install libsystemd-dev    # Debian/Ubuntu
make build-journald
```

For local package builds (`.deb`, `.rpm`, `.pkg.tar.zst`) install nfpm:

```bash
go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.42.1
make package VERSION=1.0.0
ls dist/    # three packages, ready to install or distribute
```

## Quickstart (container)

```bash
git clone https://github.com/izm1chael/goban
cd goban
make docker-build
docker run --rm --network host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v /var/log:/var/log:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v $(pwd)/examples/goban.yaml:/etc/goban/goban.yaml:ro \
  -v $(pwd)/examples/rules.d:/etc/goban/rules.d:ro \
  -v /run/goban:/run/goban \
  goban:latest
```

In another shell:

```bash
goban-client status
goban-client rules
goban-client list
```

## Quickstart (host install, systemd)

```bash
make build
sudo install -m 0755 bin/goban-daemon /usr/local/bin/
sudo install -m 0755 bin/goban-client /usr/local/bin/
sudo install -d -m 0755 /etc/goban /etc/goban/rules.d
sudo cp examples/goban.yaml /etc/goban/goban.yaml
sudo cp examples/rules.d/*.yaml /etc/goban/rules.d/
sudo cp deploy/goban.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now goban.service
```

## Concepts

- **Source**: a log stream. One of `file` (any path), `docker` (a container
  selected by name or labels), or `journal` (systemd journal, journald build
  only).
- **Rule**: a regex filter attached to a source. When the same IP triggers
  the regex more than `max_retries` times within `findtime`, the rule asks
  the banner to ban that IP for `bantime`.
- **Banner**: the kernel firewall backend. Two implementations ship:
  - `iptables` (default): two ipsets (`goban-ban-v4` + `goban-ban-v6`) plus
    iptables/ip6tables INPUT rules referencing them. Hot-path operations
    talk netlink directly to the ipset subsystem.
  - `nftables`: native netlink to `NFNL_SUBSYS_NFTABLES`. Creates one
    `inet goban` table, two timeout sets, one input-hooked chain, and two
    drop rules. No external binary dependencies. Set
    `banner.backend: nftables` in goban.yaml.
- **Allowlist**: CIDRs that are never banned. The default list includes
  loopback and all RFC1918 ranges, and at startup GoBan automatically adds
  every address bound to a local interface so the host can't ban itself.

## Configuration

Layered: built-in defaults → YAML file → environment variables. The
following file is enough to protect SSH:

```yaml
# /etc/goban/goban.yaml
log_level: info
sock_path: /run/goban/goban.sock

defaults:
  max_retries: 3
  findtime: 10m
  bantime: 24h

sources:
  - type: file
    name: auth-log
    path: /var/log/auth.log

rules:
  - name: sshd
    source: auth-log
    regex: 'Failed password for (?:invalid user )?\S+ from (?P<ip>\S+) port'
```

For a richer setup, point `rules_dir:` at `/etc/goban/rules.d/` and drop the
bundled rule files in. They cover sshd (basic + aggressive), nginx (noscript,
http-auth, badbots, common probes), apache (auth, noscript, overflows),
WordPress (wp-login + xmlrpc), Nextcloud (login + bruteforce), Postfix
(SASL + RBL), Dovecot, vsftpd, Traefik (auth + ratelimit), and Portainer.

Useful environment overrides:

```
GOBAN_LOG_LEVEL=debug
GOBAN_REPLAY_ON_START=false
GOBAN_SOCKET_MODE=0660
GOBAN_DEFAULT_FINDTIME=10m
GOBAN_DEFAULT_BANTIME=1h
GOBAN_IPV6=true
GOBAN_ALLOWLIST=10.0.0.0/8,192.168.0.0/16
```

## Hot config reload

Edit `/etc/goban/rules.d/my-rule.yaml` (or anything in `goban.yaml`) and
have the daemon pick up the change without dropping anything:

```bash
sudo systemctl reload goban      # uses SIGHUP under the hood
# OR
sudo goban-client reload         # equivalent, via the control socket
```

The daemon validates the new config completely before applying anything. On
any failure (bad YAML, invalid regex, missing source) the running daemon is
**unchanged** and the error is logged (or returned to `goban-client reload`).

Rules whose `name`, `regex`, `max_retries`, `findtime`, `bantime`, and
allowlist are all unchanged keep their tracker state across the reload.
Rules whose semantics changed get a fresh tracker (operator-expected
behavior — the rule's interpretation of "what counts as a strike" changed).

**Restart-only** fields (changes refused by reload, daemon must be restarted):
`sock_path`, `socket_mode`, `socket_group`, `ipset_name_v4`, `ipset_name_v6`,
`ipv6`, `dry_run`, `batch_bans`, `state_path`, `audit_log`.

## Persistent strike state

In-flight strike counts (IPs that have failed once or twice but not yet
crossed the threshold) survive a daemon restart. State is dumped to
`/var/lib/goban/state-<rule>.gob` every 30 seconds and on graceful shutdown,
and reloaded at startup. Already-banned IPs are kept in the kernel ipset
regardless, so this only affects "almost banned" attackers — but it stops a
determined attacker from resetting their strike count by waiting for a
daemon restart.

Tunable in YAML:

```yaml
state_path: /var/lib/goban/state.gob   # empty disables persistence
state_save_interval: 30s
```

## Audit trail

Every successful manual ban or unban via `goban-client` appends a JSON line
to an audit file:

```yaml
audit_log: /var/log/goban/audit.log    # empty disables auditing
```

Example line:

```json
{"time":"2026-05-11T13:42:01Z","action":"ban","ip":"192.0.2.99","rule":"manual","ttl":"5m0s","source":"manual"}
```

Failed attempts are deliberately NOT logged, so the file remains an accurate
"what was applied" timeline. Use logrotate to manage size.

## Recidive — repeat offenders

A built-in rule (`examples/rules.d/recidive.yaml`, shipped to
`/etc/goban/rules.d/` by the packages) watches GoBan's own audit log and
re-bans any IP that has been banned 5+ times in the last 24 hours, for a
week.

To enable it, define a file source pointing at the audit log:

```yaml
sources:
  - type: file
    name: audit
    path: /var/log/goban/audit.log
```

(The example `goban.yaml` shipped in the packages already does this.) The
rule is feedback-loop safe — both via an explicit `excludes` filter in
the YAML and a hardcoded auto-exclude for any rule named exactly
`recidive`.

Tune the thresholds in `/etc/goban/rules.d/recidive.yaml`:

```yaml
- name: recidive
  max_retries: 5      # # of past bans within findtime
  findtime: 24h       # window over which past bans count
  bantime: 168h       # 1 week — typically much longer than per-service bans
```

## Testing rules before deploying

To validate a new regex against real logs without actually banning anyone,
load the rule into a running daemon (any daemon, e.g. on a staging host)
and dry-run it via the client:

```
goban-client test --rule sshd /var/log/auth.log
```

The client fetches the rule's regex + threshold + findtime + bantime from
the daemon, applies them to the log file (or stdin if `-`), and prints
which IPs would be banned and when:

```
=== test results for rule "sshd" against /var/log/auth.log ===
Lines read:        27412
Lines matched:     312
Unique IPs seen:        18
Simulated bans:         11

Rule settings: max_retries=5, findtime=10m, bantime=1h

IP             FIRST_SEEN  BANNED_AT  EXPIRES
198.51.100.7   12:03:11    12:05:42   2026-05-11T13:05:42Z
198.51.100.42  12:08:20    12:09:55   2026-05-11T13:09:55Z
...
```

Useful for tuning thresholds against actual attack patterns before rolling
a rule out to production. Timestamps use wall-clock time at the point each
line is read, NOT the timestamps inside the log — so an old auth.log will
produce "would ban at <now>" rather than the original event times. Good for
deciding "would this rule fire too often"; not a replay tool.

## Writing a rule

Rules are YAML. The regex must contain a `(?P<ip>...)` named capture; the
value is parsed with `netip.ParseAddr` and must resolve to a valid IP. A
rule can optionally carry its own `allowlist:` of CIDRs that bypass that
rule specifically (the global allowlist still applies).

```yaml
rules:
  - name: my-app-failures
    source: my-app-container       # name of a defined source
    regex: 'login failed.*from (?P<ip>[^\s]+)'
    max_retries: 5
    findtime: 10m
    bantime: 6h
    allowlist:                     # optional per-rule allowlist
      - 203.0.113.50/32            # VPN endpoint — bypass THIS rule only
      - 10.0.0.0/16
```

GoBan uses Go's RE2 regex engine. **It does not support backreferences,
lookarounds, or named macros like fail2ban's `<HOST>`.** To port a fail2ban
filter, substitute `<HOST>` with `(?P<ip>\S+)` (or a tighter character class
if the field is quoted or bracketed).

**Date-aware rules.** When matching backfilled or replayed logs (e.g.
journald catching up at boot), use the rule's `datepattern` field and add
a `(?P<time>...)` capture to your regex. GoBan parses the captured
timestamp and uses it as the strike-window event time instead of
wall-clock, so a burst of stale events doesn't compress into a fake
attack:

```yaml
- name: sshd-with-time
  source: auth-log
  regex: '^(?P<time>\S+\s+\S+\s+\S+) \S+ sshd\[\d+\]:.*Failed password.*from (?P<ip>\S+) port'
  datepattern: sshd      # preset; also accepts iso8601, rfc3339,
                          # nginx_combined, apache_combined, syslog_traditional,
                          # OR a raw Go time layout containing "2006"
  max_retries: 5
  findtime: 10m
  bantime: 1h
```

Parsed timestamps outside ±6h (past) / 1h (future) from wall-clock fall
back to wall-clock and bump the rule's `DateDriftFallbacks` counter,
visible via `goban-client rules`.

**Post-match `excludes` filter.** Use to skip lines whose captures match
specific values — common pattern for "ignore monitoring traffic":

```yaml
- name: app-failures
  regex: '"user":"(?P<user>[^"]+)".*"ip":"(?P<ip>[^"]+)"'
  excludes:
    user: monitoring    # don't count failures attributed to monitoring
```

## Operating GoBan

```
goban-client status                    # uptime, rule count, total bans
goban-client rules                     # per-rule hit/ban counters
goban-client list                      # currently-banned IPs
goban-client unban 1.2.3.4             # remove a ban
goban-client ban 1.2.3.4 --rule manual --ttl 24h    # ban manually
goban-client test --rule sshd auth.log              # dry-run a rule
```

The daemon talks over a unix socket (default `/run/goban/goban.sock`, mode
`0660`). Members of the `goban` group can use the client without sudo if you
set `socket_group: goban` in the config.

## Persistence across reboot

ipset state lives in the kernel and survives daemon restarts, but not host
reboots. For host installs, enable `deploy/goban-persist.service` which dumps
ipset state on shutdown and restores it at startup. For container installs
on a dedicated firewall host, do the same on the host (the container's
kernel state IS the host's kernel state).

## Upgrading

`apt upgrade goban` / `dnf upgrade goban` / `pacman -Syu goban` is safe and
non-destructive. What survives, what doesn't, and what to expect:

**Preserved across upgrade:**

| Path | What | Why |
|---|---|---|
| `/var/lib/goban/state.gob` | Tracker strike state | nfpm doesn't touch existing data files |
| `/etc/goban/goban.yaml` | Your main config | `config|noreplace` — package never overwrites your edits |
| `/etc/goban/rules.d/*.yaml` | Your custom rule files | Same. The bundled rules in `examples/rules.d/` are shipped to `/etc/goban/rules.d/` only on first install; later upgrades leave your tree alone |
| `/var/log/goban/audit.log` | Append-only ban audit log | Owned by the runtime, not the package |
| Kernel ban set | Active bans (ipset / nftables set) | Lives in kernel memory; restored on daemon restart from `state.gob` for non-expired TTLs |
| `systemctl edit goban` overrides | Drop-in unit fragments | Stored in `/etc/systemd/system/goban.service.d/` which the package doesn't manage |

**Replaced or restarted on upgrade:**

| Item | Behavior |
|---|---|
| `/usr/local/bin/goban-daemon` and `goban-client` | Replaced with new binaries |
| `/usr/lib/systemd/system/goban.service` | Replaced (your `systemctl edit` overrides still apply on top) |
| The daemon process | Stopped → upgraded → restarted automatically by the package's post-install script |

**Reboot recovery.** ipset / nftables sets are kernel-resident and wiped on
host reboot. The daemon's state file is loaded on startup; the daemon then
re-adds any IPs whose recorded TTL has not yet expired to the kernel set.
This is the same path that `goban-persist.service` enables for ipset
state, so both backends recover cleanly.

**Backend switch.** Changing `banner.backend` between `iptables` and
`nftables` in goban.yaml is supported but requires a daemon restart
(`systemctl restart goban` or `goban-client reload` followed by restart —
the backend cannot be swapped via hot reload). Existing bans in the old
backend's kernel set are not auto-migrated; either let them expire or
move them manually with `goban-client unban` + `goban-client ban`.

**Cross-version compatibility.**

| Surface | Compatibility |
|---|---|
| `state.gob` (`stateVersion=1`) | Backward-compatible within v1.x.y. A version mismatch logs a warning and starts with a clean tracker |
| Audit log (JSON-lines) | Additive only. New fields are ignored by the bundled `recidive` regex |
| `goban.yaml` schema | Additive. Old YAML loads in newer daemons; new keys are no-ops for older daemons |
| Control socket protocol | Stable v1.x. `goban-client` from v1.0 talks to a daemon from v1.x, modulo missing subcommands |

**Rollback.** Pin to a specific version if a release breaks something:

```bash
sudo apt install goban=1.0.0                  # Debian / Ubuntu
sudo dnf downgrade goban-1.0.0                # Fedora / RHEL
sudo pacman -U goban-1.0.0-1-x86_64.pkg.tar.zst  # Arch (downloaded artifact)
```

The state file remains compatible; rolling back doesn't lose data.

**Cutting your own release of a fork.** Tag a semver tag matching `v*.*.*`
and push it. The GitHub Actions release workflow builds the multi-arch
binaries, packages, and image automatically — no manual artifact handling.

## Requirements

- Linux kernel ≥ 4.18 (Aug 2018) for the nftables backend; kernel ≥ 3.13 for
  the iptables backend
- For the iptables backend (default): `iptables` (legacy or nft), `ipset`,
  and (for IPv6) `ip6tables` binaries on PATH
- For the nftables backend: no external binaries — the daemon talks to the
  `NFNL_SUBSYS_NFTABLES` netlink subsystem directly
- Daemon: root on the host, or `CAP_NET_ADMIN` + `CAP_NET_RAW` in a container
  with `--network host`
- For Docker source: read access to `/var/run/docker.sock`
- For journald source: build with `make build-journald` (requires CGO and
  libsystemd-dev)

### Tested kernels

| Kernel | Backend | Status |
|---|---|---|
| 6.6 (WSL2) | iptables | end-to-end verified via the live smoke test |
| 6.6 (WSL2) | nftables | end-to-end verified (Setup → ban → refresh → list → drop → unban → idempotent re-Setup → TTL expiry → 2000-entry large-set dump → IPv4-mapped IPv6 routing) |
| 5.10, 5.15, 6.1 | both | wire format unchanged from 4.18+; expected to work but community-tested only |
| < 4.18 | nftables | will fail at `CreateSet` because `NFT_SET_TIMEOUT` was added in 4.18 — use the iptables backend instead |

If you run v1.0 on a kernel we haven't directly tested, please open a GitHub
issue with `uname -r` and the `goban-daemon -version` output, whether it
worked, and any error from `journalctl -u goban`. Smoke harness lives at
`cmd/goban-nft-smoke` if you want to reproduce locally.

## Make targets

```
make build               # default, CGO-free, no journald
make build-journald      # CGO=1, libsystemd-backed, journald support
make test                # go test ./...
make test-race           # go test -race ./...
make docker-build        # build the alpine image
make lint                # golangci-lint run
make man                 # gzip troff man pages into man/*.gz (input to nfpm)
make package             # build amd64 deb + rpm + archlinux packages
make package-deb         # just the .deb
make package-rpm         # just the .rpm
make package-arch        # just the .pkg.tar.zst
```

## Project layout

```
cmd/goban-daemon/        # the daemon binary
cmd/goban-client/        # the control client binary
internal/allowlist/      # CIDR allowlist + local-interface autodetect
internal/banner/         # Banner interface + iptables/nftables/noop impls
internal/config/         # YAML+env config loading and validation
internal/control/        # unix-socket HTTP server + client
internal/daemon/         # lifecycle: wires sources, rules, banner, control
internal/datepattern/    # named-preset & raw Go layout resolver
internal/ipset/          # native-netlink ipset client (for iptables backend)
internal/logging/        # zerolog Init/Get
internal/matcher/        # pure regex → IP extractor (with optional ?P<time>)
internal/nftables/       # native-netlink nftables client (NFNL_SUBSYS_NFTABLES)
internal/rule/           # rule orchestrator (per-rule goroutine, excludes, drift guard)
internal/source/         # Source interface + Hub helper
internal/source/file/    # nxadm/tail-backed file source
internal/source/docker/  # docker SDK log-stream source
internal/source/journal/ # build-tagged sdjournal source
internal/tracker/        # sliding-window strike counter (HitAt + gob persistence)
deploy/                  # Dockerfile, docker-compose, systemd units
examples/                # goban.yaml + rules.d/ bundle library
man/                     # troff man pages (man8 daemon, man1 client)
```

## Security considerations

- GoBan must run as root because it shells out to `iptables`/`ip6tables`/
  `ipset`. There is no userspace path. The exec runner in
  `internal/banner/iptables.go` restricts which binaries can be invoked via
  a literal-only switch — log content cannot influence the command name.
- Log lines are truncated to 16 KiB before regex matching to neutralise
  pathological inputs. Go's RE2 engine is linear-time so there is no ReDoS
  risk by construction.
- The allowlist is consulted **before** strike registration, so allowlisted
  IPs accumulate no state.
- The control socket defaults to `0660`, group-owned by `goban`. Grant
  individual operators that group rather than running the client as root.

## License

MIT.
