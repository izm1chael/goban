# Contributing

Thanks for your interest in GoBan. This is a small project — read this once
and you'll know how to land a change cleanly.

## Building locally

You need Go 1.26+, plus the `iptables` and `ipset` binaries available on the
host or container where you'll run the daemon.

```bash
git clone https://github.com/izm1chael/goban
cd goban
make build         # produces bin/goban-daemon, bin/goban-client (CGO-free)
make test-race     # all packages green with race detector
make docker-build  # alpine image
```

Optional: `make build-journald` produces a journald-enabled binary (requires
`libsystemd-dev` and CGO).

## Project layout

```
cmd/goban-daemon/       daemon entry point
cmd/goban-client/       control client entry point
internal/allowlist/     CIDR allowlist with local-interface autodetect
internal/banner/        Banner interface + iptables/ipset impl
internal/config/        YAML+env config loader, validation
internal/control/       unix-socket HTTP server + client + audit log
internal/daemon/        wiring + lifecycle + Reload diff/swap
internal/ipset/         netlink-direct ipset client
internal/logging/       zerolog Init/Get
internal/matcher/       pure regex → IP extractor
internal/rule/          per-rule orchestrator
internal/source/        Source interface + file/docker/journal backends
internal/tracker/       sharded sliding-window strike counter
benchmark/              load gen, sampler, harness scripts
deploy/                 Dockerfile, systemd units, docker-compose
packaging/              nfpm config, install/remove scripts, Arch PKGBUILD
```

## Style

- Use `gofmt` (standard). CI's `go vet ./...` must pass.
- Tests should be table-driven where it helps clarity. Use `t.TempDir()` for
  any filesystem state.
- Error wrapping: `fmt.Errorf("context: %w", err)`. Don't lose the original.
- New goroutines need an explicit shutdown story — context cancel, channel
  close, or a sentinel — and a unit test that proves they exit.
- Comments explain *why*. Code says *what*. If you find yourself describing
  what a function does, ask whether it should be split or renamed.

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/) prefixes
so GitHub's auto-generated release notes group cleanly:

- `feat:` user-visible feature
- `fix:` user-visible bug fix
- `perf:` performance improvement
- `refactor:` no behaviour change
- `test:` test-only change
- `docs:` documentation
- `ci:` GitHub Actions, build tooling
- `chore:` everything else

Example: `feat(rule): per-rule allowlist support`

## Pull requests

1. Open a PR against `main`.
2. CI must be green. The three checks are `test`, `build`, `docker`.
3. A maintainer reviews. For small fixes one approval is enough.
4. Squash-merge with a clean commit message (conventional commit format).

## Reporting bugs

Open a GitHub issue with:
- Distro + version
- Output of `goban-daemon -version`
- Relevant config snippet (redact IPs/hostnames as needed)
- Steps to reproduce
- What you expected vs what happened

## Security issues

See [SECURITY.md](SECURITY.md). Use GitHub's private vulnerability reporting
workflow under the Security tab — **do not** open a public issue for security
problems.
