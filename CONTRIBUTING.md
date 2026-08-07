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
make corpus        # production-pipeline rule compatibility corpus
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
cmd/goban-corpus/       maintainer corpus/differential tool
internal/corpus/        curated, generated, and external corpus runners
testdata/corpus/        repository cases + pinned source provenance
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
- Rule changes require corpus cases for IPv4, IPv6, legitimate negatives, malformed input, and every new documented format. Do not copy third-party datasets into the repository; register pinned external sources in `testdata/corpus/manifest.yaml`.
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

## Migration, setup, and soak changes

Changes to `internal/migrate` must prove that unsupported Fail2Ban behavior is
reported rather than silently approximated. Generated staging configuration
must pass the production `config.LoadEffective` path.

Changes to `internal/setup` must remain observational by default. Setup may
write a staging directory only after an explicit flag and must begin in
`dry_run` mode.

Changes to `goban-soak` must preserve append-only raw samples. Report logic is
a release gate, so new failure criteria require tests and an update to the
relevant soak test or release-gate command.
