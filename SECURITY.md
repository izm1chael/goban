# Security Policy

## Threat model

GoBan must run as `root` (or with `CAP_NET_ADMIN` + `CAP_NET_RAW`) because it
manipulates kernel netfilter state via the ipset subsystem. There is no
userspace path to managing iptables/ipset rules. Operators should understand
the privilege footprint:

- The daemon process can install/remove arbitrary iptables rules and ipset
  entries on the host kernel.
- The control unix socket defaults to mode `0660` owned by `root:goban`. Any
  user in the `goban` group can ban/unban/reload via `goban-client`.
- Log lines fed to GoBan are NEVER interpreted as commands — the rule engine
  treats them as data to regex-match. The exec layer in
  `internal/banner/iptables.go` restricts subprocesses to a literal-only
  switch over `{ipset, iptables, ip6tables}`.
- Log lines are capped at 16 KiB before regex evaluation and the matcher
  uses Go's RE2 engine (linear-time guarantee — no ReDoS).
- The netlink-direct ipset client (`internal/ipset/`) operates in the daemon
  process address space; it does not exec helper binaries on the hot path.

## Supported versions

The latest minor release line receives security fixes. Older releases on a
best-effort basis only.

## Reporting a vulnerability

**Do NOT open a public GitHub issue for security reports.** Use GitHub's
private vulnerability reporting workflow:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Fill in the form; the maintainer is notified privately.

The maintainer will acknowledge within 7 days. Public disclosure happens
after a fix is released, coordinated with the reporter via the resulting
GitHub Security Advisory.

GitHub Security Advisories are the only supported reporting channel — no
email address is published, and unsolicited emails sent elsewhere may be
overlooked.

## What counts as a vulnerability

In scope:

- Code paths that bypass the allowlist
- Issues that allow log content to influence the command line of `iptables`
  / `ipset` / `ip6tables`
- Memory-safety bugs in the netlink ipset client
- Crashes triggered by adversarial log lines
- Privilege escalation paths from the `goban` group to root
- Resource exhaustion vectors that survive the existing 16 KiB line cap and
  RE2 linear-time guarantees

Out of scope (don't file via Security Advisory — open a regular issue):

- Requests for features (nftables, distributed bans, etc.)
- Performance concerns at workloads not yet supported
- Documentation errors
