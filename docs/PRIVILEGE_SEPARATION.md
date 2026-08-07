# Privilege separation

Packaged systemd deployments split GoBan into two processes so attacker-controlled
log parsing does not run with firewall privileges.

```text
untrusted logs
    |
    v
+------------------+       private Unix socket       +-------------------+
| goban-daemon     |  ---------------------------->  | goban-enforcer    |
| User=goban       |      typed decisions only       | User=goban-enforcer|
| CapEff = 0       |  <----------------------------  | CAP_NET_ADMIN only|
+------------------+                                  +-------------------+
       |                                                       |
       | control/state/audit                                   | netlink + fixed
       v                                                       | hook commands
  /run,/var/lib,/var/log                                       v
                                                         kernel firewall
```

## What stays unprivileged

`goban-daemon` owns:

- file, Docker, and journald ingestion;
- bounded record handling and RE2 matching;
- strike tracking, date policies, exclusions, and trusted-proxy checks;
- reload, state, audit attribution, metrics, and the operator control socket;
- decision generation.

The packaged unit runs as the dedicated `goban` account with an empty Linux
capability set. The privileged kernel integration matrix verifies both a
non-zero UID and `CapEff=0000000000000000` before it accepts a packet-blocking
result.

## What remains privileged

`goban-enforcer` owns only:

- idempotent setup of the configured GoBan firewall objects;
- apply a validated temporary IP decision;
- remove an IP decision;
- list active kernel decisions;
- backend diagnostics and close/flush semantics.

It does not read attack logs, evaluate regexes, load arbitrary plugins, or
accept shell commands/firewall expressions from the daemon.

The packaged helper runs as the separate non-login `goban-enforcer` identity and
is bounded to `CAP_NET_ADMIN` only. It does not need root or `CAP_CHOWN`.

## Protocol boundary

The protocol is versioned and intentionally small. The daemon connects over
`/run/goban-enforcer/enforcer.sock` by default. The helper enforces both:

1. filesystem ownership/mode (`0660`, helper-owned with group `goban`),
2. Linux `SO_PEERCRED` UID validation on every accepted Unix connection.

The group permission exists only so the detector can open the socket. Other
`goban` group members are still rejected by the peer-credential check.

Root is also accepted for diagnostics/administration. Unknown JSON fields,
multiple JSON values, oversized request bodies, invalid addresses, invalid
rule identifiers, and invalid TTLs are rejected.

A daemon and helper protocol-version mismatch fails setup. A configured backend
mismatch also fails rather than allowing the two processes to operate against
different firewall state.

The daemon never sends raw iptables/nftables commands. Requests are limited to
typed setup, policy reload, ban batch, unban, list, diagnostics, and close operations.

Policy reload is also fail-closed. The detector sends only the expected semantic
policy fingerprint; the helper independently reloads the root-managed GoBan
configuration and rule directory, computes its own fingerprint, and swaps its
allowlist policy only when the two fingerprints match. The detector does not
send trusted CIDRs over the socket.

## Independent safety checks

The helper does not blindly trust a decision just because it came from the
`goban` UID. It independently builds its protection policy from the root-managed
configuration and refuses bans for:

- invalid or unspecified addresses;
- loopback addresses;
- multicast addresses;
- global allowlisted networks;
- the host's exact local interface addresses;
- per-rule allowlisted networks.

This does not make a compromised detector harmless: a process running as
`goban` could still request bans for arbitrary *non-protected* remote addresses
or request unbans. Privilege separation is intended to contain kernel/root
capability, not to provide cryptographic proof that every decision was derived
from honest log evidence.

## Failure semantics

The security invariant is unchanged:

> A strike window is reset and a successful ban is recorded only after the
> privileged helper confirms the kernel operation.

If the helper is unavailable, requests fail and strikes remain. No successful
ban is fabricated.

If systemd restarts `goban-enforcer`, its in-memory backend handles are fresh
and its health state is `not ready`. The next typed detector operation observes
that state, performs one idempotent setup, and retries the original operation
once. The detector itself does not need to restart.

Closing the detector closes the helper's current backend handles and marks the
helper unready. A later detector start performs setup again.

## Service lifecycle

`goban.service` requires and starts `goban-enforcer.service`. The helper unit is
static (it has no independent install target), so it is not meant to be enabled
or left running on its own. The detector is ordered after the helper. The helper uses `Restart=on-failure`; a helper crash
does not grant the detector new privilege or make failed decisions count as
successful.

Package upgrades restart both processes so a mixed-version pair is never left
running. Package removal stops both services.

`goban-persist.service`, when explicitly enabled, is ordered before both the
helper and detector.

## Log permissions

Privilege separation means file permissions now matter. Package hooks add the
`goban` account to conventional read-only log groups when they exist:

- `adm`
- `systemd-journal`

Some distributions or custom log paths remain root-only. Do not solve that by
giving the detector broad filesystem capabilities. Prefer one of:

- grant the `goban` account read access to the specific log file/directory;
- use the journald-enabled build and journal permissions;
- adjust the service that produces the log to expose a dedicated read-only log.

`goban-client sources` and `goban-client doctor` surface unreadable/dead sources.

### Docker sources

Access to `/var/run/docker.sock` is effectively root-equivalent. Packages do
**not** automatically add `goban` to the `docker` group. Operators who enable
Docker-socket sources must make that trust decision explicitly. Doing so weakens
the practical privilege boundary even though the daemon still has no Linux
network capabilities.

## Direct compatibility mode

`enforcer.mode: direct` keeps the pre-split single-process architecture for:

- standalone/manual launches;
- the current host-network container image;
- troubleshooting or platforms without the packaged systemd units.

Direct mode still uses the same validated firewall backend and all existing
truthful-acknowledgement behaviour, but the daemon itself needs the network
capabilities. `goban-client doctor` labels the mode so operators can tell which
security boundary is active.

The shipped systemd package overrides the mode to `split` even when an older
configuration file has no `enforcer` section. This preserves upgrade safety.

## Verification

On a disposable Linux VM:

```bash
make build
sudo test/integration/kernel/matrix.sh
```

The matrix must prove all of the following together:

- unprivileged detector UID;
- zero effective detector capabilities;
- private helper protocol path and rejection of another UID in the same socket group;
- distinct non-root helper UID with exactly `CAP_NET_ADMIN`;
- IPv4 and IPv6;
- INPUT and FORWARD;
- iptables/ipset and native nftables;
- confirmed packet blocking;
- timeout refresh;
- `doctor --probe` health.

For an installed package, also inspect:

```bash
systemctl cat goban.service goban-enforcer.service
pid=$(systemctl show -p MainPID --value goban.service)
grep -E '^(Uid|CapEff):' /proc/$pid/status
sudo goban-client doctor --probe
```

`doctor` reads `/proc` at runtime rather than trusting unit/configuration text.
In split mode it fails the host if the detector is root, has any effective,
bounding, or ambient capability, or lacks `NoNewPrivileges`. The helper health
response is checked independently and must show a non-root UID with exactly
`CAP_NET_ADMIN` in its effective, bounding, and ambient masks.
