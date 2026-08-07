# Security Policy

## Threat model

GoBan's packaged systemd deployment uses privilege separation. The process that
parses attacker-controlled logs (`goban-daemon`) runs as the dedicated `goban`
user with no effective Linux capabilities. Firewall mutation is isolated in the
small `goban-enforcer` helper, which runs as a separate non-login user, receives
only typed decisions over a private Unix socket, and holds only `CAP_NET_ADMIN`.

See `docs/PRIVILEGE_SEPARATION.md` for the privilege boundary details.

Important boundaries:

- Log lines are untrusted data and are never interpreted as commands.
- The helper accepts no arbitrary shell command or firewall expression.
- The helper socket is mode `0660` between the separate helper/detector identities,
  and accepted peers are independently checked with Linux `SO_PEERCRED`.
- The helper independently re-applies global/local/per-rule allowlist safety
  checks before accepting a ban.
- Matching uses Go's RE2 engine and input records are bounded before matching.
- The kernel firewall is authoritative for whether a decision is active; GoBan
  never records a successful ban before the backend confirms it.
- Access to `/var/run/docker.sock` is effectively root-equivalent and weakens
  the practical isolation of an otherwise unprivileged detector. Packages do
  not grant Docker-group membership automatically.
- `enforcer.mode: direct` remains a compatibility mode and requires the daemon
  itself to have firewall privilege. Native systemd packages use split mode.

Privilege separation contains root/kernel capability; it does not make a fully
compromised `goban` process harmless. Such a process can still request typed
bans of non-protected addresses or unbans. The helper's purpose is to prevent
that compromise from becoming arbitrary root command execution or arbitrary
netfilter programming.

## Supported versions

The latest minor release line receives security fixes. Older releases are
supported on a best-effort basis only.

## Reporting a vulnerability

**Do NOT open a public GitHub issue for security reports.** Use GitHub's private
vulnerability reporting workflow:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Fill in the form; the maintainer is notified privately.

The maintainer will acknowledge within 7 days. Public disclosure happens after
a fix is released, coordinated with the reporter through the resulting GitHub
Security Advisory.

GitHub Security Advisories are the only supported reporting channel. No email
address is published, and unsolicited reports sent elsewhere may be overlooked.

## What counts as a vulnerability

In scope:

- bypass of global/local/per-rule protected-address checks;
- unauthorised access to the enforcer Unix socket or peer-credential bypass;
- a way for typed enforcer input to become arbitrary firewall expressions or
  command execution;
- privilege escalation from the unprivileged detector/control identity;
- protocol confusion that causes a false successful-ban acknowledgement;
- crashes or resource exhaustion triggered by adversarial log/protocol input;
- memory-safety or state-corruption issues in direct netlink clients;
- package/service permissions that unexpectedly restore broad privileges to
  `goban-daemon`.

Out of scope for private security reporting (use a regular issue):

- feature requests;
- requests to support additional service log formats;
- performance concerns outside documented operating limits;
- documentation-only errors with no security consequence.
