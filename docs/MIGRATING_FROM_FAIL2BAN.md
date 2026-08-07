# Migrating from Fail2Ban

GoBan's migration command is deliberately conservative. It converts only
reviewed jail mappings and writes a staging directory. It never disables
Fail2Ban, enables GoBan, edits `/etc/goban`, or changes the firewall.

```bash
sudo goban-client migrate fail2ban \
  --root /etc/fail2ban \
  --out /root/goban-migration
```

The staging directory contains:

- `goban.yaml` — proposed GoBan configuration;
- `rules.d/` — only the selected reviewed rules;
- `migration-report.yaml` — converted, review, and unsupported items;
- `README.md` — validation and rollback instructions.

## Supported automatic mappings

The first release covers the common reviewed families: OpenSSH, Nginx HTTP
authentication and probes, Apache authentication/noscript/overflow rules,
Postfix SASL, Dovecot, vsftpd, Traefik authentication, Nextcloud, Portainer,
WordPress authentication, and recidive.

A custom Fail2Ban filter or action is not translated into executable GoBan
configuration. It is listed as unsupported so an operator cannot mistake a
best-effort guess for protection.

## Safe cutover

1. Back up `/etc/fail2ban`, `/etc/goban`, and current firewall state.
2. Validate the staged files:

   ```bash
   goban-client config validate \
     --config /root/goban-migration/goban.yaml \
     --rules-dir /root/goban-migration/rules.d
   ```

3. On native systemd packages, keep the packaged split mode so the GoBan
   detector remains unprivileged. Run GoBan with `dry_run: true` while Fail2Ban
   remains the sole enforcer.
4. Compare GoBan matches with Fail2Ban decisions and investigate differences.
5. Confirm `goban-client doctor` is healthy. Use `--probe` only on a controlled
   host where temporary test-set modification is acceptable.
6. During a maintenance window, stop Fail2Ban, enable GoBan enforcement, and
   confirm both host-input and forwarded-container paths.
7. Keep rollback instructions and the previous configuration available.

Do not leave both products enforcing the same log stream. They can otherwise
fight over firewall ownership, duplicate decisions, and make incident review
ambiguous.

## Known conversion boundaries

- Fail2Ban interpolation, DNS names in `ignoreip`, and custom Python filters
  require review.
- Arbitrary actions, mail notifications, shell commands, and service-specific
  port actions are reported but not recreated.
- GoBan decisions are IP-based and expire in kernel sets. A jail whose primary
  purpose is not temporary IP enforcement is outside the migration scope.
- Fail2Ban configuration precedence is approximated in documented order:
  `jail.conf`, `jail.d/*.conf`, `jail.local`, then `jail.d/*.local`.

## Privilege change from typical Fail2Ban deployments

Native GoBan packages intentionally do not run the log parser as root. If a
Fail2Ban jail currently reads a root-only file, migration may need a narrow file
ACL/group change or the journald-enabled GoBan build. `goban-client sources`
and `doctor` must be healthy before cutover. Do not grant broad filesystem
capabilities merely to reproduce a root-running legacy layout.
