# Guided setup

`goban-client setup` detects the host and proposes a conservative, dry-run
configuration. Without `--write` it prints observations only.

```bash
goban-client setup
sudo goban-client setup --write --out /root/goban-setup
```

Detection covers:

- distribution and version;
- systemd/journald availability;
- nftables or iptables+ipset;
- IPv6;
- Docker presence;
- existing Fail2Ban installation;
- common OpenSSH, Nginx, Apache, and mail log locations.

The command does not start services, insert firewall rules, or overwrite the
live configuration. The staged configuration always begins with `dry_run: true`. On systemd hosts
it also proposes `enforcer.mode: split`, matching the packaged zero-capability
detector + privileged-helper architecture.

Review all warnings. In particular, Docker application rules require explicit
container names or labels and reverse-proxy rules require trusted-proxy
configuration. In split mode the package does not grant `goban` access to
`docker.sock`; Docker-group access is effectively root-equivalent and must be a
deliberate operator choice. Custom root-only log paths also need narrow read
permissions for the unprivileged detector. Auto-detection cannot safely infer
those security boundaries.

Validate the proposal before copying it:

```bash
goban-client config validate \
  --config /root/goban-setup/goban.yaml \
  --rules-dir /root/goban-setup/rules.d
```
