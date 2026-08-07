# Supported platforms

GoBan targets modern Linux hosts. Release support is earned by passing the
kernel, package, upgrade, and soak matrix; documentation alone does not make a
platform supported.

## Release-candidate matrix

| Area | Required coverage |
|---|---|
| Architectures | linux/amd64, linux/arm64 |
| Packaging | Debian package, RPM package, Arch package, container image |
| Firewall | nftables; iptables with ipset compatibility |
| Network path | host INPUT and forwarded/container traffic |
| Address family | IPv4 and IPv6 |
| Sources | file, systemd journal build, Docker logs |
| Service packs | reviewed core bundles with corpus fixtures |

A distribution version should be named as supported only after a fresh install,
upgrade-preservation test, service lifecycle test, `doctor --probe`, and an
appropriate soak have passed on that version.

Windows, macOS, Kubernetes operators, cloud firewall APIs, and eBPF/XDP are not
part of the 1.0 support contract.
