# Release artifacts and provenance

A tag must match `vMAJOR.MINOR.PATCH` or
`vMAJOR.MINOR.PATCH-PRERELEASE` before the release workflow performs any
publication work. Build metadata (`+foo`) is intentionally not accepted because
the same version is also used as a portable container tag.

## Release channels

Pre-release tags such as `v1.0.0-rc.1` create a GitHub pre-release and GHCR
version tags (`v1.0.0-rc.1` and `1.0.0-rc.1`). They never move the GHCR
`latest` tag and are never marked as the repository's latest stable release.

Stable tags such as `v1.0.0` create a normal GitHub release and GHCR tags
`v1.0.0`, `1.0.0`, and `1.0`. After the versioned GitHub release is successfully
created, a final promotion job points `latest` at the exact already-signed image digest.

## Publication gates

The publish jobs are downstream of:

- full non-privileged verification, race tests, corpus, invariants, and chaos;
- the eight-way iptables/nftables + INPUT/FORWARD + IPv4/IPv6 kernel matrix;
- package install/lifecycle smoke tests.

A failed required job prevents both the GitHub Release and the stable/RC GHCR
publication path from completing.

## Downloadable artifacts

Tagged releases build Linux `amd64` and `arm64` standalone binaries for the
following tools:

- `goban-daemon`;
- `goban-enforcer`;
- `goban-client`;
- `goban-corpus`;
- `goban-soak`.

They also build Debian, RPM, and Arch packages plus SPDX JSON SBOMs. Native
packages use privilege separation, while the current single-container image
remains the documented direct-mode compatibility deployment.

All public files are staged into one flat directory before the checksum
manifest is generated. Consequently, users who download release assets into a
single directory can verify them directly with `sha256sum -c SHA256SUMS`; the
manifest does not contain internal CI paths such as `dist/`.

The release also contains:

- `RELEASE-MANIFEST.txt` with the tag, version, channel, commit, and immutable
  container reference;
- `docker-image.txt` with `ghcr.io/izm1chael/goban@sha256:...`;
- `SHA256SUMS`;
- `SHA256SUMS.sigstore.json`.

## Provenance and signing

Release files receive GitHub provenance attestations. The checksum manifest is
signed using keyless Sigstore OIDC. The multi-architecture GHCR image is built
with BuildKit provenance and SBOM attestations and its immutable digest is also
signed with keyless Cosign.

Local maintainers can verify reproducibility with:

```bash
make reproducible VERSION=1.0.0-rc.1
```

The script builds every GoBan binary twice with `-trimpath` and
`-buildvcs=false` and requires byte-for-byte identity.

Artifact provenance does not replace package-signing infrastructure for an APT
or RPM repository. When those repositories are introduced, repository metadata
and packages must be signed using keys held outside the build runner, with a
published rotation and revocation procedure.

Verify downloaded release assets with:

```bash
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp 'https://github.com/izm1chael/goban/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum -c SHA256SUMS
```

The immutable container reference is recorded in `docker-image.txt`; Cosign can
be used to verify the image signature against the GitHub Actions OIDC identity.
