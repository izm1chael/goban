# Release artifacts and provenance

Tagged releases build static linux/amd64 and linux/arm64 binaries, Debian/RPM/
Arch packages, and a multi-architecture container image. The release workflow
also produces:

- SHA-256 checksums;
- SPDX JSON software bills of materials;
- GitHub build-provenance attestations;
- a keyless Sigstore bundle signing the SHA-256 manifest;
- generated release notes.

Local maintainers can verify reproducibility with:

```bash
make reproducible VERSION=1.0.0-rc1
```

The script builds every GoBan binary twice with `-trimpath` and
`-buildvcs=false` and requires byte-for-byte identity.

Artifact provenance does not replace package-signing infrastructure for an APT
or RPM repository. When those repositories are introduced, repository metadata
and packages must be signed using keys held outside the build runner, with a
published rotation and revocation procedure.

Verify the checksum manifest with Cosign:

```bash
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp 'https://github.com/izm1chael/goban/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum -c SHA256SUMS
```
