#!/usr/bin/env bash
# Static release-contract tests. These intentionally test the public-release
# invariants most likely to regress during workflow maintenance.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
workflow=.github/workflows/release.yml
readme=README.md

stable="$(scripts/release-tag-metadata.sh v1.2.3)"
grep -qx 'version=1.2.3' <<<"$stable"
grep -qx 'prerelease=false' <<<"$stable"
grep -qx 'channel=stable' <<<"$stable"

rc="$(scripts/release-tag-metadata.sh v1.2.3-rc.4)"
grep -qx 'version=1.2.3-rc.4' <<<"$rc"
grep -qx 'prerelease=true' <<<"$rc"
grep -qx 'channel=prerelease' <<<"$rc"

for invalid in 1.2.3 v1.2 v1.2.3+build v1.2.3- 'v1.2.x'; do
  if scripts/release-tag-metadata.sh "$invalid" >/dev/null 2>&1; then
    echo "invalid release tag accepted: $invalid" >&2
    exit 1
  fi
done

# RCs must be GitHub prereleases and must never move the GHCR latest tag.
grep -Fq "prerelease: \${{ needs.metadata.outputs.prerelease == 'true' }}" "$workflow"
grep -Fq "make_latest: \${{ needs.metadata.outputs.prerelease == 'true' && 'false' || 'true' }}" "$workflow"
grep -Fq 'flavor: latest=false' "$workflow"
! grep -Fq 'type=raw,value=latest' "$workflow"
grep -Fq 'promote-latest:' "$workflow"
grep -Fq "if: needs.metadata.outputs.prerelease == 'false'" "$workflow"
grep -Fq 'needs: [metadata, docker, release]' "$workflow"
grep -Fq '"${IMAGE_NAME}:latest"' "$workflow"

# All split-mode binaries must be attached, and release assets must be flat so
# the downloaded SHA256SUMS manifest is directly usable.
grep -Fq 'mv bin/goban-enforcer "bin/goban-enforcer-linux-$ARCH"' "$workflow"
grep -Fq 'files: release-assets/*' "$workflow"
grep -Fq 'fail_on_unmatched_files: true' "$workflow"
grep -Fq 'scripts/stage-release-assets.sh' "$workflow"

# Container releases carry both BuildKit attestations and a keyless signature.
grep -Fq 'provenance: mode=max' "$workflow"
grep -Fq 'sbom: true' "$workflow"
grep -Fq 'cosign sign --yes "${IMAGE_NAME}@${DIGEST}"' "$workflow"

# Publication must remain downstream of kernel and package lifecycle proof.
grep -Fq 'needs: [metadata, packages, docker, kernel, package-smoke]' "$workflow"

# Public documentation must describe the channel semantics we enforce above.
grep -Fq 'Pre-release tags never update the container `latest` tag.' "$readme"
grep -Fq 'Stable tags promote `latest` only after the versioned GitHub release has been successfully created.' "$readme"

echo 'release workflow contract: PASS'
