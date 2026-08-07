#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

fail() { echo "security policy: $*" >&2; exit 1; }

# GitHub Actions execute third-party code in privileged CI contexts. Require
# immutable 40-character commit IDs; version comments are kept for humans and
# Dependabot maintenance.
while IFS= read -r ref; do
  target=${ref%%#*}
  target=${target%[[:space:]]}
  [[ "$target" =~ @[0-9a-f]{40}$ ]] || fail "mutable GitHub Action reference: $ref"
done < <(grep -RhoE 'uses:[[:space:]]+[^[:space:]#]+@[^[:space:]#]+([[:space:]]*#[[:space:]]*[^[:space:]]+)?' .github/workflows | sed -E 's/^uses:[[:space:]]+//')

# The legacy monolithic Docker module is intentionally forbidden. It includes
# daemon/server code GoBan does not use and has advisories with no fixed release
# on that module line. GoBan consumes only the supported Moby client/API modules.
if grep -Eq 'github\.com/docker/docker([[:space:]]|/)' go.mod; then
  fail "legacy github.com/docker/docker module reintroduced"
fi
grep -q 'github.com/moby/moby/client v' go.mod || fail "supported Moby client module missing"
grep -q 'github.com/moby/moby/api v' go.mod || fail "supported Moby API module missing"

# Dependabot must delay newly-published versions for both dependency ecosystems.
[[ $(grep -c 'default-days:[[:space:]]*7' .github/dependabot.yml) -eq 2 ]] || fail "Dependabot 7-day cooldown missing"

# The corpus PRNG must remain explicitly deterministic and non-cryptographic
# without using math/rand, which generic security scanners correctly discourage
# in production security-sensitive code.
! grep -Rq '"math/rand"' internal/corpus || fail "math/rand reintroduced in corpus generator"

# Background soak execution is deliberately a self-reexec through the Linux
# kernel's static procfs path, never a user-controlled executable string.
grep -q 'exec.Command("/proc/self/exe", childArgs\.\.\.)' cmd/goban-soak/main.go || fail "soak self-reexec invariant changed"

echo "Static security policy: PASS"
