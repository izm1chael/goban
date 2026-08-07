#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT_DIR"

# Security invariants are intentionally named, stable release gates. If one is
# renamed or removed this script fails rather than silently reducing coverage.
go test ./internal/rule -run '^TestRule_(FailedBanDoesNotResetOrEmitSuccess|AllowlistedNotBanned|ForwardedClientRequiresTrustedProxy)$' -count=25
go test ./internal/enforcer -run '^Test(PolicyRejectsProtectedAddresses|PolicyReloadVerifiesFingerprintBeforeSwap|ServerRejectsUnknownJSONFields|ServerAutomaticallyRepairsDetectedFirewallDrift|ServerStopWaitsForReconcileLoopBeforeBackendClose)$' -count=20
go test ./internal/banner -run '^TestNFTablesRepairRefusesNonOwnedTable$' -count=20
go test ./internal/config -run '^TestNFTablesAutomaticReconciliationRequiresOwnedTableNamespace$' -count=20
go test ./internal/privilege -run '^TestPrivilegeInvariants$' -count=20
go test ./internal/daemon -run '^Test(CutoverRecordingCountsOnlyWhileEnabled|ImmutableReloadSettings)$' -count=20

echo "PASS: security invariants"
