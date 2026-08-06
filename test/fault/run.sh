#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT_DIR"

# Repeat the lifecycle-sensitive packages under the race detector. Counts are
# intentionally higher than ordinary CI so rare close/reload interleavings are
# more likely to surface before a release candidate is tagged.
go test -race -count=20 ./internal/source/... ./internal/tracker ./internal/rule ./internal/banner ./internal/control
go test -race -count=50 -run 'Test(Cutover|Reload|Hub|FileSource)' ./internal/daemon ./internal/source/...

# Corrupt/old state and timestamp fail-closed behavior are explicit release
# gates rather than incidental unit coverage.
go test -count=20 -run 'Test(LoadVersionMismatch|LoadWithFingerprintRejectsChangedRule|SweepUsesNewestTimestamp)' ./internal/tracker
go test -count=20 -run 'TestRule_Datepattern(DriftDropsByDefault|ParseFailureDropsByDefault)' ./internal/rule

echo "PASS: repeated fault/lifecycle test suite"
