#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT_DIR"
FUZZTIME=${FUZZTIME:-30s}

# Repeated races target shutdown/reload/queue interactions.
make test-fault
make test-reload
make test-invariants

# Attacker-controlled bytes must never panic or escape the bounded-ingestion
# contract. Each fuzz target gets an independent budget for useful corpus
# evolution and reproducible crash artifacts.
go test ./internal/matcher -run '^$' -fuzz FuzzMatcherNeverPanics -fuzztime "$FUZZTIME"
go test ./internal/source -run '^$' -fuzz FuzzBoundedAccumulatorNeverExceedsLimit -fuzztime "$FUZZTIME"
go test ./internal/datepattern -run '^$' -fuzz FuzzResolveNeverPanics -fuzztime "$FUZZTIME"

echo "PASS: chaos/race/fuzz gate"
