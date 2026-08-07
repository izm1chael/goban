#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
GO=${GO:-go}
"$GO" run ./cmd/goban-corpus test "$@"
