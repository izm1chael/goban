#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

command -v semgrep >/dev/null 2>&1 || { echo "semgrep is required (tested with 1.171.x+)" >&2; exit 2; }
command -v osv-scanner >/dev/null 2>&1 || { echo "osv-scanner is required (tested with v2.4.x+)" >&2; exit 2; }

# Run the same source-level checks used during GoBan's public-release review.
# --error makes Semgrep return non-zero when findings are present.
semgrep scan --config auto --error .
osv-scanner scan source .
