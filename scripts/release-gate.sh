#!/usr/bin/env bash
set -Eeuo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"
EVIDENCE_DIR=${RELEASE_EVIDENCE_DIR:-dist/release-evidence}
mkdir -p "$EVIDENCE_DIR"

missing=()
for f in kernel-matrix.txt package-matrix.txt; do
  if [[ ! -s "$EVIDENCE_DIR/$f" ]] || ! grep -q 'PASS:' "$EVIDENCE_DIR/$f"; then
    missing+=("$f")
  fi
done
if [[ ! -s "$EVIDENCE_DIR/soak/report.json" ]]; then
  missing+=("soak/report.json")
else
  python3 - "$EVIDENCE_DIR/soak/report.json" <<'PY' || missing+=("soak/report.json(pass)")
import json,sys
p=sys.argv[1]
d=json.load(open(p))
# goban-soak reports may use either status/pass or hard_failures depending on version.
status=str(d.get('status','')).lower()
if status and status not in ('pass','passed','healthy'):
    raise SystemExit(1)
if d.get('hard_failures', 0):
    raise SystemExit(1)
PY
fi

if ((${#missing[@]})); then
  echo "NON-PRIVILEGED RELEASE GATES: PASS"
  echo "RELEASE BLOCKED: attach passing privileged/soak evidence under $EVIDENCE_DIR:" >&2
  printf '  - %s\n' "${missing[@]}" >&2
  echo "Commands:" >&2
  echo "  sudo test/integration/kernel/matrix.sh | tee $EVIDENCE_DIR/kernel-matrix.txt" >&2
  echo "  test/integration/package/run.sh | tee $EVIDENCE_DIR/package-matrix.txt" >&2
  echo "  goban-soak run ... && copy report.json/report.md to $EVIDENCE_DIR/soak/" >&2
  exit 2
fi

echo "PASS: GoBan release gate has non-privileged, kernel, package, and soak evidence"
