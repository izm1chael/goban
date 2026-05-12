#!/usr/bin/env bash
# Run the full soak matrix sequentially.
#   sudo bash soak-suite.sh [duration_per_cell]
# Default duration is 1800s (30min) per cell. 4 cells = 2h total.
set -euo pipefail
DURATION="${1:-1800}"
cd "$(dirname "$0")"

if [[ $EUID -ne 0 ]]; then
  echo "must run as root" >&2
  exit 1
fi

# Kill any prior daemons / services so they don't compete.
systemctl stop fail2ban 2>/dev/null || true
killall -q -TERM goban-daemon fail2ban-server 2>/dev/null || true
sleep 1
killall -q -KILL goban-daemon fail2ban-server 2>/dev/null || true

cells=(
  "goban native"
  "goban container"
  "fail2ban native"
  "fail2ban container"
)

echo "Soak suite: $DURATION sec/cell, ${#cells[@]} cells, est. wall time $(( DURATION * ${#cells[@]} / 60 )) min"
echo

for spec in "${cells[@]}"; do
  read -r daemon cell <<<"$spec"
  echo "=== Starting $daemon / $cell ==="
  if ! bash soak.sh "$daemon" "$cell" "$DURATION"; then
    echo "FAILED: $daemon / $cell"
  fi
  echo
  # Give the kernel a moment to settle between cells, and ipset to drain.
  sleep 5
done

echo
echo "=== FINAL SUMMARIES ==="
for f in results/soak-*.summary; do
  [[ -f "$f" ]] || continue
  echo "--- $(basename "$f" .summary)"
  cat "$f"
  echo
done

echo "Run ./analyze.sh to render comparison table and ASCII RSS plots."
