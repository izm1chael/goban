#!/usr/bin/env bash
# Render a comparison table + ASCII RSS-over-time plots from the soak results.
# Usage: ./analyze.sh
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

python3 <<'PY'
import csv, glob, os, statistics

cells = []
for path in sorted(glob.glob("results/soak-*.csv")):
    base = os.path.basename(path)[5:-4]  # strip "soak-" and ".csv"
    parts = base.split("-")
    if len(parts) < 2:
        continue
    daemon, cell = parts[0], "-".join(parts[1:])
    t, cpu, rss = [], [], []
    with open(path) as f:
        r = csv.DictReader(f)
        for row in r:
            try:
                t.append(float(row["t_sec"]))
                cpu.append(float(row["cpu_pct"]))
                rss.append(float(row["rss_kb"]))
            except (ValueError, KeyError):
                pass
    cells.append((daemon, cell, t, cpu, rss))

def stats(xs):
    if not xs: return {"mean": 0, "p50": 0, "p99": 0, "max": 0}
    s = sorted(xs)
    return {
        "mean": statistics.mean(xs),
        "p50": s[len(s)//2],
        "p99": s[min(len(s)-1, int(len(s)*0.99))],
        "max": max(xs),
    }

print()
print("=== Soak summary ===")
print(f"{'scenario':<28} {'samples':>8} {'cpu_mean%':>10} {'cpu_p99%':>10} {'cpu_max%':>10} {'rss_mean_mb':>12} {'rss_p99_mb':>12} {'rss_max_mb':>12} {'rss_growth_mb':>14}")
print("-" * 140)
for daemon, cell, t, cpu, rss in cells:
    if not rss:
        print(f"{daemon}-{cell:<22} {'(empty)':>8}")
        continue
    cstats = stats([c for c in cpu if c > 0])
    rstats = stats(rss)
    # Memory growth: difference between mean of last 60s vs mean of first 60s
    if len(t) > 60:
        early = rss[5:65]
        late = rss[-65:-5] if len(rss) > 130 else rss[-60:]
        growth_kb = statistics.mean(late) - statistics.mean(early)
    else:
        growth_kb = 0
    print(f"{daemon}-{cell:<22} {len(t):>8} {cstats['mean']:>10.2f} {cstats['p99']:>10.2f} {cstats['max']:>10.2f} "
          f"{rstats['mean']/1024:>12.1f} {rstats['p99']/1024:>12.1f} {rstats['max']/1024:>12.1f} {growth_kb/1024:>14.2f}")

# ASCII plot of RSS over time
def asciiplot(label, t, y, height=12, width=80):
    if not y: return
    y_min, y_max = min(y), max(y)
    if y_max == y_min: y_max = y_min + 1
    print(f"\n--- {label} : RSS (MB) over time, y=[{y_min/1024:.0f},{y_max/1024:.0f}] ---")
    # Resample to width buckets
    buckets = [[] for _ in range(width)]
    for ti, yi in zip(t, y):
        idx = min(width - 1, int(ti / t[-1] * (width - 1))) if t[-1] > 0 else 0
        buckets[idx].append(yi)
    means = [statistics.mean(b)/1024 if b else None for b in buckets]
    rows = [[" "] * width for _ in range(height)]
    for x, v in enumerate(means):
        if v is None: continue
        norm = (v - y_min/1024) / (y_max/1024 - y_min/1024)
        row = height - 1 - int(norm * (height - 1))
        rows[row][x] = "*"
    for row in rows:
        print("  | " + "".join(row))
    print("  +" + "-" * width)
    print(f"  0s{' '*(width-6)}{int(t[-1])}s")

for daemon, cell, t, cpu, rss in cells:
    asciiplot(f"{daemon}/{cell}", t, rss)
PY
