#!/usr/bin/env bash
# Performance benchmark suite. Drives ariguard-bench against the loaded agent and writes a results
# table (RESULTS.md) with the three figures that matter for the thesis:
#   - detector overhead per hooked syscall (in-kernel BPF run-time, ns/event)
#   - throughput (matched events/sec before the audit ring drops)
#   - flat memory (agent RSS + the constant BPF map budget) vs workload count
#
# Run in the VM as root with the agent loaded (BPF run-time stats are a system toggle this enables):
#   limactl shell statewall sudo WINDOW=8s bash tests/bench/run.sh
# NOT a CI gate (needs a live kernel + agent); the deterministic perf guards are the Go benchmarks.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BENCH="$ROOT/bin/ariguard-bench"
WINDOW="${WINDOW:-8s}"
SOCK="/var/run/docker.sock"   # matches the container-escape openat binding → counts as an event
# The agent's Prometheus endpoint. On a kind cluster port-forward the agent pod's :9102 here first,
# or set METRICS_URL to the pod IP. SWEEP stays modest by default; a big sweep needs a big box.
METRICS_URL="${METRICS_URL:-http://127.0.0.1:9102/metrics}"
SWEEP="${SWEEP:-1,10,50,100}"
OUT="$HERE/results"
mkdir -p "$OUT"

[ -x "$BENCH" ] || { echo "build it first: make build-bench" >&2; exit 1; }

LOADPIDS=""
start_load() {   # background matched-syscall load for the latency window
  local n="${1:-4}" i
  for ((i = 0; i < n; i++)); do
    python3 -c "
import os
while True:
    try:
        os.close(os.open('$SOCK', os.O_RDONLY))
    except OSError:
        pass
" 2>/dev/null &
    LOADPIDS="$LOADPIDS $!"
  done
}
stop_load() { [ -n "$LOADPIDS" ] && kill $LOADPIDS 2>/dev/null; LOADPIDS=""; }
trap stop_load EXIT

echo "[bench] detector overhead per hook (window $WINDOW)" >&2
start_load 4
sleep 1
"$BENCH" latency --window "$WINDOW" --out "$OUT/latency.csv"
stop_load

echo "[bench] throughput (window $WINDOW)" >&2
"$BENCH" throughput --window "$WINDOW" --metrics-url "$METRICS_URL" --out "$OUT/throughput.csv"

echo "[bench] flat-memory curve (sweep $SWEEP)" >&2
"$BENCH" memcurve --sweep "$SWEEP" --out "$OUT/memcurve.csv"

python3 - "$OUT" "$HERE/RESULTS.md" "$WINDOW" <<'PY'
import csv, sys, datetime, pathlib
out, results, window = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]

def rows(name):
    p = out / name
    return list(csv.DictReader(p.open())) if p.exists() else []

lat = sorted(rows("latency.csv"), key=lambda r: -int(r["run_count"] or 0))
thr = rows("throughput.csv")
mem = rows("memcurve.csv")
NOISE = 1000  # a hook with fewer runs than this is too few samples to trust its ns/run

L = ["# AriGuard — performance benchmark results\n",
     f"Run {datetime.datetime.now(datetime.UTC).isoformat(timespec='seconds')} on a live agent "
     f"(window {window}). Overhead is the in-kernel BPF run-time per hooked syscall, from "
     "`BPF_STATS_RUN_TIME`; wall-clock syscall latency is deliberately avoided (noisy).\n"]

L += ["## Detector overhead — per-hook BPF run-time\n",
      "ns/event is the in-kernel time the hook's program adds per matching syscall. Rows with few "
      f"runs (< {NOISE}) are low-sample and noisy; trust the high-run hooks.\n",
      "| program | runs | total ns | **ns / event** | |", "|---|---|---|---|---|"]
for r in lat:
    runs = int(r["run_count"])
    tag = "" if runs >= NOISE else ("idle" if runs == 0 else "noisy")
    L.append(f"| {r['program']} | {runs} | {r['run_time_ns']} | **{float(r['ns_per_run']):.0f}** | {tag} |")
solid = [r for r in lat if int(r["run_count"]) >= NOISE]
if solid:
    head = max(solid, key=lambda r: float(r["ns_per_run"]))
    L.append(f"\nHeadline (well-sampled): **{head['program']}** at **{float(head['ns_per_run']):.0f} "
             f"ns/event** over {head['run_count']} runs — the detector's per-syscall cost on the hot "
             "path, and the synchronous-kill cost (the SIGKILL is queued inside this same run).\n")

L += ["## Throughput\n", "| events/sec | events in window | audit dropped |", "|---|---|---|"]
for r in thr:
    L.append(f"| {float(r['events_per_sec']):.0f} | {r['events_total_delta']} | {r['audit_dropped_delta']} |")

L += ["\n## Flat memory vs workload count\n",
      "| workloads | agent RSS (KB) | BPF map bytes | state entries |", "|---|---|---|---|"]
for r in mem:
    L.append(f"| {r['n']} | {r['agent_rss_kb']} | {r['bpf_map_bytes']} | {r['state_entries']} |")
if mem:
    mb = {r['bpf_map_bytes'] for r in mem}
    L.append(f"\nBPF map budget is **constant** ({'flat' if len(mb) == 1 else 'VARIED: ' + ','.join(mb)}) "
             "across the sweep — pre-allocated, independent of workload count.\n")

pathlib.Path(results).write_text("\n".join(L) + "\n")
print("\n".join(L))
PY
echo "[bench] wrote $HERE/RESULTS.md" >&2
