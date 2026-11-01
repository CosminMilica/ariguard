# Phase 4 — Evaluation (our-metrics-first)

Status: in progress. Goal: produce the **evidence** for AriGuard's claims with a reproducible
harness that measures **our own system** — overhead, the flat memory curve, throughput, and
efficacy. Comparison vs Falco/Tetragon is deferred (hooks for it are left open). The harness
doubles as a **stress/soak test**, so it also strengthens the test suite.

## What we measure (our-only, this phase)
1. **Overhead — per-program latency.** The eBPF programs' run-time via the kernel's BPF
   run-time stats (`BPF_ENABLE_STATS` / `prog.Stats()` — already used in the integration
   harness): `run_time_ns / run_count` = average ns per event, per hook. Clean and defensible
   (no wall-clock noise). Report per-hook ns + total events.
2. **Flat memory curve (headline systems result).** Total AriGuard memory as the number of
   tracked workloads grows (N = 1, 10, 100, 1000, …): agent user-space RSS + kernel BPF map
   memory (`bytes_memlock`, pre-allocated and therefore constant). Plot memory-vs-N → show it
   is **flat** because maps are fixed-size and zero-allocation. This is the core claim.
3. **Throughput / drop-free rate.** Drive a high syscall-event rate and record
   `ariguard_events_total` (events/sec) and `ariguard_audit_dropped_total` — find the rate at
   which drops begin (ideally none within budget). Confirms bounded behavior under load.
4. **Efficacy on our corpus.** Detection rate (all 7 chains detected) and **false-positive
   rate** (benign workloads + the benign twins → false detections). Reuse the audit stream +
   `check_audit.py`; report rates, not just pass/fail.

## Harness
```
cmd/ariguard-bench/           # Go CLI (uses cilium/ebpf like the integration harness)
  latency    # enable BPF stats, sample prog run_time_ns/run_count over a window -> CSV
  memcurve   # sweep N load workers, sample agent RSS + BPF map memlock -> CSV
  throughput # drive load, sample events/sec + audit_dropped -> CSV
testdata/bench/
  load-gen            # spawns N worker processes (benign syscall loop, one cgroup each)
  plot.py            # matplotlib: flat memory curve + overhead bars from the CSVs
  results/           # committed CSVs + generated plots (the evidence artifacts)
Makefile: bench-latency / bench-memcurve / bench-throughput / bench-efficacy (run in the VM)
```
Metrics sources already emitted by the agent: `/metrics` (events, kills, denies,
audit_dropped) + per-program `prog.Stats()` + `bytes_memlock` per map (bpftool/cilium).

## Waves
1. **Sampler** (`cmd/ariguard-bench latency` + `metrics`): read BPF run-time stats + poll
   `/metrics` + sample agent RSS → CSV. Foundation.
2. **Load generator** (`testdata/bench/load-gen`): spawn N worker processes in their own
   cgroups doing a benign syscall loop (so `AG_STATE` tracks them); configurable N + rate.
3. **Memory curve** (`memcurve`): sweep N, sample agent RSS + BPF map memlock, CSV + `plot.py`
   → the flat curve. The money plot.
4. **Overhead + throughput**: per-hook ns/event under load; drop-free event rate.
5. **Efficacy**: detection + false-positive rates from the attack/benign corpus (reuse
   `check_audit.py`), reported as numbers.
6. **Results**: commit CSVs + plots under `testdata/bench/results/`; a short results note
   mapping numbers to the thesis claims.

## Reuse as testing
`memcurve` at high N and `throughput` at high rate are a **stress/soak** check: confirm memory
stays within the fixed budget and `audit_dropped == 0`. These can become a (manual/VM) gate.

## Honest caveats
- Wall-clock syscall latency is noisy → we use BPF run-time stats for the overhead number.
- Reaching high N for the curve needs lightweight workers (not full pods); kind/VM limits the
  absolute ceiling, but the trend (flat) is the point.
- Efficacy FP rate depends on how representative the benign corpus is; we report the corpus we
  used, not an absolute real-world rate.
- Falco/Tetragon comparison is deferred; the harness leaves a slot to add it later.
