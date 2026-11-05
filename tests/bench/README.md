# Performance benchmarks

Two layers: deterministic Go micro-benchmarks (CPU hot paths, CI-safe) and a live-kernel suite that
drives `ariguard-bench` against a running agent.

## Go micro-benchmarks (deterministic, no kernel)

```sh
make bench-go
```
`pkg/fsm` benchmarks the bundle decode (every control-plane hot-swap) and binding grouping. Fast,
allocation-aware, and a guard against perf regressions in the policy path. Sample:

```
BenchmarkUnmarshalBundle   19654 ns/op   311 MB/s   14076 B/op   90 allocs/op
BenchmarkGroupBindings       878 ns/op     0 B/op    0 allocs/op
```

## Live suite (`ariguard-bench`, in the VM as root)

```sh
# port-forward the agent's Prometheus endpoint first (for throughput):
kubectl -n ariguard-system port-forward <agent-pod> 9102:9102 &
limactl shell statewall sudo WINDOW=8s SWEEP=1,10,50,100 \
  METRICS_URL=http://127.0.0.1:9102/metrics bash tests/bench/run.sh
```

Writes [`RESULTS.md`](RESULTS.md) with three figures:

| metric | what it is |
|---|---|
| **detector overhead** | in-kernel BPF run-time per hooked syscall (`BPF_STATS_RUN_TIME`, ns/event). The busiest well-sampled hook is also the synchronous-kill cost — the `SIGKILL` is queued inside that same program run. |
| **throughput** | matched events/sec before the audit ring drops (`audit_dropped` must stay 0). |
| **flat memory** | agent RSS + the **constant** pre-allocated BPF map budget vs workload count — the basis for the "scales to many workloads" claim. |

Not a CI gate (needs a live kernel + agent, and the `memcurve` load is heavy — keep `SWEEP` modest
on a small box). The deterministic guard is `make bench-go`. Wall-clock syscall latency is
deliberately not measured (noisy); overhead is the amortized BPF run-time instead.

## Notes
- `SWEEP` higher than ~100 can overload a dev VM (each worker is a process in its own cgroup).
- `ns/event` rises under heavy concurrent load (CPU contention); the committed `RESULTS.md` was taken
  under load, so it is an upper bound, not a best case.
