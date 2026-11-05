# AriGuard — performance benchmark results

Run 2026-11-05T11:42:39+00:00 on a live agent (window 8s). Overhead is the in-kernel BPF run-time per hooked syscall, from `BPF_STATS_RUN_TIME`; wall-clock syscall latency is deliberately avoided (noisy).

## Detector overhead — per-hook BPF run-time

ns/event is the in-kernel time the hook's program adds per matching syscall. Rows with few runs (< 1000) are low-sample and noisy; trust the high-run hooks.

| program | runs | total ns | **ns / event** | |
|---|---|---|---|---|
| sw_openat | 10123920 | 33117126002 | **3271** |  |
| sw_bpf | 24807 | 81151729 | **3271** |  |
| sw_connect | 155 | 2044793 | **13192** | noisy |
| sw_dup3 | 16 | 94750 | **5921** | noisy |
| sw_execve | 16 | 72707 | **4544** | noisy |
| sw_dup2 | 0 | 0 | **0** | idle |
| sw_execveat | 0 | 0 | **0** | idle |
| sw_finit_module | 0 | 0 | **0** | idle |
| sw_fsmount | 0 | 0 | **0** | idle |
| sw_init_module | 0 | 0 | **0** | idle |
| sw_memfd_create | 0 | 0 | **0** | idle |
| sw_mount | 0 | 0 | **0** | idle |
| sw_move_mount | 0 | 0 | **0** | idle |
| sw_ptrace | 0 | 0 | **0** | idle |
| sw_setns | 0 | 0 | **0** | idle |
| sw_unshare | 0 | 0 | **0** | idle |

Headline (well-sampled): **sw_openat** at **3271 ns/event** over 10123920 runs — the detector's per-syscall cost on the hot path, and the synchronous-kill cost (the SIGKILL is queued inside this same run).

## Throughput

| events/sec | events in window | audit dropped |
|---|---|---|
| 1306401 | 10451208 | 0 |

## Flat memory vs workload count

| workloads | agent RSS (KB) | BPF map bytes | state entries |
|---|---|---|---|
| 1 | 33744 | 963168 | 1239 |
| 10 | 32320 | 963168 | 1249 |
| 50 | 33068 | 963168 | 1299 |
| 100 | 33256 | 963168 | 1398 |

BPF map budget is **constant** (flat) across the sweep — pre-allocated, independent of workload count.

