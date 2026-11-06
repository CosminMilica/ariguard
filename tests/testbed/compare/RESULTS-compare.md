# Detector comparison — AriGuard vs Falco vs Tetragon (T4)

Run 2026-11-06T14:27:12+00:00 on statewall-dev. Same three real kill-chains (the T3 scenarios) in detect mode so every tool sees the full chain. Falco runs its default ruleset; Tetragon ships no rules, so it runs hand-written TracingPolicies watching each chain's characteristic syscall.

## Detection
| scenario | AriGuard | Falco | Tetragon |
|---|---|---|---|
| reverse-shell | detected | detected | detected |
| fileless-exec | detected | detected | detected |
| container-escape | detected | — | detected |

## Agent CPU (same node load, 30s window, main-process utime+stime)

| tool | agent CPU | where detection runs |
|---|---|---|
| AriGuard | 0.00% | in-kernel FSM — per-syscall cost borne by the workload (~4µs/hooked syscall, BPF_STATS) |
| Tetragon | 0.87% | user space (per TracingPolicy event) |
| Falco | 1.40% | user space (default ruleset over a broad syscall set) |

**Reading it.** AriGuard detects each scenario as one correlated multi-stage incident (the FSM reaching a threat state), with the full chain + IOCs. Falco and Tetragon fire per isolated event: Falco's out-of-the-box rules catch the reverse-shell and fileless IOCs but not the escape chain (its namespace-change rule is disabled by default as noisy); Tetragon catches only what a hand-written policy names, with no built-in correlation. The CPU figures compare each agent's user-space footprint under the same load — AriGuard keeps detection in the kernel, so its agent is near-idle while the per-syscall cost is paid by the workload; Falco and Tetragon evaluate in user space. Measured on a single-node 4-vCPU kind cluster.

