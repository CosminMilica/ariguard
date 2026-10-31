# agent — Tasks

Node data-plane manager (Go / cilium/ebpf). See [ROADMAP.md](../ROADMAP.md).
Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked.

## Phase 0 — Spike
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` AGT-0.1 | Load the Rust-built BPF object via `cilium/ebpf` | BPF-0.1 | object loads without ABI errors |
| `[ ]` AGT-0.2 | Attach the kprobe and read one map value | AGT-0.1, BPF-0.2 | value round-trips kernel→user |
| `[ ]` AGT-0.3 | Decide binding strategy (bpf2go vs BTF-generated structs) | AGT-0.2 | documented decision + working bindings |

## Phase 1 — Load, maps, telemetry
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[~]` AGT-1.1 | Load all programs + maps, attach per the active policy | AGT-0.3, BPF-1.4 | all hooks attached at startup |
| `[~]` AGT-1.2 | Ring buffer reader → structured audit events | BPF-1.6 | events parsed into Go structs |
| `[~]` AGT-1.3 | Populate `SW_TRANSITIONS`, `SW_BINDINGS`, `SW_DIMS` from a policy bundle v2 | PKG-1.4, BPF-1.2 | policy active in the kernel |
| `[~]` AGT-1.4 | Hot-swap the policy without reloading programs (write `SW_DIMS` last) | AGT-1.3 | new policy active, no detach |
| `[ ]` AGT-1.5 | Resolve `cgroup_id` → pod metadata (CRI / cgroupfs) | AGT-1.2 | audit events carry pod name/ns |
| `[~]` AGT-1.6 | Dev mode: plain binary on the VM, `--object`, `--bundle`, JSON audit to stdout (D7) | AGT-1.1 | `sudo statewall-agent --bundle …` streams audit |

`[~]` AGT-1.1–1.4, AGT-1.6: code complete, runtime verification in the VM (wave C).

## Phase 2 — Mitigation surface
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` AGT-2.1 | Surface mitigations + expose Prometheus metrics | BPF-2.5 | denies/kills visible as metrics |
| `[ ]` AGT-2.2 | Health/readiness probes; graceful detach on shutdown | AGT-1.1 | clean teardown, no leaked programs |

## Phase 3 — Fleet
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` AGT-3.1 | gRPC client: receive `PushPolicy`, stream audit upstream | PROTO-3.1, CP-3.4 | policies arrive from control plane |

## Phase 4 — Evaluation support
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` AGT-4.1 | pprof / overhead instrumentation for benchmarks | AGT-1.1 | CPU/mem profiles collectable |
