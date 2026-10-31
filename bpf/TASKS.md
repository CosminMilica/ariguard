# bpf — Tasks

eBPF data plane (Rust / Aya). See [ROADMAP.md](../ROADMAP.md).
Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked.

## Phase 0 — Spike
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` BPF-0.1 | Minimal kprobe program that compiles to a loadable object | — | `cargo build --release` emits a BPF object |
| `[ ]` BPF-0.2 | Define maps with libbpf-compatible BTF so the Go loader can read them | BPF-0.1 | Go loader (`AGT-0.2`) reads a value written by the program |

## Phase 1 — Passive FSM
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[~]` BPF-1.0 | ABI v2 types in `statewall-common` (hooks, `Binding`, `HookBindings`, `Dims`, `AuditRecord`, capacities) | — | Go mirror passes; Rust compiles in the VM |
| `[ ]` BPF-1.1 | `SW_STATE`: preallocated `LRU_HASH` keyed by `cgroup_id` (D5) | BPF-0.2 | state persists across syscalls for one workload |
| `[ ]` BPF-1.2 | `SW_TRANSITIONS`, `SW_BINDINGS`, `SW_DIMS` maps | BPF-1.0 | agent can populate all three |
| `[ ]` BPF-1.3 | Zero-allocation FSM engine (lookup, advance, write-back) | BPF-1.1, BPF-1.2 | no heap/stack growth; passes verifier |
| `[ ]` BPF-1.4 | Tracepoint programs `sw_openat` … `sw_ptrace` (D1, D2) | BPF-1.3 | each hook fires on its syscall |
| `[ ]` BPF-1.5 | Binding evaluation: hook → event, path-prefix match via `SW_SCRATCH` (D3, D6) | BPF-1.4 | only matching paths raise an event |
| `[ ]` BPF-1.6 | Emit `AuditRecord` to `SW_AUDIT` on every transition | BPF-1.3 | agent (`AGT-1.2`) receives records |
| `[ ]` BPF-1.7 | Skip the root cgroup; track every other cgroup (D8) | BPF-1.1 | host processes ignored |
| `[ ]` BPF-1.8 | State expiry: reset to `normal` after `window_ns` without progress (D4) | BPF-1.3 | stale chains do not accumulate |
| `[ ]` BPF-1.9 | Cover the new mount API (`fsopen`/`fsmount`/`move_mount`) as mount hooks | BPF-1.4 | default util-linux `mount` (no `LIBMOUNT_FORCE_MOUNT2`) raises `host_mount` |

> BPF-1.0: written on the host; the Go mirror (`pkg/fsm`) passes the size/offset test.
> Flip to `[x]` once `cargo build` succeeds in the VM.

## Phase 2 — Synchronous mitigation
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` BPF-2.1 | Add BPF LSM programs at enforcement points | BPF-1.3 | LSM hooks attach on kernel ≥ 5.7 |
| `[ ]` BPF-2.2 | DENY action: return `-EPERM` on the critical step | BPF-2.1 | denied syscall fails for the attacker |
| `[ ]` BPF-2.3 | KILL action: `bpf_send_signal(SIGKILL)` on compromised state | BPF-2.1 | process terminated in-kernel |
| `[ ]` BPF-2.4 | THROTTLE action (optional): delay suspicious syscalls | BPF-2.1 | measurable added latency, no deny |
| `[ ]` BPF-2.5 | Per-CPU metric counters (events, denies, kills) | BPF-1.3 | counters readable from `AGT-2.1` |

## Phase 4 — Evaluation support
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` BPF-4.1 | Fixed memory budget: expose map sizes; prove O(1) per event | BPF-1.* | memory independent of process count |
