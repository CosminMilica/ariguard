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
| `[ ]` BPF-1.1 | Per-cgroup state map (`HASH`, fixed size), keyed by `cgroup_id` | BPF-0.2 | state persists across syscalls for one workload |
| `[ ]` BPF-1.2 | Transition-table map (`ARRAY`): (state, event) → (next, action) | PKG-0.1 | table lookup drives state changes |
| `[ ]` BPF-1.3 | Zero-allocation FSM engine (lookup, advance, write-back) | BPF-1.1, BPF-1.2 | no heap/stack growth; passes verifier |
| `[ ]` BPF-1.4 | Attach hooks for the chosen kill chain (open, setns, unshare, mount, execve, ptrace) | BPF-1.3 | each syscall produces an event |
| `[ ]` BPF-1.5 | Map syscall + args → event id | BPF-1.4 | correct event for each hooked call |
| `[ ]` BPF-1.6 | Emit audit records to `RINGBUF` on transitions | BPF-1.3 | agent (`AGT-1.2`) receives events |
| `[ ]` BPF-1.7 | cgroup/namespace filter: only track K8s pod cgroups | BPF-1.1 | host processes ignored |

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
