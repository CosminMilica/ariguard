# bpf — Tasks

eBPF data plane (Rust / Aya). See [ROADMAP.md](../ROADMAP.md).
Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked.

## Phase 0 — Spike
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[x]` BPF-0.1 | Minimal kprobe program that compiles to a loadable object | — | `cargo build --release` emits a BPF object |
| `[x]` BPF-0.2 | Define maps with libbpf-compatible BTF so the Go loader can read them | BPF-0.1 | Go loader (`AGT-0.2`) reads a value written by the program |

## Phase 1 — Passive FSM
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[x]` BPF-1.0 | ABI v2 types in `statewall-common` (hooks, `Binding`, `HookBindings`, `Dims`, `AuditRecord`, capacities) | — | Go mirror passes; Rust compiles in the VM |
| `[x]` BPF-1.1 | `SW_STATE`: preallocated `LRU_HASH` keyed by `cgroup_id` (D5) | BPF-0.2 | state persists across syscalls for one workload |
| `[x]` BPF-1.2 | `SW_TRANSITIONS`, `SW_BINDINGS`, `SW_DIMS` maps | BPF-1.0 | agent can populate all three |
| `[x]` BPF-1.3 | Zero-allocation FSM engine (lookup, advance, write-back) | BPF-1.1, BPF-1.2 | no heap/stack growth; passes verifier |
| `[x]` BPF-1.4 | Tracepoint programs `sw_openat` … `sw_ptrace` (D1, D2) | BPF-1.3 | each hook fires on its syscall |
| `[x]` BPF-1.5 | Binding evaluation: hook → event, path-prefix match via `SW_SCRATCH` (D3, D6) | BPF-1.4 | only matching paths raise an event |
| `[x]` BPF-1.6 | Emit `AuditRecord` to `SW_AUDIT` on every transition | BPF-1.3 | agent (`AGT-1.2`) receives records |
| `[x]` BPF-1.7 | Skip the root cgroup; track every other cgroup (D8) | BPF-1.1 | host processes ignored |
| `[x]` BPF-1.8 | State expiry: reset to `normal` after `window_ns` without progress (D4) | BPF-1.3 | stale chains do not accumulate |
| `[x]` BPF-1.9 | Cover the new mount API (`fsopen`/`fsmount`/`move_mount`) as mount hooks — folded into E7 / `BPF-1.5.5` | BPF-1.4 | `fsmount` and `move_mount` tracepoints raise `host_mount`; propagation-only `mount` is excluded by the `mask_none` predicate |

> Phase 0 gate (VM, aya-ebpf 0.3.0, bpf-linker 0.12.0): BPF-0.1 is a tracepoint
> (`sw_execve`), not a kprobe, per D1. All six contract maps are BTF maps; the agent
> loads them, writes SW_TRANSITIONS/SW_BINDINGS/SW_DIMS and reads `AuditRecord`s
> from SW_AUDIT. BPF-1.0: `cargo build --release` succeeds in the VM.

> Phase 1 (VM, kernel 6.8): six tracepoints share one inlined handler; no bpf-to-bpf calls,
> 172–296 xlated insns per program. The object needs a GPL license section
> (`bpf_probe_read_*` are GPL-only). Root cgroup = id 1 (cgroup v2). `SW_STATE` holds only
> non-normal workloads: an entry is deleted when its workload returns to normal (expired or by
> transition). Path prefix is evaluated for `openat`/`execve` (filename) and `mount`
> (dir_name). Verified with the manual chain, out-of-order, expiry and SIGHUP runs, and EVAL-1.3.

## Phase 1.5 — Generic engine
Decisions E1–E14 and the v3 contract: [docs/architecture.md](../docs/architecture.md#phase-15-decisions).

| ID | Task | Depends | Done when |
|---|---|---|---|
| `[x]` BPF-1.5.1 | ABI v3 in `statewall-common` (rules, scope, predicates, 16 hooks, `comm`) | — | Go mirror passes; Rust compiles in the VM |
| `[x]` BPF-1.5.2 | Maps v3: `SW_POLICY`, `SW_RULES`, `SW_BINDINGS` (8 per hook), `SW_STATE` keyed by `FsmKey` v3 | BPF-1.5.1 | `pkg/fsm` BTF + capacity tests pass on the object |
| `[x]` BPF-1.5.3 | 16 tracepoint programs; syscall argument `i` read at offset `16 + 8i` | BPF-1.5.2 | all programs load; `dup2` missing on arm64 skipped by the agent (E14) |
| `[x]` BPF-1.5.4 | Multi-rule evaluation: per-rule first match, several rules per syscall (E1, E4) | BPF-1.5.3 | `execve` advances container-escape + fileless/reverse rules in one call; integration test green |
| `[x]` BPF-1.5.5 | Predicates: `PATH_PREFIX`, `PATH_SUN_PREFIX`, `ARG_EQ/LE/MASK_ANY/MASK_NONE` (E5, E6) | BPF-1.5.4 | propagation-only mount excluded; `connect` to the runtime socket counts |
| `[x]` BPF-1.5.6 | Scope: key by cgroup id or tgid per rule (E3) | BPF-1.5.4 | reverse-shell/fileless (process scope) progress per tgid; escape per cgroup |
| `[x]` BPF-1.5.7 | Terminal states never expire (E8) | BPF-1.5.4 | expiry gated on `state < terminal_from`; `compromised` survives the window |
| `[x]` BPF-1.5.8 | Atomic transitions: `BPF_NOEXIST` create + in-place advance (E9) | BPF-1.5.4 | create is `BPF_NOEXIST`; advance is a plain update (last-writer-wins) — see the residual-race note below |
| `[x]` BPF-1.5.9 | `comm` in `AuditRecord` (E12) | BPF-1.5.4 | audit lines carry the process name (`kubelet`, `coredns`, `python3`, …) |
| `[x]` BPF-1.5.10 | Verifies on the CI kernel matrix (5.15 → stable) (E13) | BPF-1.5.4 … 1.5.9 | `ci-kernel KERNEL=5.15` and `KERNEL=stable` pass (vimto TCG — no nested KVM in Lima); instruction budget NOT raised (503/512) |

> Phase 1.5 (VM, kernel 6.8; matrix 5.15 + stable via vimto/TCG). One inlined handler per
> tracepoint reads `SW_POLICY`, skips the root cgroup, and walks the hook's `SW_BINDINGS`
> (bounded 0..8). Per binding: path predicate (`PATH_PREFIX`/`PATH_SUN_PREFIX`, arg read once
> per invocation into `SW_SCRATCH`; `sun_path` at +2) and argument predicate
> (`EQ/LE/MASK_ANY/MASK_NONE` on arg `i` at record offset `16+8i`). First matching binding per
> rule wins (tracked in a `u32` bitmask), so one syscall can advance several rules. Each match
> reads `SW_RULES[rule]`, keys `SW_STATE` by cgroup id or tgid (scope), applies expiry only
> while `state < terminal_from` (E8), reads the cell at `trans_base + state*num_events + event`
> and emits a 64-byte `AuditRecord` with `comm` on a state change or non-observe action.
> Loops stay as bounded loops (no unrolling, no `bpf_loop`, no kfuncs); all 16 programs are
> 492–503 xlated insns, under the 512 budget — `maxInstructions` was NOT raised.
>
> Atomic transitions (E9): the create of a workload's first non-initial state uses
> `BPF_NOEXIST`; an advance is a plain in-place update (last-writer-wins), and a return to the
> initial state deletes the entry. A real compare-and-swap on the `state` field is not used.
> Residual race: if the same workload advances on two CPUs for *distinct* events at the same
> from-state, the read-modify-write can drop one of the two updates (one step lost); a doubled
> step cannot happen (idempotent writes). Closing this fully needs either a `bpf_spin_lock`
> field in `FsmState` (an ABI change — out of scope) or an atomic CAS on the map-value pointer
> (`get_ptr_mut` + `AtomicU32::compare_exchange`), which is the Phase 2 upgrade path. In
> practice a single workload rarely issues two advancing syscalls truly concurrently, and the
> integration + exit-check chains are deterministic.

## Phase 2 — Synchronous mitigation
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` BPF-2.1 | Add BPF LSM programs at enforcement points | BPF-1.3 | LSM hooks attach on kernel ≥ 5.7 |
| `[ ]` BPF-2.2 | DENY action: return `-EPERM` on the critical step | BPF-2.1 | denied syscall fails for the attacker |
| `[ ]` BPF-2.3 | KILL action: `bpf_send_signal(SIGKILL)` on compromised state | BPF-2.1 | process terminated in-kernel |
| `[ ]` BPF-2.4 | THROTTLE action (optional): delay suspicious syscalls | BPF-2.1 | measurable added latency, no deny |
| `[ ]` BPF-2.5 | Per-CPU metric counters (events, denies, kills) | BPF-1.3 | counters readable from `AGT-2.1` |
| `[ ]` BPF-2.6 | Atomic per-cgroup transition — moved to `BPF-1.5.8` (E9) | | |
| `[ ]` BPF-2.7 | `compromised` terminal — moved to `BPF-1.5.7` (E8) | | |
| `[ ]` BPF-2.8 | Mount flag and execve path predicates — moved to `BPF-1.5.5` (E5, E7) | | |
| `[ ]` BPF-2.9 | Pattern length edge — decided in E10, enforced by `CMP-1.5.1` / `PKG-1.5.2` | | |

## Phase 4 — Evaluation support
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` BPF-4.1 | Fixed memory budget: expose map sizes; prove O(1) per event | BPF-1.* | memory independent of process count |
