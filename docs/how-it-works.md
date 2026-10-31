# How AriGuard works

## Why it's different

| | Falco / Tetragon (typical) | **AriGuard** |
|---|---|---|
| Detection unit | single event | **multi-stage sequence (FSM)** |
| Decision location | user space (async) | **in-kernel (synchronous)** |
| Reaction timing | after the event (ms) | **before/at the critical step** |
| Memory on data path | allocates / grows | **zero-allocation, fixed budget** |
| Rule updates | reload / restart | **hot map swap, no reload** |
| Enforcement | alert (mostly) | **alert → throttle → deny → kill** |

## 1. The attack is a chain, not an event

A container-escape kill chain modeled as an FSM. Each transition is a syscall observed via
tracepoint (and, for synchronous deny, an LSM hook):

```
 S0  normal
  │  openat / connect  ".../containerd.sock"   → runtime socket touched
  ▼
 S1  suspicious
  │  setns / unshare (mount/pid/user ns)       → namespace manipulation
  ▼
 S2  escalating
  │  mount (not propagation-only)              → host mount attempt
  ▼
 S3  breakout-imminent
  │  execve                                    → CRITICAL
  ▼
 S_COMPROMISED  ──►  MITIGATE  (SIGKILL today; -EPERM deny via LSM is phase 2b)
```

A single `mount` or `setns` is normal in many workloads. The **ordered sequence** is what
trips the machine. Each rule is one such chain; AriGuard runs **several at once**, each
scoped to a container (cgroup) or a single process, and a syscall can advance more than one
rule. Bindings carry predicates on the syscall arguments (a path prefix, a flag mask) so a
rule fires on the real step, not its benign look-alike. Three rules ship today: container
escape, reverse shell, fileless execution.

## 2. Dynamic, escalating mitigation

The response depends on the current state, not a static yes/no:

- **observe** — log to the audit ring buffer (early states)
- **throttle** — delay the syscall (mid states)
- **deny** — return `-EPERM` from an LSM hook (critical step; phase 2b)
- **kill / quarantine** — `SIGKILL` via `bpf_send_signal` (compromised state; shipped)

Enforcement is gated per pod: the agent marks which cgroups are enforcement candidates, so
detection stays cluster-wide while a kill only ever fires on a workload pod — never the
node's own container runtime.

## 3. Rules come from threat intelligence

The in-kernel transition table is produced offline and loaded into a BPF map:

- **ML path** — mine malicious subsequences from labeled syscall traces (ADFA-LD / LID-DS +
  synthetic attacks) and emit FSM transitions.
- **LLM path** — translate ATT&CK technique / Sigma descriptions into the formal
  state-transition representation.

The model/LLM runs **once, offline, at compile time** — never on the data path.

## Architecture

```
┌──────────────────────── USER SPACE ─────────────────────────────┐
│  Threat intel (ATT&CK / Sigma / labeled syscall traces)          │
│        ▼  compiler/  (Python, ML + LLM)                          │
│        │   emits transition table + mitigation policy            │
│        ▼  control-plane/  (Go) — CRDs, fleet, telemetry (phase 3)│
│        ▼  agent/  (Go, cilium/ebpf) — DaemonSet, one per node    │
│        │  load & attach programs, populate maps, stream audit    │
└────────┼───────────────────────────────────────┬─────────┬──────┘
         │ map update (hot, no reload)            │ audit   │ attach
┌────────┼───────────────────────────────────────┼─────────┼──────┐
│        ▼                   KERNEL               │         ▼      │
│  tracepoints / LSM ──► FSM ENGINE (Rust, Aya) ──► deny / kill    │
│  per-cgroup state ◄─ HASH   transition table ─► ARRAY           │
│  counters ◄─ PERCPU        audit stream ─► RINGBUF              │
└──────────────────────────────────────────────────────────────────┘
```

**The decision plane is 100% in-kernel.** User space only compiles rules, distributes them,
and collects audit telemetry — the inverse of the Falco model.

## Zero-allocation design

The defining systems property. On the data path there is **no `malloc`, no GC, no unbounded
growth** — everything is reserved at load time:

| Purpose | Map type | Notes |
|---|---|---|
| Per-cgroup / per-PID FSM state | `HASH` (fixed) | O(1) lookup, capped entries |
| Transition table (state × event → next, action) | `ARRAY` | hot-swappable from user space |
| Lock-free counters / metrics | `PERCPU_ARRAY` | no cross-core contention |
| Audit / telemetry to user space | `RINGBUF` | observability only, off the decision path |

**The headline result:** memory is independent of process count — the "memory vs. number of
processes" curve is **flat** — with bounded per-event latency and no in-kernel
allocation-failure paths.
