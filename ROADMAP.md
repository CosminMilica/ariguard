# AriGuard — Development Roadmap

Complete development plan. Work is organized into **phases**; each phase has an exit
criterion. Concrete tasks live in each component's `TASKS.md` and are referenced here by
ID (`<PREFIX>-<phase>.<n>`).

**Phases 1–2 alone are a complete dissertation contribution. Phase 3 is the differentiator;
Phase 4 produces the evidence.**

## Task ID prefixes

| Prefix | Component | Tasks file |
|---|---|---|
| `BPF` | eBPF data plane (Rust) | [bpf/TASKS.md](bpf/TASKS.md) |
| `AGT` | Node agent (Go) | [agent/TASKS.md](agent/TASKS.md) |
| `CP` | Control plane (Go) | [control-plane/TASKS.md](control-plane/TASKS.md) |
| `PKG` | Shared Go libs | [pkg/TASKS.md](pkg/TASKS.md) |
| `CMP` | Rule compiler (Python) | [compiler/TASKS.md](compiler/TASKS.md) |
| `PROTO` | gRPC contract | [proto/TASKS.md](proto/TASKS.md) |
| `DEP` | Deploy / dev env | [deploy/TASKS.md](deploy/TASKS.md) |
| `DOC` | Docs / thesis | [docs/TASKS.md](docs/TASKS.md) |
| `EVAL` | Datasets + benchmarks | [testdata/TASKS.md](testdata/TASKS.md) |

Status legend (used in every TASKS file): `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked.

## Milestones

| Phase | Goal | Exit criterion | Lead tasks |
|---|---|---|---|
| **0** | Spike & dev env | Rust-built BPF loads via Go loader; map read works; `make dev-up` gives a kind cluster | `DEP-0.*`, `AGT-0.*`, `BPF-0.*`, `PKG-0.*`, `PROTO-0.1` |
| **1** | Passive FSM | Multi-stage chain detected in-kernel, audit events reach user space (no enforcement) | `BPF-1.*`, `AGT-1.*`, `CMP-1.*`, `EVAL-1.*` |
| **1.5** | Generic engine | Three different attack chains detected at once, by pod name; benign twins only ever observed; verifies on kernels 5.15 → stable | `BPF-1.5.*`, `AGT-1.5.*`, `PKG-1.5.*`, `CMP-1.5.*`, `EVAL-1.5.*` |
| **2** | Synchronous mitigation | Critical step denied / killed in-kernel; demo blocks a container escape | `BPF-2.*`, `AGT-2.*`, `DEP-1.1` |
| **3** | Rule compiler + fleet | Threat intel (ML/LLM) → tables; CRD-driven distribution to agents | `CMP-3.*`, `CP-3.*`, `AGT-3.1`, `PROTO-3.1` |
| **4** | Evaluation | Efficacy, latency, flat memory curve, comparison vs Falco — tables & plots | `EVAL-4.*`, `BPF-4.1`, `DOC-3` |

## Phase detail

### Phase 0 — Spike & dev environment
De-risk the single biggest unknown first: the Rust-authored eBPF ↔ Go-loader ABI boundary.
- Dev env on macOS: Lima/multipass VM + kind (`DEP-0.1`, `DEP-0.2`).
- Minimal Rust kprobe + libbpf-compatible maps (`BPF-0.1`, `BPF-0.2`).
- Go loader attaches it and reads a map (`AGT-0.1`, `AGT-0.2`); binding strategy decided (`AGT-0.3`).
- Go ABI mirror + size-assertion test (`PKG-0.1`, `PKG-0.2`).
- proto code-gen pipeline (`PROTO-0.1`).
- **Gate: passed.** The Go agent loads the Rust object unchanged (BTF maps), writes the
  policy maps and streams `AuditRecord`s from the ring buffer. No Rust loader fallback.

### Phase 1 — Passive FSM (detection only)
The core systems contribution. Design decisions D1–D8, the kernel object contract and
the policy bundle v2 format are in [docs/architecture.md](docs/architecture.md#phase-1-decisions).

Execution order:

| Wave | Where | Tasks | Output |
|---|---|---|---|
| A | macOS, parallel | `CMP-1.5`, `CMP-1.6`, `PKG-1.4` · `AGT-1.1`, `AGT-1.2`, `AGT-1.6` (code) · `EVAL-1.1`, `EVAL-1.2` | bundle v2 end to end; agent compiles for linux; workloads ready |
| B | VM | `BPF-0.*`, `AGT-0.*`, `BPF-1.0` | **Phase 0 gate**: Rust object loads from Go, map read works |
| C | VM | `BPF-1.1`–`BPF-1.8`, `AGT-1.3`, `AGT-1.4` | FSM runs in the kernel, policy loaded from a bundle |
| D | VM | `EVAL-1.3`, `AGT-1.5` | exit check passes on kind |

Exit check (`EVAL-1.3`): the attack pod drives its cgroup to `compromised`; the benign
workloads never go past `suspicious`.

**Status: done.** The exit check passed twice on kind: only the attack cgroup produced
records (normal → suspicious → escalating → breakout_imminent → compromised), the benign
workloads and kind system components produced none. False-positive risks found on the
way are listed in [docs/threat-model.md](docs/threat-model.md); they were folded into the
Phase 1.5 decisions (E8–E10) and the Phase 2 atomic transition (`BPF-2.2`).
- Maps: per-cgroup state HASH, transition-table ARRAY, audit RINGBUF (`BPF-1.1`, `BPF-1.2`, `BPF-1.6`).
- Zero-allocation FSM engine; syscall→event mapping; cgroup filter (`BPF-1.3`, `BPF-1.5`, `BPF-1.7`).
- Hooks for the chosen kill chain (`BPF-1.4`).
- Agent: load+attach, ringbuf reader, table population, hot swap, cgroup→pod resolution (`AGT-1.*`).
- Compiler: rule schema + emit + CLI so a hand-written chain compiles to a table (`CMP-1.*`).
- Synthetic benign + attack workloads (`EVAL-1.*`).

### Phase 1.5 — Generic engine
Phase 1 proved the idea on one hard-wired chain. Phase 1.5 makes the engine generic before
anything is enforced: several rules at once, per-container or per-process state,
predicates on any syscall argument, more hooks, atomic transitions. It also closes the
false-positive risks phase 1 found, which phase 2 must not turn into killed processes.
Decisions E1–E14, the v3 kernel contract, bundle v3 and rule schema v3 are in
[docs/architecture.md](docs/architecture.md#phase-15-decisions).

Work happens on branch `feat/phase-1.5`, in a separate checkout from the CI work.

| Wave | Where | Tasks | Output |
|---|---|---|---|
| A | macOS | `BPF-1.5.1`, `PKG-1.5.1` | **done**: ABI v3 in Rust and Go, contract documented |
| B | macOS, parallel | `CMP-1.5.*`, `PKG-1.5.2` · `AGT-1.5.1`–`AGT-1.5.5` (code) · `EVAL-1.5.1`–`EVAL-1.5.3` | **done**: three rules compile into one bundle; agent v3 builds; workloads and checker v2 ready |
| C | VM | `BPF-1.5.2`–`BPF-1.5.10`, runtime check of `AGT-1.5.*` | **done**: engine v3 verifies in the kernel; integration chains + kernel matrix 5.15 → stable pass |
| D | VM, kind | `EVAL-1.5.4` | **done**: exit check v2 passes twice in a row |

Exit check (`EVAL-1.5.4`): with every benign and attack pod running at once, each attack
pod reaches its rule's terminal state through the declared chain, identified by pod name,
and no other pod or host process gets an action other than `observe`.

End-to-end runs share the VM's kernel and kind cluster with the CI work: run them one at a
time, or each checker also sees the other's attacks.

### Phase 2 — Kill-based mitigation (branch `feat/mitigation`)
Make detection act: kill the attacker at the terminal step, from the existing tracepoint
engine, with the safety machinery that makes enforcement safe. `-EPERM` deny via BPF LSM
followed in Phase 2b (the ABI already carries `ACTION_DENY`). Decisions F1–F7 and the v3.1
ABI additions are in [docs/architecture.md](docs/architecture.md#phase-2-decisions--synchronous-mitigation-kill-based).

| Wave | Where | Tasks | Output |
|---|---|---|---|
| 0 | contract + parallel | `PKG-2.1` + `BPF-2.1` (ABI v3.1, me) · `BPF-2.2`, `BPF-2.3` (engine, VM) · `AGT-2.1` (agent, Mac) | per-pod gating + atomic transition; detection identical to Phase 1.5 |
| 1 | VM | `BPF-2.4`, `BPF-2.5`, `BPF-2.6`, `BPF-2.7` | KILL fires on the terminal step for pod cgroups only; kernel matrix green |
| 3 | parallel | `AGT-2.2`, `AGT-2.3` (agent) · `DEP-0.3`, `DEP-1.1` (deploy) · eval: enforce-mode exit check | DaemonSet + metrics; `make demo-escape` kills a live escape |

Exit check (enforce on): each attacker is killed at its terminal step; benign twins and the
node's own runtime are never killed; the detection table is otherwise unchanged. Work is
parallelized into small agents (sonnet for well-defined work, opus 4.8 for the kernel).

**Status: done.**

### Phase 2b — LSM `-EPERM` deny (branch `feat/phase-2b-lsm-deny`)
Make `ACTION_DENY` enforce: `lsm/*` programs on `sb_mount`/`move_mount` return `-EPERM`,
refusing the host mount before it happens. The `sys_enter_mount` tracepoint stays the only
FSM writer and arms a deny token in `AG_DENY` (keyed by `pid_tgid`); the LSM program consumes
it and refuses the mount, emitting `action=deny, enforced=1`. Hybrid: on a kernel with BPF
LSM the chain halts at `breakout_imminent` (execve/kill never reached); without it the LSM
programs are dropped at load time and the `kill` fallback fires. New metric
`ariguard_denies_total`. Design in [docs/phase-2b-lsm-deny.md](docs/phase-2b-lsm-deny.md).

**Status: done, merged.** `lsm/*` on `sb_mount`/`move_mount` return `-EPERM`, keyed off an
`AG_DENY` token (by `pid_tgid`); new metric `ariguard_denies_total`. An in-kernel integration
test drives the chain to the mount step and asserts `EPERM` + an enforced deny record; it skips
where BPF LSM is absent.

### Phase 3 — Rule compiler + fleet management
The AI bridge and the cluster story.
- Compiler: Sigma/ATT&CK → FSM, sequence mining (ML), optional LLM NL→FSM, validation (`CMP-3.*`).
- Control plane: CRD, manager, reconciler, gRPC server, registry, audit sink (`CP-3.*`).
- Agent gRPC client (`AGT-3.1`); finalize proto (`PROTO-3.1`).

**Status: implemented** (control-plane CRD / fleet distribution still deferred). The Sigma
`temporal_ordered` → FSM compiler (`compiler/ariguard_compiler/sigma.py`, multi-selection OR)
and a MITRE ATT&CK ingester (`ingest_attack.py` → `compiler/techniques/attack-linux.yml`) are
in place. The automated pipeline co-authors rules offline (Claude in-session; outputs committed,
CI never calls an LLM), gated by A4 validation (`validate.py`: schema + binary round-trip +
kernel limits) and a behavioral check (must detect the attack and not fire on a benign twin).
The rule library is now **7 kill-chains**: container-escape, reverse-shell, fileless-exec
(native) + bpf-tampering, cred-access-exfil, kernel-module-load, ptrace-injection (generated
Sigma). See [docs/phase-3-rulegen-plan.md](docs/phase-3-rulegen-plan.md).

### Phase 4 — Evaluation
The evidence that earns the grade.

**Status: implemented** (our-metrics-first; Falco/Tetragon comparison still deferred). The
`ariguard-bench` CLI (`agent/cmd/ariguard-bench`) measures per-hook latency (BPF run-time stats),
the flat memory curve (agent RSS + BPF map bytes vs N workloads) and throughput (events/sec +
`audit_dropped`); the agent exposes per-program run-time and BPF map bytes (`--bpf-stats`).
See [docs/phase-4-eval-plan.md](docs/phase-4-eval-plan.md).

- Benchmark harness: latency, throughput, **flat memory-vs-process curve** (`EVAL-4.1`, `EVAL-4.2`, `BPF-4.1`).
- Efficacy: detection + false-positive rates (`EVAL-4.3`).
- Comparison vs Falco/Tetragon (`EVAL-4.4`, `DEP-4.1`) — deferred.
- Results tables & plots; thesis write-up mapping (`EVAL-4.5`, `DOC-3`).
- **Reporting UI — built (Vue):** a full incident-investigation console (agent → sink → SQLite →
  Vue) with Triage, Campaigns (blast-radius), Timeline, Coverage (ATT&CK × hooks), Performance,
  per-incident JSON export, interactive per-rule FSM diagrams and a process tree from `ppid`.
  Reads the agent's Prometheus `/metrics` + the audit stream. See
  [docs/incident-investigation-plan.md](docs/incident-investigation-plan.md).
- **Autonomous workload isolation — shipped (Tier C1):** on a confirmed terminal mitigation
  (`enforced=1`, action `kill`/`deny`) the agent's responder quarantines the offending pod with no
  operator — a `ariguard.io/quarantine` label/annotations plus a namespace-scoped deny-all
  NetworkPolicy (`ariguard-quarantine`) — gated `--isolate=off|dryrun|on`, idempotent, never
  touching system namespaces. Closes the process-kill ≠ pod-isolation gap. Actor correlation (C2)
  and the lateral-movement graph (C3) are next. See [docs/tier-c-plan.md](docs/tier-c-plan.md).

## Critical path

```
DEP-0.1/0.2 ─┐
BPF-0.* ─────┼─► AGT-0.* (ABI spike) ─► BPF-1.* ─► AGT-1.* ─► BPF-2.* ─► demo ─► EVAL-4.*
PKG-0.* ─────┘                             │
CMP-1.* ───────────────────────────────────┘ (parallel, Mac-doable)
CP-3.* / CMP-3.* ───────────────────────── (after Phase 2, parallel)
```

**Parallelizable now (no Linux/eBPF needed):** `CMP-1.*`, `PKG-0.*`, `PROTO-0.1`, `DOC-*`,
`DEP-0.1`. Everything touching the kernel waits for the Phase 0 gate.
