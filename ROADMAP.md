# Statewall — Development Roadmap

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
- **Gate:** if the ABI boundary is impractical, switch the node loader to Rust/Aya (see
  [docs/architecture.md](docs/architecture.md)) before Phase 1.

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
- Maps: per-cgroup state HASH, transition-table ARRAY, audit RINGBUF (`BPF-1.1`, `BPF-1.2`, `BPF-1.6`).
- Zero-allocation FSM engine; syscall→event mapping; cgroup filter (`BPF-1.3`, `BPF-1.5`, `BPF-1.7`).
- Hooks for the chosen kill chain (`BPF-1.4`).
- Agent: load+attach, ringbuf reader, table population, hot swap, cgroup→pod resolution (`AGT-1.*`).
- Compiler: rule schema + emit + CLI so a hand-written chain compiles to a table (`CMP-1.*`).
- Synthetic benign + attack workloads (`EVAL-1.*`).

### Phase 2 — Synchronous mitigation
- BPF LSM enforcement: deny `-EPERM`, kill, throttle, per-CPU metrics (`BPF-2.*`).
- Agent surfaces mitigations + metrics; graceful detach (`AGT-2.*`).
- Privileged DaemonSet manifest (`DEP-1.1`).
- **Demo:** `make demo-escape` — train benign, then block a live escape.

### Phase 3 — Rule compiler + fleet management
The AI bridge and the cluster story.
- Compiler: Sigma/ATT&CK → FSM, sequence mining (ML), optional LLM NL→FSM, validation (`CMP-3.*`).
- Control plane: CRD, manager, reconciler, gRPC server, registry, audit sink (`CP-3.*`).
- Agent gRPC client (`AGT-3.1`); finalize proto (`PROTO-3.1`).

### Phase 4 — Evaluation
The evidence that earns the grade.
- Benchmark harness: latency, throughput, **flat memory-vs-process curve** (`EVAL-4.1`, `EVAL-4.2`, `BPF-4.1`).
- Efficacy: detection + false-positive rates (`EVAL-4.3`).
- Comparison vs Falco/Tetragon (`EVAL-4.4`, `DEP-4.1`).
- Results tables & plots; thesis write-up mapping (`EVAL-4.5`, `DOC-3`).

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
