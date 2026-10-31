# Statewall

> **In-kernel, zero-allocation threat mitigation.**
> Statewall recognizes *multi-stage* attacks as they unfold inside the Linux kernel and blocks the critical step **synchronously** — before the payload executes.

[![status](https://img.shields.io/badge/status-early--development-orange)](#project-status)
[![data plane](https://img.shields.io/badge/data%20plane-Rust%20%2B%20Aya-dea584)](#technology-stack)
[![control plane](https://img.shields.io/badge/control%20plane-Go%20%2B%20cilium%2Febpf-00add8)](#technology-stack)
[![kernel](https://img.shields.io/badge/kernel-eBPF%20%2F%20LSM%20%E2%89%A5%205.7-1793d1)](#requirements)

---

## What is Statewall?

Most runtime security tools (Falco, Tetragon) are **reactive** and **point-based**: they
observe a single syscall, ship the event to user space over a ring buffer, and *then*
decide what to do — by which time the payload has already run. They also reason about
**isolated events**, while real intrusions are **sequences**: recon → privilege
escalation → persistence → exfiltration. Any single step looks benign; the *chain* is the
attack.

Statewall takes a different approach. It runs a **finite state machine entirely in the
kernel**. Syscalls are *transitions*; each process/container carries a *state*. When a
sequence advances to a compromised state, Statewall mitigates **synchronously** from
inside the kernel (deny the syscall with `-EPERM`, kill, or quarantine) — on the hot path,
before the critical operation completes.

All kernel-side state lives in **pre-allocated eBPF maps**. There is **no dynamic
allocation on the data path**: a fixed, known memory budget and deterministic, bounded
latency regardless of load.

High-level threat intelligence (MITRE ATT&CK techniques, Sigma rules, labeled syscall
traces) is turned into the compact in-kernel transition tables by an offline **compiler**
(ML / LLM assisted) — so the kernel stays tiny and fast while the rules stay expressive.

---

## Why it's different

| | Falco / Tetragon (typical) | **Statewall** |
|---|---|---|
| Detection unit | single event | **multi-stage sequence (FSM)** |
| Decision location | user space (async) | **in-kernel (synchronous)** |
| Reaction timing | after the event (ms) | **before the critical step (ns)** |
| Memory on data path | allocates / grows | **zero-allocation, fixed budget** |
| Rule updates | reload / restart | **hot map swap, no reload** |
| Enforcement | alert (mostly) | **alert → throttle → deny → kill** |

---

## How it works

### 1. The attack is a chain, not an event

Example: a container-escape kill chain modeled as an FSM. Each transition is a syscall
observed via kprobe/tracepoint/LSM hook.

```
 S0  normal
  │  open("/var/run/docker.sock")            → runtime socket touched
  ▼
 S1  suspicious
  │  setns() / unshare(CLONE_NEWNS)          → namespace manipulation
  ▼
 S2  escalating
  │  mount()                                 → host mount attempt
  ▼
 S3  breakout-imminent
  │  execve() from the new mount             → CRITICAL
  ▼
 S_COMPROMISED  ──►  MITIGATE  (deny -EPERM / SIGKILL / network quarantine)
```

A single `mount()` or `setns()` is normal in many workloads. The **ordered sequence**,
tracked per cgroup, is what trips the machine.

### 2. Dynamic, escalating mitigation

The response depends on the current state, not a static yes/no:

- **observe** — log to the audit ring buffer (early states)
- **throttle** — delay the syscall (mid states)
- **deny** — return `-EPERM` from an LSM hook (critical step)
- **kill / quarantine** — `SIGKILL` + drop the socket/traffic (compromised state)

### 3. Rules come from threat intelligence

The in-kernel transition table is produced offline and loaded into a BPF map:

- **ML path** — mine malicious subsequences from labeled syscall traces
  (e.g. ADFA-LD / LID-DS, plus synthetic attacks) and emit FSM transitions.
- **LLM path** — translate ATT&CK technique / Sigma descriptions in natural language
  into the formal state-transition representation.

The model/LLM runs **once, offline, at compile time** — never on the data path.

---

## Architecture

```
┌──────────────────────── USER SPACE ─────────────────────────────┐
│                                                                  │
│  Threat intel (ATT&CK / Sigma / labeled syscall traces)          │
│        │                                                         │
│        ▼                                                         │
│  compiler/  (Python, ML + LLM)                                   │
│        │   emits  transition table  +  mitigation policy         │
│        ▼                                                         │
│  control-plane/  (Go, controller-runtime)                        │
│        │   CRDs (ThreatPolicy), fleet mgmt, telemetry sink       │
│        ▼                                                         │
│  agent/  (Go, cilium/ebpf)   ── DaemonSet, one per node ──┐      │
│        │  load & attach programs, populate maps,          │      │
│        ▲  stream audit events                             │      │
└────────┼───────────────────────────────────────┬─────────┼──────┘
         │ map update (hot, no reload)            │ audit   │ attach
┌────────┼───────────────────────────────────────┼─────────┼──────┐
│        ▼                   KERNEL               │         ▼      │
│  ┌───────────────┐   ┌──────────────────┐   ┌──────────────────┐ │
│  │ kprobes /     │──►│  FSM ENGINE       │──►│  LSM hooks        │ │
│  │ tracepoints / │   │  bpf/ (Rust, Aya) │   │  deny / kill /    │ │
│  │ LSM entry     │   │  no_std, no alloc │   │  quarantine       │ │
│  └───────────────┘   └────────┬─────────┘   └──────────────────┘ │
│                               │                                  │
│   per-cgroup state  ◄─ HASH map   transition table ─► ARRAY map  │
│   lock-free counters ◄─ PERCPU map   audit stream ─► RINGBUF      │
└──────────────────────────────────────────────────────────────────┘
```

**The decision plane is 100% in-kernel.** User space only compiles rules, distributes
them, and collects audit telemetry — the inverse of the Falco model.

---

## Zero-allocation design

The defining systems property. On the data path there is **no `malloc`, no GC, no
unbounded growth**. Everything is reserved at load time:

| Purpose | Map type | Notes |
|---|---|---|
| Per-cgroup / per-PID FSM state | `BPF_MAP_TYPE_HASH` (fixed) | O(1) lookup, capped entries |
| Transition table (state × event → next, action) | `BPF_MAP_TYPE_ARRAY` | hot-swappable from user space |
| Lock-free counters / metrics | `BPF_MAP_TYPE_PERCPU_ARRAY` | no cross-core contention |
| Audit / telemetry to user space | `BPF_MAP_TYPE_RINGBUF` | observability only, off the decision path |

**Consequences we will measure:** fixed memory budget independent of process count,
bounded per-event latency, and no in-kernel allocation-failure paths. The "memory vs.
number of processes" curve should be **flat** — that flat line is the headline result.

---

## Technology stack

| Layer | Choice |
|---|---|
| eBPF data plane | **Rust + [Aya](https://aya-rs.dev/)** (`aya-ebpf`, `no_std`, zero-alloc) |
| Kernel hooks | kprobes, tracepoints (`sys_enter_*`), **BPF LSM** (`lsm/*`) |
| Node agent / loader | **Go + [cilium/ebpf](https://github.com/cilium/ebpf)**, runs as a DaemonSet |
| Cluster control plane | **Go + controller-runtime** (CRDs, policy distribution) |
| Rule compiler | **Python** — sequence mining (ML) + optional LLM for NL→FSM |
| Local dev / demo | **Linux VM** (Lima / multipass) + **kind** single-node cluster |
| Datasets | ADFA-LD / LID-DS + synthetic scripted attacks |

> **Design note (first thing to validate).** The eBPF objects are authored in Rust
> (`aya-ebpf`) but loaded by a Go agent (`cilium/ebpf`). These are two loader ecosystems
> with different map/BTF conventions, so **map-ABI compatibility across the toolchain
> boundary is the first engineering spike**. If it proves impractical, the fallback is to
> keep the node loader in Rust (Aya's own userspace loader) and limit Go to the cluster
> control plane. The agent ↔ control-plane boundary is a stable gRPC API regardless.

---

## Repository layout (planned)

```
statewall/
├── bpf/                      # eBPF data plane — Rust workspace (no_std, zero-alloc)
│   ├── statewall-ebpf/       #   kernel programs: kprobes, tracepoints, LSM, FSM engine
│   └── statewall-common/     #   shared ABI types (State/Event/Action, map layouts)
├── agent/                    # node DaemonSet — Go, cilium/ebpf
│   ├── cmd/statewall-agent/
│   └── internal/{loader,mitigator,audit}/
├── control-plane/            # cluster operator — Go, controller-runtime
│   ├── cmd/statewall-ctl/
│   ├── apis/v1alpha1/        #   CRDs: ThreatPolicy
│   └── controllers/
├── pkg/                      # shared Go libraries (used by agent + control-plane)
├── compiler/                 # threat-intel → FSM tables — Python (ML/LLM)
│   └── statewall_compiler/{sigma,mine,emit}.py
├── proto/                    # gRPC contract (agent ↔ control-plane)
├── deploy/
│   ├── kind/                 # local single-node cluster
│   └── k8s/                  # DaemonSet + operator manifests
├── testdata/                 # synthetic benign + attack syscall traces
├── docs/                     # architecture.md, threat-model.md
├── go.mod                    # single Go module (covers agent/, control-plane/, pkg/)
└── Makefile                  # orchestrates the Rust / Go / Python toolchains
```

---

## Project status

Early development — defining the baseline. Built in phases; **Phases 1–2 alone are a
complete contribution**, Phase 3 is the differentiator.

- [ ] **Phase 0 — Spike:** validate the Rust-eBPF ↔ Go-loader map ABI (see design note).
- [ ] **Phase 1 — Passive FSM:** in-kernel state machine, detection only (audit log).
- [ ] **Phase 2 — Synchronous mitigation:** LSM-based deny / kill / quarantine.
- [ ] **Phase 3 — Rule compiler:** threat intel → transition tables (ML, then LLM).
- [ ] **Phase 4 — Evaluation:** efficacy, latency, and the flat memory curve vs. Falco.

---

## Requirements

- Linux kernel **≥ 5.7** with `CONFIG_BPF_LSM=y` (BPF LSM hooks)
- BTF-enabled kernel (`/sys/kernel/btf/vmlinux`) for CO-RE
- Rust toolchain + `bpf-linker`; Go ≥ 1.22; Python ≥ 3.11
- For local work on macOS: a Linux VM (Lima / multipass) + kind

## Quickstart (planned)

```sh
# bring up a local single-node cluster inside a Linux VM
make dev-up            # lima/multipass VM + kind

# build eBPF (Rust) + agent (Go)
make build

# deploy the DaemonSet and load a demo threat policy
make deploy
make load-policy POLICY=container-escape

# run the demo: a benign workload trains, then an exploit is blocked in-kernel
make demo-escape
```

---

## Threat model & scope

**In scope:** detection and synchronous mitigation of multi-stage, syscall-observable
attack chains on a single node (container escape, local privilege escalation).

**Out of scope (for now):** kernel-exploit-based eBPF bypass, attacks that never touch the
monitored syscalls, cluster-wide correlation across nodes, and full MITRE ATT&CK coverage.
The FSM is deliberately scoped to **one or two well-chosen kill chains** to keep the work
tractable and the evaluation rigorous.

---

## Academic context

Statewall is the engineering artifact of a master's dissertation. Its contribution is
threefold: a **systems** contribution (a zero-allocation in-kernel state machine with
deterministic overhead), a **security** contribution (sequence-based synchronous
mitigation vs. event-based async alerting), and an **AI bridge** (compiling high-level
threat intelligence into low-level kernel detection).
