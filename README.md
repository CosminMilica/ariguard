<p align="center">
  <img src="logo.png" alt="AriGuard" width="440">
</p>

> **In-kernel, zero-allocation threat mitigation.**
> AriGuard recognizes *multi-stage* attacks as they unfold inside the Linux kernel and blocks the critical step **synchronously** — before the payload completes.

[![CI](https://github.com/CosminMilica/ariguard/actions/workflows/ci.yml/badge.svg)](https://github.com/CosminMilica/ariguard/actions/workflows/ci.yml)
[![status](https://img.shields.io/badge/status-active-brightgreen)](#status)
[![mitigation](https://img.shields.io/badge/mitigation-kill%20%2B%20eBPF%20LSM%20deny-ff6b35)](docs/how-it-works.md#2-dynamic-escalating-mitigation)
[![data plane](https://img.shields.io/badge/data%20plane-Rust%20%2B%20Aya-dea584)](docs/deployment.md#technology-stack)
[![agent](https://img.shields.io/badge/agent-Go%20%2B%20cilium%2Febpf-00add8)](docs/deployment.md#technology-stack)
[![kernel](https://img.shields.io/badge/kernel-eBPF%20%E2%89%A5%205.7-1793d1)](docs/deployment.md#requirements)

---

## What is AriGuard?

Most runtime security tools (Falco, Tetragon) are **reactive** and **point-based**: they
observe one syscall, ship it to user space, and decide *after* the payload has run. Real
intrusions are **sequences** — recon → escalation → persistence → exfiltration — where any
single step looks benign; the *chain* is the attack.

AriGuard runs a **finite state machine entirely in the kernel**: syscalls are transitions,
each container/process carries a state, and when a sequence reaches a compromised state
AriGuard mitigates **synchronously** — `-EPERM` deny via a BPF LSM hook where one exists, kill
everywhere else. All state
lives in **pre-allocated eBPF maps** — no allocation on the data path, so memory is flat and
latency is bounded regardless of load. High-level threat intel (ATT&CK / Sigma / labeled
traces) is compiled into the compact in-kernel tables offline (ML / LLM assisted).

## Documentation

| Doc | What |
|---|---|
| [docs/how-it-works.md](docs/how-it-works.md) | the FSM model, escalating mitigation, architecture, zero-allocation design |
| [docs/deployment.md](docs/deployment.md) | how it deploys, tech stack, repo layout, requirements, dev quickstart |
| [deploy/helm/ariguard](deploy/helm/ariguard/README.md) | the Helm chart and all values |
| [docs/architecture.md](docs/architecture.md) | design decisions (ABI, phase decisions) |
| [docs/threat-model.md](docs/threat-model.md) | threat model, scope, false-positive risks |
| [ROADMAP.md](ROADMAP.md) | phases, waves, per-component tasks |

## Try it

```sh
helm upgrade --install ariguard deploy/helm/ariguard -n ariguard-system --create-namespace
kubectl -n ariguard-system port-forward svc/ariguard-console-frontend 8080:80   # http://localhost:8080
```

See [docs/deployment.md](docs/deployment.md) for the local VM + kind dev loop.

## Status

Built in phases. **Phases 0–2 are complete and in `main`** (CI green end to end: unit,
contract, console, helm, security, bpf, the kernel matrix 5.15→stable, and the kind e2e).

- [x] **Phase 0–1.5** — generic multi-rule in-kernel FSM; three attack chains detected by the
  *ordered sequence* of syscalls, per pod, across kernels 5.15→stable.
- [x] **Phase 2** — synchronous mitigation: the attacker is **killed** at the terminal step
  (`bpf_send_signal`), gated per pod; benign workloads and the node runtime are untouched.
- [x] **Console** — a live web console (agent → sink → SQLite → Vue) showing workloads, FSM
  state, attack chains, mitigations and incidents.
- [x] **Phase 2b** — LSM `-EPERM` deny: the host mount is refused via a BPF LSM hook
  (`sb_mount`/`move_mount`), with a `kill` fallback where no LSM hook exists.
- [ ] **Phase 3** — rule compiler (ML, then LLM) + cluster distribution.
- [ ] **Phase 4** — evaluation: efficacy, latency, the flat memory curve vs. Falco.

## Academic context

AriGuard is the engineering artifact of a master's dissertation. Its contribution is
threefold: a **systems** contribution (a zero-allocation in-kernel state machine with
deterministic overhead), a **security** contribution (sequence-based synchronous mitigation
vs. event-based async alerting), and an **AI bridge** (compiling high-level threat
intelligence into low-level kernel detection).
