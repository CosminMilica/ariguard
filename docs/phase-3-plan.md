# Phase 3 — Rule compiler (AI bridge) + control plane (fleet)

Status: planned. The AI bridge is the dissertation differentiator; the control plane is the
cluster story. Both land as independent slices, each with its own PR and CI gate.

## Goal
Replace hand-written rules with rules **generated from threat intelligence**, and distribute
them to a **fleet** of agents from a cluster operator — without changing the kernel data plane
(the compiled bundle v3 and the `AG_*` maps stay the same; everything plugs into the existing
loader + hot-swap path).

## What already exists (scaffolding)
```
compiler/ariguard_compiler/
  schema.py, emit.py, cli.py   # v3 rule schema → bundle (DONE, used by the golden)
  sigma.py                     # stub: Sigma/ATT&CK → FSM          (CMP-3.1)
  mine.py                      # stub: sequence mining (ML)        (CMP-3.2)
control-plane/
  apis/v1alpha1/threatpolicy_types.go   # ThreatPolicy CRD types   (CP-3.1)
  controllers/threatpolicy_controller.go# reconciler skeleton       (CP-3.3)
  cmd/ariguard-ctl/main.go              # manager entrypoint        (CP-3.2)
proto/statewall/v1/statewall.proto      # PushPolicy + StreamAudit RPCs (PROTO-3.1)
```
Generated Go for the proto is not produced yet (`PROTO-0.1`: buf config is in place, `make
proto` not run). The proto package stays `statewall` deliberately (kept for buf-breaking).

## Pillar A — Compiler / AI bridge (`CMP-3.*`)
Output must be a **valid bundle v3** via the existing `emit.py`: deterministic, within the
kernel limits (`MAX_RULES`=16, `MAX_TRANSITIONS`=1024), loadable by the agent unchanged.

- **A1 — Sigma/ATT&CK → FSM (`CMP-3.1`)** — deterministic mapping first: a Sigma correlation
  / ordered sequence → states + hook-bound events + transitions. Most tractable; no data
  needed. Done when a Sigma rule compiles to a table that loads and detects its chain.
- **A2 — Sequence mining / ML (`CMP-3.2`)** — mine malicious subsequences from labeled
  syscall traces (ADFA-LD / LID-DS + synthetic attacks), emit FSM transitions. Depends on a
  dataset (`EVAL-1.*`). Done when a learned chain detects held-out attacks.
- **A3 — LLM path (`CMP-3.3`, optional)** — NL technique description → FSM, offline at compile
  time only. Non-deterministic → strict validation (A4) rejects anything invalid.
- **A4 — Validation (`CMP-3.4`)** — round-trip (FSM → bundle → parse → FSM) + map-size limits;
  oversized/invalid tables rejected with a clear message.

## Pillar B — Control plane / fleet (`CP-3.*`, `PROTO-*`, `AGT-3.1`)
- **B0 — Proto codegen (`PROTO-0.1`, `PROTO-3.1`)** — `make proto` generates Go; finalize
  service + messages + versioning. Blocks the gRPC work.
- **B1 — CRD (`CP-3.1`)** — `ThreatPolicy` types + deepcopy + CRD manifest; `kubectl apply`
  installs it.
- **B2 — Manager (`CP-3.2`)** — controller-runtime bootstrap + leader election.
- **B3 — Reconciler (`CP-3.3`)** — `ThreatPolicy` spec → transition table. Can start on the
  **existing YAML compiler** (CRD carries rules); swap in `CMP-3.*` output later.
- **B4 — gRPC server (`CP-3.4`)** — `PushPolicy` to agents, `StreamAudit` sink.
- **B5 — Agent client (`AGT-3.1`)** — agent dials the control plane, receives `PushPolicy`,
  swaps the maps via the existing hot-swap path (no reload), streams audit up.
- **B6 — Fleet view + audit aggregation (`CP-3.5`, `CP-3.6`)** — connected agents + status;
  cluster-wide audit queryable (the console can read it).
- **B7 — Dynamic rule updates (`CP-3.7`)** — new/changed rules reach running agents
  automatically, no restart, no image rebuild. Source of truth is `ThreatPolicy` CRDs (or Git
  synced to them via Flux/Argo); the operator **watches** them (controller-runtime), on change
  compiles (Sigma/YAML → bundle, via CI-published bundle or an in-operator compile step) and
  pushes to agents (`PushPolicy`), which hot-swap the maps. End state: a new ATT&CK-tagged
  Sigma rule committed/applied propagates to the whole fleet live. A lighter alternative for
  single-node/dev: the compiled bundle in a ConfigMap mounted into the agent, which watches the
  file (fsnotify) and re-applies via the same hot-swap.

## Dependencies / critical path
- A and B are mostly independent. B3 (reconciler) only needs *a* compiler — start with the
  existing YAML one, so **B can proceed without A**.
- B0 (proto codegen) blocks B4/B5. Do it first in the B slice.
- A2 (ML) blocks on a dataset; A1 (Sigma) and A3 (LLM) do not.

## Testing (simple gates, like Phase 2b)
- Compiler: `pytest` — Sigma rule → valid loadable FSM; mined chain detects held-out attacks;
  round-trip + size-limit validation; determinism (byte-identical output).
- Control plane: `envtest` for the reconciler; a gRPC integration test (server ↔ agent client)
  that pushes a policy and asserts the agent swapped maps; a kind e2e (apply `ThreatPolicy` →
  policy distributed → attack detected/mitigated). New `ci-control-plane` gate = `go test` on
  the module; extend the compiler pytest gate.

## Risks
- ML needs labeled datasets (ADFA-LD / LID-DS) — acquisition + preprocessing is real work;
  synthetic traces are the fallback.
- LLM output is non-deterministic → must be validated strictly and kept offline/optional.
- Generated rules must fit the kernel map limits → A4 validation is mandatory, not optional.
- Proto Go package is `statewall` (deliberate); generated path is `pkg/proto/statewallv1`.

## Suggested sequencing (decide at implementation time)
1. **Control-plane-first** (concrete, demoable): B0 → B1/B2 → B3 (on existing compiler) →
   B4/B5 → fleet distribution working end to end in kind; then layer A on top.
2. **Compiler-first** (dissertation differentiator): A1 (Sigma, deterministic) → A4 (validation)
   → A2 (ML) → A3 (LLM optional); then B to distribute what A produces.

Either way, each slice ships as its own PR with its own gate.

## Progress
A1 started — Sigma `temporal_ordered` → FSM shipped for single-selection sub-rules
(fileless-exec, reverse-shell); next: multi-selection OR for container-escape, then A2 (ML).
