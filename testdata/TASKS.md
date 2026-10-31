# testdata — Tasks

Synthetic datasets + benchmark/evaluation harness. See [ROADMAP.md](../ROADMAP.md).
Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked.

## Phase 1 — Workloads
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` EVAL-1.1 | Synthetic benign workload scripts (training/FP baseline) | — | reproducible benign syscall traffic |
| `[ ]` EVAL-1.2 | Container-escape attack script (the demo chain) | — | triggers the FSM to compromised state |

## Phase 4 — Benchmarks & results
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` EVAL-4.1 | Latency harness: syscall overhead (ns) with/without Statewall | AGT-4.1 | reproducible latency numbers |
| `[ ]` EVAL-4.2 | Memory vs. process-count measurement (the flat curve) | BPF-4.1 | flat-line result produced |
| `[ ]` EVAL-4.3 | Efficacy: detection rate + false-positive rate | EVAL-1.*, BPF-2.* | precision/recall per kill chain |
| `[ ]` EVAL-4.4 | Head-to-head vs Falco/Tetragon (reaction timing) | DEP-4.1 | sync (ns) vs async (ms) shown |
| `[ ]` EVAL-4.5 | Results tables + plots for the thesis | EVAL-4.1–4.4 | figures ready for `DOC-3` |
