# docs — Tasks

Documentation + dissertation artifacts. See [ROADMAP.md](../ROADMAP.md).
Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked.

## Ongoing
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` DOC-1 | Keep `architecture.md` in sync with the implementation | — | matches current design each phase |
| `[ ]` DOC-2 | Refine `threat-model.md` as scope firms up | — | in/out-of-scope accurate |

## Phase 4 — Thesis
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` DOC-3 | Map contributions → related work → evaluation (thesis write-up) | EVAL-4.* | dissertation chapters drafted |
| `[ ]` DOC-4 | Demo runbook (reproducible steps for the defense) | — | anyone can reproduce the demo |

## Console (Tier C follow-ups) — see [backlog.md](backlog.md)
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` DOC-5 | Relabel C3 honestly: call the current image-correlation view "actor spread"; reserve "lateral movement" for the observed network pivots (backlog F2 / AGT-5.2) (backlog F3) | — | console no longer claims lateral movement it doesn't observe |
| `[ ]` DOC-6 | Richer actor IOCs (C2): add dst IP (and later file hash) to the actor key once B3 lands (backlog F4) | BPF-5.1 | "same actor" correlation keyed on observed IOCs, not just image digest |
| `[ ]` DOC-7 | Console hardening: SQLite retention/rotation, auth, and multi-node correlation across agents (cross-node campaigns/actors) (backlog F10) | — | retention + auth + cross-node correlation in place |
