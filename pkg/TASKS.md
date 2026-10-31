# pkg — Tasks

Shared Go libraries. See [ROADMAP.md](../ROADMAP.md).
Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked.

## Phase 0 — ABI mirror
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[x]` PKG-0.1 | Go mirror of `bpf/statewall-common` (states, events, actions, key/value structs) | — | constants + structs defined in `pkg/fsm` |
| `[x]` PKG-0.2 | Size/offset assertion test guarding ABI drift vs the Rust source of truth | PKG-0.1 | test fails if layouts diverge |

## Phase 1 — Serialization
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[x]` PKG-1.1 | Transition-table (de)serialization shared format | PKG-0.1 | compiler output ↔ Go round-trips |
| `[x]` PKG-1.2 | Cross-language golden test (Go reads the Python-emitted table) | PKG-1.1, CMP-1.2 | `go test ./pkg/...` decodes `testdata/golden/` |
| `[x]` PKG-1.3 | Go mirror of ABI v2 (hooks, `Binding`, `HookBindings`, `Dims`, `AuditRecord`) + size/offset tests | BPF-1.0 | `go test ./pkg/...` passes |
| `[x]` PKG-1.4 | Policy bundle v2 (de)serialization, replacing v1; golden test on v2 | PKG-1.3, CMP-1.6 | Go decodes the v2 golden |

## Phase 3 — Generated proto
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` PKG-3.1 | Home + helpers for generated proto types (`pkg/proto/...`) | PROTO-0.1 | generated code imports cleanly |
