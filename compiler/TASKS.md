# compiler — Tasks

Threat intelligence → FSM tables (Python). See [ROADMAP.md](../ROADMAP.md).
Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked.

## Phase 1 — Hand-written rules → table
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[x]` CMP-1.1 | Rule file schema (YAML): states, events, transitions, actions | — | one kill chain expressible in YAML |
| `[x]` CMP-1.2 | `emit.py`: serialize FSM → transition-table binary matching the ABI | CMP-1.1, PKG-0.1 | output loads via `AGT-1.3` |
| `[x]` CMP-1.3 | CLI `statewall-compile` (rule file → table) | CMP-1.2 | `statewall-compile` produces a table |
| `[x]` CMP-1.4 | Golden test: emitted table matches the committed golden | CMP-1.2 | `pytest` matches `testdata/golden/` |
| `[x]` CMP-1.5 | Schema v2: events bind to hooks + optional `path_prefix`; `window_seconds` | BPF-1.0 | container-escape rule matches only runtime sockets |
| `[x]` CMP-1.6 | Emit policy bundle v2 (see `docs/architecture.md`); regenerate golden | CMP-1.5 | bundle passes limits; golden updated |

## Phase 3 — Intelligence-driven generation
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` CMP-3.1 | `sigma.py`: ATT&CK / Sigma rules → FSM transitions | CMP-1.1 | a Sigma rule compiles to a table |
| `[ ]` CMP-3.2 | `mine.py`: sequence mining from labeled syscall traces (ML) | EVAL-1.*, CMP-1.1 | learned chain detects held-out attacks |
| `[ ]` CMP-3.3 | LLM path: NL technique description → FSM (optional) | CMP-1.1 | NL prompt yields a valid FSM |
| `[ ]` CMP-3.4 | Validation: round-trip + respect kernel map size limits | CMP-1.2 | oversized/invalid tables rejected |
