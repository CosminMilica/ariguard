# proto — Tasks

gRPC contract (agent ↔ control-plane). See [ROADMAP.md](../ROADMAP.md).
Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked.

## Phase 0 — Code generation
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[~]` PROTO-0.1 | `buf`/`protoc` setup + `make proto` target generating Go | — | `make proto` regenerates `pkg/proto/...` |

> PROTO-0.1: config (`proto/buf.yaml`, `buf.gen.yaml`) and `make proto` are in place.
> Generation not yet run — `buf`, `go`, and the `protoc-gen-go*` plugins are not installed
> on this host. Install per [README.md](README.md), run `make proto`, then flip to `[x]`.

## Phase 3 — Finalize contract
| ID | Task | Depends | Done when |
|---|---|---|---|
| `[ ]` PROTO-3.1 | Finalize service + messages; versioning policy | PROTO-0.1 | agent & control-plane build against it |
