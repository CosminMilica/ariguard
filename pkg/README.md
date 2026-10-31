# pkg — shared Go libraries

Code shared between `agent/` and `control-plane/`.

- **fsm** — Go mirror of the in-kernel ABI (`bpf/statewall-common`). State/event/action
  constants and map key/value layouts. Must stay in sync with the Rust source of truth.

gRPC-generated types live under `proto/` (generated), not here.
