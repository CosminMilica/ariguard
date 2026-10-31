# Architecture

> Expanded design notes. The high-level overview lives in the root [README](../README.md).

## Components

| Component | Language | Role |
|---|---|---|
| `bpf/` | Rust (Aya) | In-kernel FSM engine, syscall hooks, zero-allocation maps |
| `agent/` | Go (cilium/ebpf) | Per-node loader, map manager, telemetry pump (no decisions) |
| `control-plane/` | Go (controller-runtime) | CRDs, policy distribution, audit aggregation |
| `compiler/` | Python | Threat intel → transition tables (ML / LLM), offline |
| `proto/` | protobuf | gRPC contract: agent ↔ control-plane |

## The ABI boundary (critical)

`bpf/statewall-common` is the single source of truth for map key/value layouts and the
state/event/action enums. The Go mirror in `pkg/fsm` must match it byte-for-byte.

**Open decision (phase 0):** the eBPF object is authored in Rust (aya-ebpf) but loaded by
a Go agent (cilium/ebpf). Map/BTF conventions differ across these toolchains — validating
that the Go loader can consume the Rust-built object (and read its maps) is the first
engineering spike. Fallback: keep the node loader in Rust (Aya) and limit Go to the
cluster control plane.

## Data flow

1. `compiler/` turns rules into a transition table.
2. `control-plane/` stores it (CRD) and pushes it to agents over gRPC.
3. `agent/` writes the table into the kernel `ARRAY` map (hot swap, no reload).
4. Kernel programs advance per-cgroup state on each hooked syscall and mitigate in place.
5. Audit events flow back up through the ring buffer → agent → control plane.
