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

**Resolved (phase 0 gate):** the Go agent (cilium/ebpf v0.22) loads the Rust object
(aya-ebpf 0.3, bpf-linker 0.12) unchanged. Maps are BTF-style (`#[btf_map]`, `.maps`
section), so bpftool and cilium/ebpf see typed keys and values, and every `Put` is checked
against the map's value size. The Go structs stay hand-mirrored in `pkg/fsm`, guarded by
size/offset tests (bpf2go does not apply to a Rust object). Linker flags `--btf` and
`--disable-expand-memcpy-in-order` are required; see [bpf/README.md](../bpf/README.md).

## Data flow

1. `compiler/` turns rules into a transition table.
2. `control-plane/` stores it (CRD) and pushes it to agents over gRPC.
3. `agent/` writes the table into the kernel `ARRAY` map (hot swap, no reload).
4. Kernel programs advance per-cgroup state on each hooked syscall and mitigate in place.
5. Audit events flow back up through the ring buffer → agent → control plane.

## Phase 1 decisions

| # | Decision | Why |
|---|---|---|
| D1 | Events come from per-syscall tracepoints `syscalls/sys_enter_*` (one program per hook) | stable ABI; enforcement moves to BPF LSM in phase 2 |
| D2 | Hooks: `openat`, `setns`, `unshare`, `mount`, `execve`, `ptrace` — no `open` | `open` does not exist on arm64 (Apple Silicon dev VM) |
| D3 | Events are gated by bindings (hook → event + optional path prefix) | without predicates every `openat` would trip the FSM |
| D4 | State expires after `window_ns` without progress (back to `normal`) | a chain must complete within a time window; cuts false positives |
| D5 | State map is `LRU_HASH`, preallocated (`MAX_TRACKED_WORKLOADS`) | fixed memory; stale cgroups evicted instead of exhausting the map |
| D6 | Path buffer lives in a per-CPU scratch map, not on the stack | 512 B stack limit; keeps the hot path allocation-free |
| D7 | In phase 1 the agent runs as a plain binary on the VM, not as a DaemonSet | shortest dev loop; DaemonSet lands with `DEP-1.1` |
| D8 | Track every non-root cgroup; per-pod selection comes later | kind pods are nested cgroups of the VM kernel; good enough for detection |

Known limitation (documented for the thesis): tracepoint path matching sees the
user-supplied string, so relative paths and symlinks bypass it. Phase 2 moves file
matching to `lsm/file_open` with `bpf_d_path` (resolved paths).

### Kernel object contract

Program and map names are the contract between `bpf/` and `agent/`.

| Kind | Name | Type / attach point | Key → value |
|---|---|---|---|
| program | `sw_openat` … `sw_ptrace` | tracepoint `syscalls/sys_enter_<hook>` | — |
| map | `SW_STATE` | `LRU_HASH`, `MAX_TRACKED_WORKLOADS` | `FsmKey` → `FsmState` |
| map | `SW_TRANSITIONS` | `ARRAY`, `MAX_TRANSITIONS` | `u32` index → `Transition` |
| map | `SW_BINDINGS` | `ARRAY`, `NUM_HOOKS` | `u32` hook → `HookBindings` |
| map | `SW_DIMS` | `ARRAY`, 1 | `0` → `Dims` |
| map | `SW_AUDIT` | `RINGBUF`, 256 KiB | `AuditRecord` stream |
| map | `SW_SCRATCH` | `PERCPU_ARRAY`, 1 | `0` → `[u8; PATTERN_LEN]` |

Transition index = `state * num_events + event`. An empty `SW_DIMS` means no policy:
programs return immediately.

### Policy bundle format v2

What the compiler emits and the agent loads. All little-endian.

```
Header (32 B): magic u32 = 0x53544254 ("STBT"), version u32 = 2,
               num_states u32, num_events u32, num_bindings u32, reserved u32 = 0,
               window_ns u64
Transitions:   num_states * num_events × Transition (8 B), row-major
Bindings:      num_bindings × Binding (80 B), same layout as the kernel struct
```

Limits checked by both compiler and agent: `num_states * num_events ≤ MAX_TRANSITIONS`,
`≤ MAX_BINDINGS_PER_HOOK` bindings per hook, `pattern_len ≤ PATTERN_LEN`.
