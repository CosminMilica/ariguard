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
| D9 | The agent opens a bare perf event per online CPU for each attached tracepoint | some kernels (7.0-azure, AKS) run syscall tracepoint programs only on CPUs with a perf event open; `link.Tracepoint` opens one on CPU 0 |

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

## Phase 1.5 decisions

Phase 1.5 turns the single hard-wired chain into a generic engine: several rules at once,
argument predicates, more hooks. It replaces the phase 1 ABI (v2) and bundle (v2) with v3.

| # | Decision | Why |
|---|---|---|
| E1 | A policy holds up to `MAX_RULES` rules, evaluated together | one detector per kill chain, all active at once |
| E2 | State is kept per (workload, rule): `FsmKey { id, rule }` | rules do not overwrite each other's progress |
| E3 | Each rule has a scope: `cgroup` (all processes of a container) or `process` (one tgid) | escapes span processes; a reverse shell is one process, and per-process state cuts false positives |
| E4 | One syscall can raise events in several rules; within a rule the first matching binding wins | `execve("/bin/sh")` is a step of two different chains |
| E5 | Bindings carry a path predicate (`PATH_PREFIX`, `PATH_SUN_PREFIX`) and an argument predicate (`EQ`, `LE`, `MASK_ANY`, `MASK_NONE`) on any syscall argument by index | the kernel stays generic: no per-hook code, everything comes from the bundle |
| E6 | Runtime-socket access is also matched on `connect` to a unix socket (`sockaddr_un.sun_path`) | real clients (`curl --unix-socket`, docker CLI) connect; only `cat` uses `openat` |
| E7 | `mount` ignores propagation-only changes (`MS_SHARED`, `MS_PRIVATE`, `MS_SLAVE`, `MS_UNBINDABLE`); `fsmount` and `move_mount` count as mounts | fixes `unshare -m` walking a chain by itself; closes the new-mount-API gap (`BPF-1.9`) |
| E8 | States at or after `terminal_from` never expire | `compromised` must not silently return to the initial state |
| E9 | State transitions are atomic: insert with `BPF_NOEXIST`, advance with compare-and-swap on `state` | no skipped or doubled step when one workload runs on several CPUs |
| E10 | Patterns are at most `PATTERN_LEN - 1` bytes | the scratch buffer holds the NUL; a 64-byte pattern could never match |
| E11 | State, event and rule names travel in the bundle metadata, not in the ABI | rules define their own states; the kernel only sees numbers |
| E12 | Audit records carry `comm`; the agent adds namespace, pod and container | readable audit; the checker can assert on pod names |
| E13 | The engine must verify on every kernel in the CI matrix (5.15 → stable): bounded loops only, no `bpf_loop`, no kfuncs | the CI kernel gate is blocking |
| E14 | A hook whose tracepoint does not exist on the running kernel is skipped with a warning (e.g. `dup2` on arm64) | one object for every architecture |

### Kernel object contract (v3)

| Kind | Name | Type, capacity | Key → value |
|---|---|---|---|
| program | `sw_<hook>` for the 16 hooks | tracepoint `syscalls/sys_enter_<hook>` | — |
| map | `SW_POLICY` | `ARRAY`, 1 | `0` → `Policy` |
| map | `SW_RULES` | `ARRAY`, `MAX_RULES` | rule → `Rule` |
| map | `SW_TRANSITIONS` | `ARRAY`, `MAX_TRANSITIONS` | `trans_base + state * num_events + event` → `Transition` |
| map | `SW_BINDINGS` | `ARRAY`, `NUM_HOOKS` | hook → `HookBindings` (up to 8) |
| map | `SW_STATE` | `LRU_HASH`, `MAX_TRACKED_WORKLOADS` | `FsmKey` → `FsmState` |
| map | `SW_AUDIT` | `RINGBUF`, 256 KiB | `AuditRecord` (64 B) |
| map | `SW_SCRATCH` | `PERCPU_ARRAY`, 1 | `0` → `[u8; PATTERN_LEN]` |

Hooks, in id order: `openat setns unshare mount execve ptrace connect dup2 dup3
memfd_create execveat fsmount move_mount init_module finit_module bpf`. Syscall
argument `i` is read from the tracepoint record at offset `16 + 8 * i`.

Per syscall, a program: reads `SW_POLICY` (returns if no rules); skips the root cgroup;
walks the hook's bindings; for each binding whose rule has not matched yet and whose
predicates hold, applies one transition in that rule: key by scope, expire if allowed,
read the cell, update the state atomically, emit an `AuditRecord` if the state changed
or the action is not `observe`.

Hot swap: `SW_POLICY = {0}` → `SW_RULES` → `SW_TRANSITIONS` → `SW_BINDINGS` (all 16
hooks) → `SW_POLICY = {num_rules}`.

### Policy bundle format v3

```
Header (32 B):  magic u32 = 0x53544254 ("STBT"), version u32 = 3,
                num_rules u32, num_transitions u32, num_bindings u32, meta_len u32,
                reserved u64 = 0
Rules:          num_rules × Rule (32 B)
Transitions:    num_transitions × Transition (8 B); rule r owns
                [trans_base, trans_base + num_states * num_events), row-major
Bindings:       num_bindings × Binding (104 B), same layout as the kernel struct
Metadata:       meta_len bytes of UTF-8 JSON, compact, sorted keys:
                {"rules":[{"events":[…],"name":"…","scope":"cgroup|process","states":[…]}]}
```

Limits checked by both compiler and agent: `num_rules ≤ MAX_RULES`, `num_transitions ≤
MAX_TRANSITIONS`, rule ranges inside the table, `terminal_from ≤ num_states`, ≤ 8
bindings per hook, `binding.rule < num_rules`, `binding.event < rule.num_events`,
`path_len ≤ PATTERN_LEN - 1` (and > 0 for a path predicate), argument indexes `< 6` or
`NO_ARG`, known scope, path kind and argument operator.

### Rule file schema v3

One rule per file in `compiler/rules/`; the compiler links all of them into one bundle.

```yaml
name: container-escape
scope: cgroup                # cgroup | process
window_seconds: 30
states: [normal, suspicious, escalating, breakout_imminent, compromised]
terminal: [compromised]      # optional, must be a suffix of states
events:
  runtime_socket_open:
    - hook: openat
      path_prefix: [/run/containerd/containerd.sock, /var/run/docker.sock, /run/docker.sock]
    - hook: connect
      sun_path_prefix: [/run/containerd/containerd.sock, /var/run/docker.sock, /run/docker.sock]
  host_mount:
    - hook: mount
      arg: {index: 3, mask_none: 0x1E0000}   # not propagation-only
    - hook: fsmount
    - hook: move_mount
transitions:
  - {from: normal, event: runtime_socket_open, to: suspicious, action: observe}
```

The compiler knows each hook's path argument (`openat` 1, `execve` 0, `execveat` 1,
`mount` 1, `memfd_create` 0, `connect` 1 for `sun_path_prefix`); a path predicate on a
hook without one is an error. `arg` takes exactly one of `eq`, `le`, `mask_any`,
`mask_none`.
