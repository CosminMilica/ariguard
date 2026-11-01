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

`bpf/ariguard-common` is the single source of truth for map key/value layouts and the
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
| map | `AG_STATE` | `LRU_HASH`, `MAX_TRACKED_WORKLOADS` | `FsmKey` → `FsmState` |
| map | `AG_TRANSITIONS` | `ARRAY`, `MAX_TRANSITIONS` | `u32` index → `Transition` |
| map | `AG_BINDINGS` | `ARRAY`, `NUM_HOOKS` | `u32` hook → `HookBindings` |
| map | `AG_DIMS` | `ARRAY`, 1 | `0` → `Dims` |
| map | `AG_AUDIT` | `RINGBUF`, 256 KiB | `AuditRecord` stream |
| map | `AG_SCRATCH` | `PERCPU_ARRAY`, 1 | `0` → `[u8; PATTERN_LEN]` |

Transition index = `state * num_events + event`. An empty `AG_DIMS` means no policy:
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
| map | `AG_POLICY` | `ARRAY`, 1 | `0` → `Policy` |
| map | `AG_RULES` | `ARRAY`, `MAX_RULES` | rule → `Rule` |
| map | `AG_TRANSITIONS` | `ARRAY`, `MAX_TRANSITIONS` | `trans_base + state * num_events + event` → `Transition` |
| map | `AG_BINDINGS` | `ARRAY`, `NUM_HOOKS` | hook → `HookBindings` (up to 8) |
| map | `AG_STATE` | `LRU_HASH`, `MAX_TRACKED_WORKLOADS` | `FsmKey` → `FsmState` |
| map | `AG_AUDIT` | `RINGBUF`, 256 KiB | `AuditRecord` (72 B, see Tier B capture) |
| map | `AG_SCRATCH` | `PERCPU_ARRAY`, 1 | `0` → `[u8; PATTERN_LEN]` |

Hooks, in id order: `openat setns unshare mount execve ptrace connect dup2 dup3
memfd_create execveat fsmount move_mount init_module finit_module bpf`. Syscall
argument `i` is read from the tracepoint record at offset `16 + 8 * i`.

Per syscall, a program: reads `AG_POLICY` (returns if no rules); skips the root cgroup;
walks the hook's bindings; for each binding whose rule has not matched yet and whose
predicates hold, applies one transition in that rule: key by scope, expire if allowed,
read the cell, update the state atomically, emit an `AuditRecord` if the state changed
or the action is not `observe`.

Hot swap: `AG_POLICY = {0}` → `AG_RULES` → `AG_TRANSITIONS` → `AG_BINDINGS` (all 16
hooks) → `AG_POLICY = {num_rules}`.

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

## Phase 2 decisions — synchronous mitigation (kill-based)

Phase 1.5 detects; Phase 2 acts. This branch (`feat/mitigation`) adds **kill-based
enforcement** from the existing tracepoint engine plus the safety machinery it requires.
`-EPERM` deny via BPF LSM is a separate, additive follow-up (the ABI already carries
`ACTION_DENY`; nothing here blocks it).

| # | Decision | Why |
|---|---|---|
| F1 | Enforce by `bpf_send_signal(SIGKILL)` from the tracepoint engine | a tracepoint cannot deny a syscall, but it can kill the current task; highest-value, lowest-risk enforcement, no new attach surface |
| F2 | Only pod cgroups are mitigation candidates | detection runs for every cgroup, but a KILL only fires when the workload's cgroup is in `AG_PODS`, so the node's own runtime/systemd cgroups can never be killed (closes the Phase 1.5 host false-positive at the enforcement layer) |
| F3 | Global enforce switch in `Policy.enforce` (0 = detect-only, 1 = enforce) | run dry (actions recorded, nothing applied), then flip to enforcing; the demo shows both. Default 0 (safe) |
| F4 | Atomic transition before enforcing: CAS on `FsmState.state` | replaces last-writer-wins (E9); only the committed winner enforces, so a concurrent syscall can't skip the step that triggers the kill |
| F5 | KILL fires only when `enforce==1` AND the committed transition's action is `kill` AND the cgroup ∈ `AG_PODS` | `throttle`/`deny` stay audit-only on this branch; `deny` becomes real with the LSM follow-up |
| F6 | `dup2` has no tracepoint on arm64 | glibc maps `dup2`→`dup3` there (already covered); LSM coverage is a follow-up |
| F7 | Per-CPU metrics map `AG_METRICS` | events / kills / dropped-audit counters, read by the agent and exposed as Prometheus metrics |

### ABI additions (v3.1, additive — no existing field moves)

- `Policy._pad` → `enforce: u32` (same 8-byte layout).
- `AuditRecord._pad` → `enforced: u32` (1 when a mitigation was applied; same 64-byte layout).
- New map `AG_PODS`: `LRU_HASH`, key `u64` cgroup id → `u8` present; the agent populates it
  from `podmeta` (every tracked pod cgroup) and prunes on pod deletion.
- New map `AG_METRICS`: `PERCPU_ARRAY` of `u64` counters (indices: events, kills, audit_dropped).

Mirrored in `pkg/fsm`; the `btf_test.go` size/offset checks extend to the new fields and maps.

### Enforcement path (kernel)

After the committed transition (F4): if `policy.enforce == 1`, `action == ACTION_KILL`, and
`AG_PODS` contains the cgroup id, call `bpf_send_signal(SIGKILL)` and set `enforced = 1` on
the audit record; bump the `AG_METRICS` kill counter. Everything else is unchanged from
Phase 1.5 — detection, audit and the dry-run path are identical whether or not enforcement
is on.

## Tier B capture — process ancestry and container image

Added for the incident-investigation console (see
[docs/incident-investigation-plan.md](incident-investigation-plan.md)):

- **`ppid` (process ancestry).** `AuditRecord` gains a `ppid: u32`, growing the record from
  **64 to 72 bytes**. The kernel reads `task_struct->real_parent->tgid` via CO-RE, using
  `vmlinux` bindings generated from the kernel's BTF (`bpf/ariguard-ebpf/src/vmlinux.rs`,
  committed, auto-generated with `aya-tool`). The agent builds a process tree from it.
- **Container image + digest.** Agent-only, no kernel change: the agent resolves the image from
  the pod object and emits `image` / `image_id` per event, which the sink stores.

Mirrored in `pkg/fsm`; the size/offset checks extend to the new `ppid` field.

## Tier C1 — autonomous workload isolation

The in-kernel kill/deny stops the offending **process**; it does not contain the **workload** —
a pod can keep running (and its egress/ingress open) after a confirmed kill. Tier C1 closes that
gap with no new kernel work: it is pure agent/control-plane (see
[docs/tier-c-plan.md](tier-c-plan.md)).

- **Trigger.** The ringbuf audit stream drives an `audit.Reactor` interface. On a confirmed
  terminal mitigation — an `AuditRecord` with `enforced == 1` and action `kill` or `deny` — the
  agent's responder (`agent/internal/responder`) quarantines that pod, once. The pod identity is
  already resolved from `podmeta` (namespace/pod). The reactor runs off the audit drain, so it is
  non-blocking and never on the kernel data path.
- **Quarantine action.** The responder labels the pod `ariguard.io/quarantine=true` and adds the
  annotations `ariguard.io/quarantine-rule` and `ariguard.io/quarantined-at`. In mode `on` it also
  creates a namespace-scoped deny-all NetworkPolicy named `ariguard-quarantine` (podSelector
  `ariguard.io/quarantine=true`, `policyTypes: Ingress, Egress`, no ingress/egress rules = deny
  all). This cuts egress (C2 callback, exfiltration), ingress and lateral movement while leaving
  the pod running for investigation (isolate-don't-destroy).
- **Gating + safety.** `--isolate=off|dryrun|on`; `dryrun` labels only, no NetworkPolicy. It is
  idempotent (a pod is quarantined once), never isolates system namespaces (`kube-system`,
  `kube-public`, `kube-node-lease`, `ariguard-system`), and honors muted pods — the same allowlist
  spirit as the F2 pod-gating.
- **Wiring + reporting.** The agent gets a `--isolate` flag; each quarantine is reported to the
  console via `POST /api/v1/quarantine`.
- **CNI caveat.** NetworkPolicy is enforced by the CNI (Cilium/Calico). kindnet (kind's default)
  does **not** enforce it, so on kind the policy object is created but traffic is not actually
  blocked.

### RBAC additions

The agent ClusterRole gains `pods: get,patch` and
`networking.k8s.io/networkpolicies: get,list,create,update`
(`deploy/k8s/base/rbac.yaml` + Helm). Deploy wiring: Helm value `agent.isolate` (default `"off"`)
appends `--isolate=<mode>`; a new kustomize overlay `deploy/k8s/overlays/isolate` runs
`--enforce --isolate=on`.

### Console

Ingest `POST /api/v1/quarantine` writes a `quarantine` table; read `GET /api/quarantine`. A
`quarantined` boolean is added to `/api/triage` and `/api/incidents`, surfaced as an `ISOLATED`
badge in the Triage and Incidents UI.

## Tier C2 — actor correlation

Console-only, no kernel/agent change: it reuses the incident-group materialization (now carrying
`image_id`/`image`/`comm`) and the container image + digest captured in Tier B1.

- **`GET /api/actors`** clusters incident groups by **container image digest** (`image_id`): the
  same compromised image seen across many pods and namespaces is one actor — a campaign by payload,
  not by rule — sorted widest-spread (most pods) first. Each actor carries its image + digest,
  incidents, pods, namespaces, nodes, killed/blocked/detected counts, the `rules[]` it triggered,
  the `comms[]`, and `affected_namespaces[]`. The frontend **Actors** page is one row per actor,
  wide-spread rows accented.

## Tier C3 — lateral-movement trails

Also console-only, on existing incident data.

- **`GET /api/lateral`** reconstructs attacker movement as **per-actor trails**: for each actor
  (container image digest) it returns the distinct namespaces that actor reached in first-seen order
  (`path`, earliest-first), `hops` (len(path) − 1; 0 = no lateral movement), plus its namespaces,
  pods, incidents, killed/blocked counts, the `rules[]` it triggered and first/last seen; actors
  sort movers-first. The response is `{ actors: [...], namespaces: [...] }`, the namespace list
  feeding the filter. The frontend **Lateral** page is an actor-centric, filterable view (not a
  single graph): an explainer intro; Actor + Namespace dropdowns and a "Moved only" toggle (default
  on, hops ≥ 1); a list of actors, each row rendering the actor's namespace path as chips with arrows
  (ns-a → ns-b → ns-c) with hops/namespaces/pods/incidents, killed/blocked badges, rules and
  first/last seen; and a focused inline-SVG path diagram (a left→right line of the namespaces) shown
  only when a single actor is selected.

Still next: B3 (observed values — argv/path/connect dst IP:port), which will add the C2 dst IP as an
extra IOC.
