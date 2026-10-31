# Phase 2b — LSM `-EPERM` deny (prevent, not just kill)

**Status: implemented** (branch `feat/phase-2b-lsm-deny`).

## Goal
Make `ACTION_DENY` actually enforce: a BPF **LSM** program returns `-EPERM` from inside the
syscall, *before* the operation completes, so the escape never happens. Phase 2 kills the
attacker *after* the terminal syscall ran; 2b refuses the dangerous syscall itself. The ABI
already carried `ACTION_DENY`, so this is additive — no rework of the FSM.

The deny lands at the **host mount step**, not at execve. On the `container-escape` rule the
`host_mount` transition (`escalating -> breakout_imminent`) already carries `action: deny`;
the terminal `critical_execve` transition carries `action: kill`. 2b makes the mount deny
bite, which short-circuits the chain before the terminal step is ever reached.

Kill stays the fallback for transitions that have no LSM hook. The result is a **hybrid**:
deny where a hook exists, kill everywhere else.

## Why LSM
A tracepoint can only observe (and `bpf_send_signal` to kill after the fact). A
`BPF_PROG_TYPE_LSM` program attached to a security hook runs *in* the syscall and its return
value is honored by the kernel: return `-EPERM` → the operation is denied. Requires a kernel
with `CONFIG_BPF_LSM=y` and `bpf` listed in `/sys/kernel/security/lsm` (the dev VM and the
Ubuntu CI runners both have it).

## Mechanism — token hand-off (single writer preserved)
The `sys_enter_mount` tracepoint remains the **only FSM writer**. The LSM program never
advances state; it only reads a token and returns a verdict. This keeps the single-writer
invariant from phase 1.5 intact.

1. `sys_enter_mount` commits the `host_mount` transition as usual. If that transition's
   action is `ACTION_DENY` **and** enforcement is active (enforce mode on **and** the cgroup
   is in `AG_PODS`), the tracepoint **arms a deny token** in a new internal BPF map `AG_DENY`,
   keyed by `pid_tgid`. It also emits its own audit record, marked `enforced=0` (the
   tracepoint cannot itself refuse the syscall).
2. A BPF LSM program on the **`sb_mount`** hook (and **`move_mount`**) runs during the *same*
   syscall, looks up `AG_DENY` by `pid_tgid`, and if a token is present **consumes it and
   returns `-EPERM`** — refusing the mount before it happens. It emits the audit record that
   counts: `action=deny, enforced=1`.

Ordering holds: `sys_enter_mount` fires at syscall entry, before the `sb_mount`/`move_mount`
security hook, so the token is armed by the time the LSM program runs.

## Hybrid deny / kill
- **Kernel WITH BPF LSM active** (`/sys/kernel/security/lsm` contains `bpf`): the host mount
  is refused at `sb_mount`/`move_mount`, the chain **halts at `breakout_imminent`**, and the
  `critical_execve` terminal (and its `kill`) is never reached.
- **Kernel WITHOUT BPF LSM**: the LSM programs are dropped at load time by the capability
  gate, so the `AG_DENY` token is inert (nothing consumes it). The chain proceeds to the
  execve terminal and the fallback **`kill`** fires.
- **Transitions without an LSM counterpart** (e.g. `dup2` for the reverse-shell terminal)
  **always stay kill**, regardless of LSM availability.

## Syscall → LSM hook mapping
`sb_mount` and `move_mount` are the hooks **wired** in 2b. The rest are listed as available
extension points, not shipped.

| Tracked event | LSM hook | Status in 2b |
|---|---|---|
| mount | `sb_mount` | ✅ wired (deny) |
| move_mount | `move_mount` | ✅ wired (deny, ≥5.x) |
| execve / execveat | `bprm_check_security` | extension point (not shipped) |
| openat | `file_open` | extension point (not shipped) |
| connect | `socket_connect` | extension point (not shipped) |
| ptrace | `ptrace_access_check` | extension point (not shipped) |
| bpf | `bpf` | extension point (not shipped) |
| setns, unshare, dup2/3, memfd_create, fsmount, *_module | — (no direct hook) | → stays kill |

## Loader & ABI
- ABI: `ACTION_DENY` already exists; no struct-layout change. The audit `action` already
  encodes deny; `enforced` distinguishes the tracepoint record (`0`) from the LSM record (`1`).
- Loader (`agent/internal/loader`): attaches the `BPF_PROG_TYPE_LSM` programs
  (`sb_mount`, `move_mount`) with `cilium/ebpf` (`AttachLSM`). When BPF LSM is unavailable
  the LSM programs are **dropped at load time** (capability gate, skip-with-warning, same
  pattern as E14). Enforce/deny is gated by `Policy.enforce` + `AG_PODS`.
- Mode: `enforce` already means "act"; `ACTION_DENY` transitions deny via LSM, `ACTION_KILL`
  transitions kill via tracepoint. No new flag — the committed transition's action decides
  the path.

## Metrics
A new counter `ariguard_denies_total` counts refusals (incremented on each `-EPERM` returned
by the LSM program), alongside the existing kill counter.

## Kernel & CI requirements
- `CONFIG_BPF_LSM=y` and `bpf` present in `/sys/kernel/security/lsm`.
- Kernels without BPF LSM **skip** (not fail) the deny test — capability gate.

## Testing
The proof is that the **mount is refused**, not merely that a process died.

- **In-kernel integration test** (`agent/internal/integration`): drives
  socket → `setns` → host-mount through the `container-escape` chain and asserts (a) the
  **mount syscall returns `EPERM`** (captured from the workload, not just from audit) and
  (b) an **enforced deny** audit record appears (`action=deny, enforced=1`). It **skips**
  when BPF LSM is not active.
- **Where it runs**: the host-kernel leg of the kernel matrix in CI (Ubuntu runners enable
  BPF LSM) and in the dev VM.

## Risks
- Not every terminal has an LSM hook → hybrid deny/kill (documented above).
- Verifier limits on LSM programs (same `no_std`/zero-alloc constraints as the engine).
- BPF LSM absent on some CI kernels → the deny test skips there.
- Ordering tracepoint→LSM within one syscall must hold per hook (covered by the integration
  test).
