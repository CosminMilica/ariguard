#![no_std]

//! Shared ABI between the eBPF data plane and user space (v3, phase 1.5).
//! Changing any layout here requires updating the Go mirror in pkg/fsm.

/// Every rule starts in state 0; state names live in the bundle metadata.
pub const STATE_INITIAL: u32 = 0;

/// Mitigation actions, ordered by severity.
pub const ACTION_OBSERVE: u32 = 0;
pub const ACTION_THROTTLE: u32 = 1;
pub const ACTION_DENY: u32 = 2;
pub const ACTION_KILL: u32 = 3;

/// Hook points: one `syscalls/sys_enter_<name>` tracepoint program each.
/// Index into AG_BINDINGS.
pub const HOOK_OPENAT: u32 = 0;
pub const HOOK_SETNS: u32 = 1;
pub const HOOK_UNSHARE: u32 = 2;
pub const HOOK_MOUNT: u32 = 3;
pub const HOOK_EXECVE: u32 = 4;
pub const HOOK_PTRACE: u32 = 5;
pub const HOOK_CONNECT: u32 = 6;
pub const HOOK_DUP2: u32 = 7;
pub const HOOK_DUP3: u32 = 8;
pub const HOOK_MEMFD_CREATE: u32 = 9;
pub const HOOK_EXECVEAT: u32 = 10;
pub const HOOK_FSMOUNT: u32 = 11;
pub const HOOK_MOVE_MOUNT: u32 = 12;
pub const HOOK_INIT_MODULE: u32 = 13;
pub const HOOK_FINIT_MODULE: u32 = 14;
pub const HOOK_BPF: u32 = 15;
pub const NUM_HOOKS: u32 = 16;

/// Whose state a rule tracks.
pub const SCOPE_CGROUP: u32 = 0;
pub const SCOPE_PROCESS: u32 = 1;

/// Path predicate on the argument `path_arg`.
pub const PATH_ANY: u32 = 0;
/// NUL-terminated string at the argument pointer.
pub const PATH_PREFIX: u32 = 1;
/// `sockaddr_un.sun_path` at the argument pointer (connect).
pub const PATH_SUN_PREFIX: u32 = 2;
/// Match when the `connect` sockaddr is AF_INET and not loopback (no pattern). Lets a rule fire
/// only on outbound network connects, ignoring AF_UNIX local IPC and loopback (B3/FP-killer).
pub const PATH_INET: u32 = 3;

/// Argument predicate on the argument `arg_index`.
pub const ARG_ANY: u32 = 0;
pub const ARG_EQ: u32 = 1;
pub const ARG_LE: u32 = 2;
/// `(arg & arg_value) != 0`
pub const ARG_MASK_ANY: u32 = 3;
/// `(arg & arg_value) == 0`
pub const ARG_MASK_NONE: u32 = 4;

/// Unused argument index.
pub const NO_ARG: u32 = u32::MAX;
pub const MAX_SYSCALL_ARGS: u32 = 6;

/// Path buffer size; patterns are at most `PATTERN_LEN - 1` bytes.
pub const PATTERN_LEN: usize = 32;
pub const COMM_LEN: usize = 16;

/// Fixed map capacities (zero-allocation budget, set at load time).
/// The per-hook binding budget is bundle-wide: all rules' bindings on one hook share it. Raised
/// 8->16 so the library can grow persistence/indicator-removal chains (openat + execve are the
/// busiest hooks). The hot-path match loop (main.rs) reads the path once and is bounded by this
/// constant; the 5.15..7.0 verifier matrix gates the change.
pub const MAX_BINDINGS_PER_HOOK: usize = 14;
pub const MAX_RULES: u32 = 16;
pub const MAX_TRANSITIONS: u32 = 1024;
pub const MAX_TRACKED_WORKLOADS: u32 = 16384;

/// Key into AG_STATE: `id` is the cgroup id or the tgid, per the rule's scope.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FsmKey {
    pub id: u64,
    pub rule: u32,
    pub _pad: u32,
}

/// Current state of one (workload, rule) pair.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FsmState {
    pub state: u32,
    pub last_event: u32,
    pub updated_ns: u64,
}

/// One transition-table cell: (state, event) -> (next_state, action).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Transition {
    pub next_state: u32,
    pub action: u32,
}

/// A hook firing raises `event` in `rule` when both predicates hold.
/// Same layout on the wire (policy bundle) and in the kernel map.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Binding {
    pub hook: u32,
    pub rule: u32,
    pub event: u32,
    pub path_arg: u32,
    pub path_kind: u32,
    pub path_len: u32,
    pub arg_index: u32,
    pub arg_op: u32,
    pub arg_value: u64,
    pub pattern: [u8; PATTERN_LEN],
}

/// Value of AG_BINDINGS, indexed by hook.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HookBindings {
    pub count: u32,
    pub _pad: u32,
    pub entries: [Binding; MAX_BINDINGS_PER_HOOK],
}

/// One rule. Its cells start at `trans_base` in AG_TRANSITIONS. States with
/// index >= `terminal_from` never expire; `window_ns` = 0 disables expiry.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Rule {
    pub num_states: u32,
    pub num_events: u32,
    pub trans_base: u32,
    pub scope: u32,
    pub terminal_from: u32,
    pub _pad: u32,
    pub window_ns: u64,
}

/// AG_POLICY[0]. `num_rules` = 0 means no policy (programs return at once).
/// `enforce` = 1 applies mitigations; 0 is detect-only (dry run).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Policy {
    pub num_rules: u32,
    pub enforce: u32,
}

/// Emitted to AG_AUDIT when a state changes or the action is not observe.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuditRecord {
    pub cgroup_id: u64,
    pub ts_ns: u64,
    pub pid: u32,
    pub hook: u32,
    pub rule: u32,
    pub event: u32,
    pub from_state: u32,
    pub to_state: u32,
    pub action: u32,
    pub enforced: u32,
    pub comm: [u8; COMM_LEN],
}

/// Observed IPv4 `connect` destination, written to AG_CONNDST keyed by tgid (B3). `ip`/`port` are
/// in network byte order. A dedicated map keeps the connect capture out of the hot binding loop,
/// so the shared handler stays within the verifier's complexity budget (like the AG_PPID map).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnDst {
    pub ip: u32,
    pub port: u16,
    pub _pad: u16,
}

/// Observed path of an exec/memfd hook (execve/execveat/memfd_create), written to AG_PATH keyed by
/// tgid (B3) by the hook wrapper, so the agent can attach the concrete path IOC (the binary that ran,
/// the fileless object name). `len` is the string length (no NUL), capped at PATTERN_LEN-1; `buf` is
/// the NUL-terminated path prefix.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PathVal {
    pub len: u32,
    pub _pad: u32,
    pub buf: [u8; PATTERN_LEN],
}

/// Number of exec argv entries captured, and the per-entry byte budget. Fixed slots (not a packed
/// buffer) so each entry is written at a constant offset — the verifier can bound that; a running
/// offset over variable-length strings it cannot (pre-6.8).
pub const MAX_ARGS: usize = 5;
pub const ARG_LEN: usize = 32;

/// Observed exec argv, written to AG_ARGV keyed by tgid (B3) by the execve/execveat wrappers. `args`
/// holds up to MAX_ARGS NUL-terminated entries, each truncated to ARG_LEN-1 bytes; `argc` is how many
/// were present. The agent joins them into the command line for the audit event.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ArgvVal {
    pub argc: u32,
    pub _pad: u32,
    pub args: [[u8; ARG_LEN]; MAX_ARGS],
}

/// Emitted to AG_LEARN on every hooked syscall of an opt-in learn-mode cgroup (F11): one raw event,
/// no FSM. The agent assembles these per (cgroup, tgid) into full-syscall traces the rulegen loop
/// mines for novel chains. Written only by the dedicated `_learn` programs.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LearnRecord {
    pub cgroup_id: u64,
    pub ts_ns: u64,
    pub pid: u32,
    pub hook: u32,
}
