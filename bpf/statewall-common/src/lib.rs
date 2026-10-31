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
/// Index into SW_BINDINGS.
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
pub const PATTERN_LEN: usize = 64;
pub const COMM_LEN: usize = 16;

/// Fixed map capacities (zero-allocation budget, set at load time).
pub const MAX_BINDINGS_PER_HOOK: usize = 8;
pub const MAX_RULES: u32 = 16;
pub const MAX_TRANSITIONS: u32 = 1024;
pub const MAX_TRACKED_WORKLOADS: u32 = 16384;

/// Key into SW_STATE: `id` is the cgroup id or the tgid, per the rule's scope.
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

/// Value of SW_BINDINGS, indexed by hook.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HookBindings {
    pub count: u32,
    pub _pad: u32,
    pub entries: [Binding; MAX_BINDINGS_PER_HOOK],
}

/// One rule. Its cells start at `trans_base` in SW_TRANSITIONS. States with
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

/// SW_POLICY[0]. `num_rules` = 0 means no policy (programs return at once).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Policy {
    pub num_rules: u32,
    pub _pad: u32,
}

/// Emitted to SW_AUDIT when a state changes or the action is not observe.
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
    pub _pad: u32,
    pub comm: [u8; COMM_LEN],
}
