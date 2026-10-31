#![no_std]

//! Shared ABI between the eBPF data plane and user space.
//! Changing any layout here requires updating the Go mirror in pkg/fsm.

/// FSM states, ordered by severity.
pub const STATE_NORMAL: u32 = 0;
pub const STATE_SUSPICIOUS: u32 = 1;
pub const STATE_ESCALATING: u32 = 2;
pub const STATE_BREAKOUT_IMMINENT: u32 = 3;
pub const STATE_COMPROMISED: u32 = 4;

/// Mitigation actions, ordered by severity.
pub const ACTION_OBSERVE: u32 = 0;
pub const ACTION_THROTTLE: u32 = 1;
pub const ACTION_DENY: u32 = 2;
pub const ACTION_KILL: u32 = 3;

/// Hook points (one tracepoint program each). Index into the bindings map.
pub const HOOK_OPENAT: u32 = 0;
pub const HOOK_SETNS: u32 = 1;
pub const HOOK_UNSHARE: u32 = 2;
pub const HOOK_MOUNT: u32 = 3;
pub const HOOK_EXECVE: u32 = 4;
pub const HOOK_PTRACE: u32 = 5;
pub const NUM_HOOKS: u32 = 6;

/// Binding predicates.
pub const MATCH_ANY: u32 = 0;
pub const MATCH_PATH_PREFIX: u32 = 1;

pub const PATTERN_LEN: usize = 64;
pub const MAX_BINDINGS_PER_HOOK: usize = 4;

/// Fixed map capacities (zero-allocation budget, set at load time).
pub const MAX_TRANSITIONS: u32 = 1024;
pub const MAX_TRACKED_WORKLOADS: u32 = 16384;

/// Key into the per-workload state map.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FsmKey {
    pub cgroup_id: u64,
}

/// Current FSM state for a workload.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FsmState {
    pub state: u32,
    pub last_event: u32,
    pub updated_ns: u64,
}

/// One entry of the transition table: (state, event) -> (next_state, action).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Transition {
    pub next_state: u32,
    pub action: u32,
}

/// Maps a hook firing to an event, optionally gated by a path predicate.
/// Same layout on the wire (policy bundle) and in the kernel map.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Binding {
    pub hook: u32,
    pub event: u32,
    pub match_kind: u32,
    pub pattern_len: u32,
    pub pattern: [u8; PATTERN_LEN],
}

/// Value of the bindings map, indexed by hook.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HookBindings {
    pub count: u32,
    pub _pad: u32,
    pub entries: [Binding; MAX_BINDINGS_PER_HOOK],
}

/// Active policy dimensions. `window_ns` = 0 disables state expiry.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Dims {
    pub num_states: u32,
    pub num_events: u32,
    pub window_ns: u64,
}

/// Audit record emitted to the ring buffer on every state transition.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuditRecord {
    pub cgroup_id: u64,
    pub ts_ns: u64,
    pub pid: u32,
    pub hook: u32,
    pub event: u32,
    pub from_state: u32,
    pub to_state: u32,
    pub action: u32,
}
