#![no_std]

//! Shared ABI between the eBPF data plane and user space.
//! Changing any layout here requires regenerating the Go map bindings.

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
