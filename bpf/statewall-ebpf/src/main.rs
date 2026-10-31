#![no_std]
#![no_main]

// Phase-0 gate: the contract maps plus one execve tracepoint that emits an
// audit record while a policy is loaded. The FSM engine lands in phase 1.

use aya_ebpf::{
    btf_maps::{Array, LruHashMap, PerCpuArray, RingBuf},
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::{btf_map, tracepoint},
    programs::TracePointContext,
};
use statewall_common::{
    AuditRecord, Dims, FsmKey, FsmState, HookBindings, Transition, ACTION_OBSERVE, HOOK_EXECVE,
    MAX_TRACKED_WORKLOADS, MAX_TRANSITIONS, NUM_HOOKS, PATTERN_LEN, STATE_NORMAL,
};

const AUDIT_RING_BYTES: usize = 256 * 1024;

#[btf_map]
static SW_STATE: LruHashMap<FsmKey, FsmState, { MAX_TRACKED_WORKLOADS as usize }> =
    LruHashMap::new();

#[btf_map]
static SW_TRANSITIONS: Array<Transition, { MAX_TRANSITIONS as usize }> = Array::new();

#[btf_map]
static SW_BINDINGS: Array<HookBindings, { NUM_HOOKS as usize }> = Array::new();

#[btf_map]
static SW_DIMS: Array<Dims, 1> = Array::new();

#[btf_map]
static SW_AUDIT: RingBuf<AuditRecord, AUDIT_RING_BYTES> = RingBuf::new();

#[btf_map]
static SW_SCRATCH: PerCpuArray<[u8; PATTERN_LEN], 1> = PerCpuArray::new();

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn sw_execve(_ctx: TracePointContext) -> u32 {
    let Some(dims) = SW_DIMS.get(0) else {
        return 0;
    };
    if dims.num_states == 0 {
        return 0;
    }
    let Some(mut entry) = SW_AUDIT.reserve(0) else {
        return 0;
    };
    entry.write(AuditRecord {
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        ts_ns: unsafe { bpf_ktime_get_ns() },
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        hook: HOOK_EXECVE,
        event: 0,
        from_state: STATE_NORMAL,
        to_state: STATE_NORMAL,
        action: ACTION_OBSERVE,
    });
    entry.submit(0);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
