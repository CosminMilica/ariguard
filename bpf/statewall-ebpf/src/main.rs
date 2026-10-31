#![no_std]
#![no_main]

// Phase 1 passive FSM: one tracepoint per hook, a shared handler that maps the
// syscall to an event via SW_BINDINGS, advances the per-cgroup state through
// SW_TRANSITIONS and emits an AuditRecord. Detection only, no enforcement.

use aya_ebpf::{
    btf_maps::{Array, LruHashMap, PerCpuArray, RingBuf},
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_ns,
        bpf_probe_read_user_str_bytes,
    },
    macros::{btf_map, tracepoint},
    programs::TracePointContext,
    EbpfContext,
};
use statewall_common::{
    AuditRecord, Dims, FsmKey, FsmState, HookBindings, Transition, ACTION_OBSERVE, HOOK_EXECVE,
    HOOK_MOUNT, HOOK_OPENAT, HOOK_PTRACE, HOOK_SETNS, HOOK_UNSHARE, MATCH_ANY, MATCH_PATH_PREFIX,
    MAX_BINDINGS_PER_HOOK, MAX_TRACKED_WORKLOADS, MAX_TRANSITIONS, NUM_HOOKS, PATTERN_LEN,
    STATE_NORMAL,
};

#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
pub static LICENSE: [u8; 4] = *b"GPL\0";

const AUDIT_RING_BYTES: usize = 256 * 1024;

// cgroup v2 root (kernfs inode 1); host processes outside any cgroup are ignored (D8).
const ROOT_CGROUP_ID: u64 = 1;

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

#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn sw_openat(ctx: TracePointContext) -> u32 {
    handle(&ctx, HOOK_OPENAT)
}

#[tracepoint(category = "syscalls", name = "sys_enter_setns")]
pub fn sw_setns(ctx: TracePointContext) -> u32 {
    handle(&ctx, HOOK_SETNS)
}

#[tracepoint(category = "syscalls", name = "sys_enter_unshare")]
pub fn sw_unshare(ctx: TracePointContext) -> u32 {
    handle(&ctx, HOOK_UNSHARE)
}

#[tracepoint(category = "syscalls", name = "sys_enter_mount")]
pub fn sw_mount(ctx: TracePointContext) -> u32 {
    handle(&ctx, HOOK_MOUNT)
}

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn sw_execve(ctx: TracePointContext) -> u32 {
    handle(&ctx, HOOK_EXECVE)
}

#[tracepoint(category = "syscalls", name = "sys_enter_ptrace")]
pub fn sw_ptrace(ctx: TracePointContext) -> u32 {
    handle(&ctx, HOOK_PTRACE)
}

// Offset of the path argument in the sys_enter_<hook> record
// (/sys/kernel/tracing/events/syscalls/sys_enter_*/format, kernel 6.8).
#[inline(always)]
fn path_offset(hook: u32) -> Option<usize> {
    match hook {
        HOOK_OPENAT => Some(24), // filename
        HOOK_EXECVE => Some(16), // filename
        HOOK_MOUNT => Some(24),  // dir_name
        _ => None,
    }
}

// Reads the hook's path argument into SW_SCRATCH; returns the buffer and the
// string length without NUL.
#[inline(always)]
fn read_path(ctx: &TracePointContext, hook: u32) -> Option<(*const [u8; PATTERN_LEN], usize)> {
    let off = path_offset(hook)?;
    let ptr = unsafe { *(ctx.as_ptr().cast::<u8>().add(off).cast::<u64>()) };
    if ptr == 0 {
        return None;
    }
    let buf = SW_SCRATCH.get_ptr_mut(0)?;
    let len = unsafe { bpf_probe_read_user_str_bytes(ptr as *const u8, &mut *buf) }
        .ok()?
        .len();
    Some((buf.cast_const(), len))
}

#[inline(always)]
fn prefix_matches(
    buf: *const [u8; PATTERN_LEN],
    len: usize,
    pattern: &[u8; PATTERN_LEN],
    plen: u32,
) -> bool {
    let plen = plen as usize;
    if plen == 0 || plen > len {
        return false;
    }
    let buf = unsafe { &*buf };
    for j in 0..PATTERN_LEN {
        if j >= plen {
            break;
        }
        if buf[j] != pattern[j] {
            return false;
        }
    }
    true
}

// Returns the event raised by this hook firing, first matching binding wins.
#[inline(always)]
fn match_event(ctx: &TracePointContext, hook: u32) -> Option<u32> {
    let hb: *const HookBindings = SW_BINDINGS.get_ptr(hook)?;
    let count = unsafe { (*hb).count } as usize;
    // Path is read at most once: None = not read yet, Some(None) = unreadable.
    let mut path = None;
    for i in 0..MAX_BINDINGS_PER_HOOK {
        if i >= count {
            break;
        }
        let b = unsafe { &(*hb).entries[i] };
        match b.match_kind {
            MATCH_ANY => return Some(b.event),
            MATCH_PATH_PREFIX => {
                if let Some((buf, len)) = *path.get_or_insert_with(|| read_path(ctx, hook)) {
                    if prefix_matches(buf, len, &b.pattern, b.pattern_len) {
                        return Some(b.event);
                    }
                }
            }
            _ => {}
        }
    }
    None
}

#[inline(always)]
fn handle(ctx: &TracePointContext, hook: u32) -> u32 {
    let Some(dims) = SW_DIMS.get_ptr(0) else {
        return 0;
    };
    let (num_states, num_events, window_ns) =
        unsafe { ((*dims).num_states, (*dims).num_events, (*dims).window_ns) };
    if num_states == 0 || num_events == 0 {
        return 0;
    }

    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if cgroup_id == ROOT_CGROUP_ID {
        return 0;
    }

    let Some(event) = match_event(ctx, hook) else {
        return 0;
    };
    if event >= num_events {
        return 0;
    }

    let now = unsafe { bpf_ktime_get_ns() };
    let key = FsmKey { cgroup_id };
    let (tracked, mut state, updated_ns) = match SW_STATE.get_ptr(&key) {
        Some(p) => unsafe { (true, (*p).state, (*p).updated_ns) },
        None => (false, STATE_NORMAL, 0),
    };
    if window_ns > 0 && state != STATE_NORMAL && now.wrapping_sub(updated_ns) > window_ns {
        state = STATE_NORMAL;
    }
    if state >= num_states {
        return 0;
    }

    let index = state * num_events + event;
    if index >= num_states * num_events || index >= MAX_TRANSITIONS {
        return 0;
    }
    let Some(t) = SW_TRANSITIONS.get_ptr(index) else {
        return 0;
    };
    let (next_state, action) = unsafe { ((*t).next_state, (*t).action) };

    // Only non-normal workloads hold an entry; a tracked workload that is back
    // in normal (expired or by transition) has its entry removed.
    if next_state == STATE_NORMAL {
        if tracked {
            let _ = SW_STATE.remove(&key);
        }
    } else if next_state != state {
        let value = FsmState {
            state: next_state,
            last_event: event,
            updated_ns: now,
        };
        let _ = SW_STATE.insert(&key, &value, 0);
    }

    if next_state != state || action != ACTION_OBSERVE {
        if let Some(mut entry) = SW_AUDIT.reserve(0) {
            entry.write(AuditRecord {
                cgroup_id,
                ts_ns: now,
                pid: (bpf_get_current_pid_tgid() >> 32) as u32,
                hook,
                event,
                from_state: state,
                to_state: next_state,
                action,
            });
            entry.submit(0);
        }
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
