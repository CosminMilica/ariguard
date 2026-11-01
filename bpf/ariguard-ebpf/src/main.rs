#![no_std]
#![no_main]

// Phase 1.5 generic FSM engine: one tracepoint per hook, a shared inlined handler
// that evaluates every binding of the hook, advances each matching rule's per-workload
// state through its block of AG_TRANSITIONS and emits an AuditRecord. Detection only,
// no enforcement (that is phase 2, BPF LSM).

use ariguard_common::{
    AuditRecord, FsmKey, FsmState, HookBindings, Policy, Rule, Transition, ACTION_DENY,
    ACTION_KILL, ACTION_OBSERVE, ARG_ANY, ARG_EQ, ARG_LE, ARG_MASK_ANY, ARG_MASK_NONE, HOOK_BPF,
    HOOK_CONNECT, HOOK_DUP2, HOOK_DUP3, HOOK_EXECVE, HOOK_EXECVEAT, HOOK_FINIT_MODULE,
    HOOK_FSMOUNT, HOOK_INIT_MODULE, HOOK_MEMFD_CREATE, HOOK_MOUNT, HOOK_MOVE_MOUNT, HOOK_OPENAT,
    HOOK_PTRACE, HOOK_SETNS, HOOK_UNSHARE, MAX_BINDINGS_PER_HOOK, MAX_RULES, MAX_TRACKED_WORKLOADS,
    MAX_TRANSITIONS, PATH_ANY, PATH_PREFIX, PATH_SUN_PREFIX, PATTERN_LEN, SCOPE_PROCESS,
    STATE_INITIAL,
};
use aya_ebpf::{
    btf_maps::{Array, LruHashMap, PerCpuArray, RingBuf},
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_ktime_get_ns, bpf_probe_read_user_str_bytes, bpf_send_signal,
    },
    macros::{btf_map, lsm, tracepoint},
    programs::{LsmContext, TracePointContext},
};

#[unsafe(no_mangle)]
#[unsafe(link_section = "license")]
pub static LICENSE: [u8; 4] = *b"GPL\0";

const AUDIT_RING_BYTES: usize = 256 * 1024;

// cgroup v2 root (kernfs inode 1); host processes outside any cgroup are ignored.
const ROOT_CGROUP_ID: u64 = 1;

// Map update flags.
const BPF_NOEXIST: u64 = 1;

// First syscall argument is at this record offset; argument i is at BASE + 8*i.
const ARG_BASE: usize = 16;
// sockaddr_un.sun_path starts here in the pointed-to struct.
const SUN_PATH_OFF: u64 = 2;

// SIGKILL, delivered by bpf_send_signal to the current task (F1, F5).
const SIGKILL: u32 = 9;

// Negated and returned from an LSM hook to refuse the operation (phase 2b).
const EPERM: i32 = 1;

// How long a deny token stays valid between the sys_enter tracepoint and the LSM
// hook of the same syscall (1s); a stale token is ignored so a later benign call
// on a reused tid is never refused on an old decision.
const DENY_TOKEN_TTL_NS: u64 = 1_000_000_000;

// AG_METRICS per-CPU counters; indices mirror pkg/fsm (events, kills, audit_dropped, denies).
const NUM_METRICS: usize = 4;
const METRIC_EVENTS: u32 = 0;
const METRIC_KILLS: u32 = 1;
const METRIC_AUDIT_DROPPED: u32 = 2;
const METRIC_DENIES: u32 = 3;

#[btf_map]
static AG_POLICY: Array<Policy, 1> = Array::new();

#[btf_map]
static AG_RULES: Array<Rule, { MAX_RULES as usize }> = Array::new();

#[btf_map]
static AG_TRANSITIONS: Array<Transition, { MAX_TRANSITIONS as usize }> = Array::new();

#[btf_map]
static AG_BINDINGS: Array<HookBindings, { ariguard_common::NUM_HOOKS as usize }> = Array::new();

#[btf_map]
static AG_STATE: LruHashMap<FsmKey, FsmState, { ariguard_common::MAX_TRACKED_WORKLOADS as usize }> =
    LruHashMap::new();

#[btf_map]
static AG_AUDIT: RingBuf<AuditRecord, AUDIT_RING_BYTES> = RingBuf::new();

#[btf_map]
static AG_SCRATCH: PerCpuArray<[u8; PATTERN_LEN], 1> = PerCpuArray::new();

// Pod cgroup ids that are mitigation candidates (F2); the agent populates it from
// podmeta. A KILL fires only for a cgroup present here.
#[btf_map]
static AG_PODS: LruHashMap<u64, u8, 16384> = LruHashMap::new();

// Per-CPU counters read by the agent (F7). Indices: events, kills, audit_dropped, denies.
#[btf_map]
static AG_METRICS: PerCpuArray<u64, NUM_METRICS> = PerCpuArray::new();

// A pending -EPERM verdict for a syscall (phase 2b). The sys_enter_* tracepoint, the
// single FSM writer, records one keyed by the full pid_tgid when a committed transition's
// action is DENY under enforcement; the LSM hook for that same syscall consumes it and
// returns -EPERM. Internal to the data plane: the agent never reads it, so it has no Go
// mirror. hook distinguishes which LSM hook may honor the token.
#[repr(C)]
#[derive(Clone, Copy)]
struct DenyToken {
    hook: u32,
    rule: u32,
    event: u32,
    from_state: u32,
    to_state: u32,
    _pad: u32,
    ts_ns: u64,
}

#[btf_map]
static AG_DENY: LruHashMap<u64, DenyToken, { MAX_TRACKED_WORKLOADS as usize }> = LruHashMap::new();

// child tgid -> parent tgid, populated synchronously on fork. The agent reads it to attach
// process ancestry (ppid) to audit events — no task_struct walk, so this stays verifier-cheap
// on older kernels and the record ABI is unchanged.
#[btf_map]
static AG_PPID: LruHashMap<u32, u32, { MAX_TRACKED_WORKLOADS as usize }> = LruHashMap::new();

// sched_process_fork format: common(8) + parent_comm[16]@8 + parent_pid@24 + child_comm[16]@28
// + child_pid@44. Records child -> parent so the agent can resolve ppid for any later event.
#[tracepoint(category = "sched", name = "sched_process_fork")]
pub fn trace_fork(ctx: TracePointContext) -> u32 {
    let parent_pid = unsafe { ctx.read_at::<i32>(24) }.unwrap_or(0) as u32;
    let child_pid = unsafe { ctx.read_at::<i32>(44) }.unwrap_or(0) as u32;
    if child_pid != 0 {
        let _ = AG_PPID.insert(&child_pid, &parent_pid, 0);
    }
    0
}

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

#[tracepoint(category = "syscalls", name = "sys_enter_connect")]
pub fn sw_connect(ctx: TracePointContext) -> u32 {
    handle(&ctx, HOOK_CONNECT)
}

#[tracepoint(category = "syscalls", name = "sys_enter_dup2")]
pub fn sw_dup2(ctx: TracePointContext) -> u32 {
    handle(&ctx, HOOK_DUP2)
}

#[tracepoint(category = "syscalls", name = "sys_enter_dup3")]
pub fn sw_dup3(ctx: TracePointContext) -> u32 {
    handle(&ctx, HOOK_DUP3)
}

#[tracepoint(category = "syscalls", name = "sys_enter_memfd_create")]
pub fn sw_memfd_create(ctx: TracePointContext) -> u32 {
    handle(&ctx, HOOK_MEMFD_CREATE)
}

#[tracepoint(category = "syscalls", name = "sys_enter_execveat")]
pub fn sw_execveat(ctx: TracePointContext) -> u32 {
    handle(&ctx, HOOK_EXECVEAT)
}

#[tracepoint(category = "syscalls", name = "sys_enter_fsmount")]
pub fn sw_fsmount(ctx: TracePointContext) -> u32 {
    handle(&ctx, HOOK_FSMOUNT)
}

#[tracepoint(category = "syscalls", name = "sys_enter_move_mount")]
pub fn sw_move_mount(ctx: TracePointContext) -> u32 {
    handle(&ctx, HOOK_MOVE_MOUNT)
}

#[tracepoint(category = "syscalls", name = "sys_enter_init_module")]
pub fn sw_init_module(ctx: TracePointContext) -> u32 {
    handle(&ctx, HOOK_INIT_MODULE)
}

#[tracepoint(category = "syscalls", name = "sys_enter_finit_module")]
pub fn sw_finit_module(ctx: TracePointContext) -> u32 {
    handle(&ctx, HOOK_FINIT_MODULE)
}

#[tracepoint(category = "syscalls", name = "sys_enter_bpf")]
pub fn sw_bpf(ctx: TracePointContext) -> u32 {
    handle(&ctx, HOOK_BPF)
}

// Reads syscall argument i (a u64) from the tracepoint record.
#[inline(always)]
fn read_arg(ctx: &TracePointContext, i: u32) -> Option<u64> {
    unsafe { ctx.read_at::<u64>(ARG_BASE + 8 * i as usize) }.ok()
}

// Reads the hook's path argument into AG_SCRATCH; returns the string length (no NUL).
// PATH_SUN_PREFIX reads sockaddr_un.sun_path at offset 2 of the pointed-to struct.
#[inline(always)]
fn read_path(ctx: &TracePointContext, path_arg: u32, path_kind: u32) -> Option<usize> {
    let ptr = read_arg(ctx, path_arg)?;
    if ptr == 0 {
        return None;
    }
    let addr = if path_kind == PATH_SUN_PREFIX {
        ptr + SUN_PATH_OFF
    } else {
        ptr
    };
    let buf = AG_SCRATCH.get_ptr_mut(0)?;
    let len = unsafe { bpf_probe_read_user_str_bytes(addr as *const u8, &mut *buf) }
        .ok()?
        .len();
    Some(len)
}

// Prefix match against the current AG_SCRATCH contents. The loop never breaks on a
// variable bound: a pre-6.8 verifier cannot bound an early exit on `plen`.
#[inline(always)]
fn prefix_matches(len: usize, pattern: &[u8; PATTERN_LEN], plen: u32) -> bool {
    let plen = plen as usize;
    if plen == 0 || plen > len {
        return false;
    }
    let Some(buf) = AG_SCRATCH.get_ptr(0) else {
        return false;
    };
    let buf = unsafe { &*buf };
    for j in 0..PATTERN_LEN {
        if j < plen && buf[j] != pattern[j] {
            return false;
        }
    }
    true
}

#[inline(always)]
fn arg_matches(ctx: &TracePointContext, op: u32, index: u32, value: u64) -> bool {
    if op == ARG_ANY {
        return true;
    }
    let Some(v) = read_arg(ctx, index) else {
        return false;
    };
    match op {
        ARG_EQ => v == value,
        ARG_LE => v <= value,
        ARG_MASK_ANY => (v & value) != 0,
        ARG_MASK_NONE => (v & value) == 0,
        _ => false,
    }
}

// Increments a per-CPU counter (F7). Per-CPU, so a plain read-modify-write is race-free.
#[inline(always)]
fn bump_metric(index: u32) {
    if let Some(p) = AG_METRICS.get_ptr_mut(index) {
        unsafe { *p += 1 };
    }
}

// Reports whether the workload's committed state is `state` (re-read from the map). Used
// to gate enforcement so a kill fires only on the last-writer-wins commit (see advance).
#[inline(always)]
fn state_is(key: &FsmKey, state: u32) -> bool {
    match AG_STATE.get_ptr(key) {
        Some(p) => unsafe { (*p).state == state },
        None => false,
    }
}

// Applies one transition of `rule` on `event` to the workload's state. `can_kill` is
// (policy.enforce == 1 && cgroup in AG_PODS); when the committed transition's action is
// KILL and can_kill holds, the current task is SIGKILLed and the audit record is marked
// enforced (F5). Detection, state and audit are identical to Phase 1.5 otherwise.
#[inline(always)]
fn advance(rule: u32, event: u32, hook: u32, cgroup_id: u64, tgid: u32, can_kill: bool) {
    let Some(rp) = AG_RULES.get_ptr(rule) else {
        return;
    };
    let (num_states, num_events, trans_base, scope, terminal_from, window_ns) = unsafe {
        (
            (*rp).num_states,
            (*rp).num_events,
            (*rp).trans_base,
            (*rp).scope,
            (*rp).terminal_from,
            (*rp).window_ns,
        )
    };
    if num_states == 0 || num_events == 0 || event >= num_events {
        return;
    }

    let id = if scope == SCOPE_PROCESS {
        tgid as u64
    } else {
        cgroup_id
    };
    let key = FsmKey { id, rule, _pad: 0 };

    let now = unsafe { bpf_ktime_get_ns() };
    let (tracked, mut state, updated_ns) = match AG_STATE.get_ptr(&key) {
        Some(p) => unsafe { (true, (*p).state, (*p).updated_ns) },
        None => (false, STATE_INITIAL, 0),
    };
    // Terminal states (index >= terminal_from) never expire (E8).
    if window_ns > 0 && state < terminal_from && now.wrapping_sub(updated_ns) > window_ns {
        state = STATE_INITIAL;
    }
    if state >= num_states {
        return;
    }

    let rel = state * num_events + event;
    let index = trans_base + rel;
    if rel >= num_states * num_events || index >= MAX_TRANSITIONS {
        return;
    }
    let Some(tp) = AG_TRANSITIONS.get_ptr(index) else {
        return;
    };
    let (next_state, action) = unsafe { ((*tp).next_state, (*tp).action) };

    // State write (E9): first entry is created with BPF_NOEXIST; an advance updates in
    // place; returning to the initial state deletes the entry so only live chains are held.
    // The BPF target has atomic-cas: false, so a true compare-and-swap on FsmState.state
    // (the F4 intent) cannot be expressed; the write stays last-writer-wins. See the
    // residual-race note in bpf/TASKS.md.
    if next_state == STATE_INITIAL {
        if tracked {
            let _ = AG_STATE.remove(&key);
        }
    } else if next_state != state {
        let value = FsmState {
            state: next_state,
            last_event: event,
            updated_ns: now,
        };
        let flags = if tracked { 0 } else { BPF_NOEXIST };
        let _ = AG_STATE.insert(&key, &value, flags);
    }

    // Enforcement (F5): kill only when the committed action is KILL, can_kill holds, and the
    // workload's current committed state is the one this transition produced. Re-reading the
    // state closes the last-writer-wins gap at the enforcement layer: if a concurrent syscall
    // clobbered this step, the re-read no longer matches and no kill fires on a stale decision.
    let committed = next_state == state || state_is(&key, next_state);
    let enforced = can_kill && action == ACTION_KILL && committed;

    // Deny (phase 2b): when the committed action is DENY under enforcement, arm a token for
    // this task. The LSM hook of this same syscall consumes it and returns -EPERM, refusing
    // the operation before it runs. The tracepoint stays the single state writer and does not
    // mark this record enforced: the mitigation is applied (and audited enforced) by the LSM
    // hook only if it actually fires, so a kernel without BPF LSM leaves the token inert and
    // falls back to the kill transition further along the chain.
    if can_kill && action == ACTION_DENY && committed {
        let pid_tgid = bpf_get_current_pid_tgid();
        let token = DenyToken {
            hook,
            rule,
            event,
            from_state: state,
            to_state: next_state,
            _pad: 0,
            ts_ns: now,
        };
        let _ = AG_DENY.insert(&pid_tgid, &token, 0);
    }

    if next_state != state || action != ACTION_OBSERVE {
        if let Some(mut entry) = AG_AUDIT.reserve(0) {
            let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
            entry.write(AuditRecord {
                cgroup_id,
                ts_ns: now,
                pid: tgid,
                hook,
                rule,
                event,
                from_state: state,
                to_state: next_state,
                action,
                enforced: enforced as u32,
                comm,
            });
            entry.submit(0);
        } else {
            bump_metric(METRIC_AUDIT_DROPPED);
        }
    }

    if enforced {
        unsafe {
            bpf_send_signal(SIGKILL);
        }
        bump_metric(METRIC_KILLS);
    }
}

// Consumes a deny token armed by the tracepoint for the current task (phase 2b). Returns
// -EPERM when a fresh token for this hook is pending, refusing the syscall before it runs,
// and audits the refusal as an enforced DENY. Returns 0 (allow) otherwise. The token is
// removed on consumption; a stale one (TTL elapsed, or for another hook) is ignored.
#[inline(always)]
fn lsm_verdict(hook: u32) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let token = match AG_DENY.get_ptr(&pid_tgid) {
        Some(p) => unsafe { *p },
        None => return 0,
    };
    let _ = AG_DENY.remove(&pid_tgid);
    if token.hook != hook {
        return 0;
    }
    let now = unsafe { bpf_ktime_get_ns() };
    if now.wrapping_sub(token.ts_ns) > DENY_TOKEN_TTL_NS {
        return 0;
    }

    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if let Some(mut entry) = AG_AUDIT.reserve(0) {
        let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
        entry.write(AuditRecord {
            cgroup_id,
            ts_ns: now,
            pid: (pid_tgid >> 32) as u32,
            hook: token.hook,
            rule: token.rule,
            event: token.event,
            from_state: token.from_state,
            to_state: token.to_state,
            action: ACTION_DENY,
            enforced: 1,
            comm,
        });
        entry.submit(0);
    } else {
        bump_metric(METRIC_AUDIT_DROPPED);
    }
    bump_metric(METRIC_DENIES);
    -EPERM
}

// LSM hooks that honor a deny token. sb_mount backs the mount syscall (HOOK_MOUNT) and
// move_mount backs move_mount (HOOK_MOVE_MOUNT) — the host_mount step of container-escape.
// Both run inside their syscall, after the matching sys_enter tracepoint, so the token is
// already armed. Kernels without BPF LSM (or lacking a hook's BTF) skip these at load time.
#[lsm(hook = "sb_mount")]
pub fn lsm_sb_mount(_ctx: LsmContext) -> i32 {
    lsm_verdict(HOOK_MOUNT)
}

#[lsm(hook = "move_mount")]
pub fn lsm_move_mount(_ctx: LsmContext) -> i32 {
    lsm_verdict(HOOK_MOVE_MOUNT)
}

#[inline(always)]
fn handle(ctx: &TracePointContext, hook: u32) -> u32 {
    let Some(pp) = AG_POLICY.get_ptr(0) else {
        return 0;
    };
    let (num_rules, enforce) = unsafe { ((*pp).num_rules, (*pp).enforce) };
    if num_rules == 0 {
        return 0;
    }

    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    if cgroup_id == ROOT_CGROUP_ID {
        return 0;
    }
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Per-pod enforcement gate (F2, F3): a KILL fires only when enforcement is on and the
    // cgroup is a tracked pod. Short-circuit keeps the detect-only path free of the lookup.
    let can_kill = enforce == 1 && AG_PODS.get_ptr(&cgroup_id).is_some();

    let Some(hb) = AG_BINDINGS.get_ptr(hook) else {
        return 0;
    };
    let count = unsafe { (*hb).count } as usize;

    // One transition per rule per syscall: first matching binding wins (E4).
    let mut done: u32 = 0;
    // Path is read at most once per invocation; cached across the hook's bindings.
    let mut path_read = false;
    let mut path_len: usize = 0;

    for i in 0..MAX_BINDINGS_PER_HOOK {
        if i >= count {
            break;
        }
        let b = unsafe { &(*hb).entries[i] };
        let rule = b.rule;
        if rule >= MAX_RULES || (done & (1 << rule)) != 0 {
            continue;
        }

        let path_ok = match b.path_kind {
            PATH_ANY => true,
            PATH_PREFIX | PATH_SUN_PREFIX => {
                if !path_read {
                    path_len = read_path(ctx, b.path_arg, b.path_kind).unwrap_or(0);
                    path_read = true;
                }
                path_len != 0 && prefix_matches(path_len, &b.pattern, b.path_len)
            }
            _ => false,
        };
        if !path_ok {
            continue;
        }
        if !arg_matches(ctx, b.arg_op, b.arg_index, b.arg_value) {
            continue;
        }

        bump_metric(METRIC_EVENTS);
        advance(rule, b.event, hook, cgroup_id, tgid, can_kill);
        done |= 1 << rule;
    }
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
