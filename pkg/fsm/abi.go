package fsm

import "unsafe"

// Mirror of bpf/ariguard-common (ABI v3). Struct and field names must match the
// Rust ones (case and underscores aside): btf_test.go compares them with the object.

// StateInitial is the state every rule starts in.
const StateInitial uint32 = 0

// Mitigation actions, ordered by severity.
const (
	ActionObserve  uint32 = 0
	ActionThrottle uint32 = 1
	ActionDeny     uint32 = 2
	ActionKill     uint32 = 3
)

// Hook points: one syscalls/sys_enter_<name> tracepoint program each.
const (
	HookOpenat      uint32 = 0
	HookSetns       uint32 = 1
	HookUnshare     uint32 = 2
	HookMount       uint32 = 3
	HookExecve      uint32 = 4
	HookPtrace      uint32 = 5
	HookConnect     uint32 = 6
	HookDup2        uint32 = 7
	HookDup3        uint32 = 8
	HookMemfdCreate uint32 = 9
	HookExecveat    uint32 = 10
	HookFsmount     uint32 = 11
	HookMoveMount   uint32 = 12
	HookInitModule  uint32 = 13
	HookFinitModule uint32 = 14
	HookBPF         uint32 = 15
	NumHooks        uint32 = 16
)

// Whose state a rule tracks.
const (
	ScopeCgroup  uint32 = 0
	ScopeProcess uint32 = 1
)

// Path predicates.
const (
	PathAny       uint32 = 0
	PathPrefix    uint32 = 1 // NUL-terminated string at the argument pointer
	PathSunPrefix uint32 = 2 // sockaddr_un.sun_path at the argument pointer
)

// Argument predicates.
const (
	ArgAny      uint32 = 0
	ArgEq       uint32 = 1
	ArgLe       uint32 = 2
	ArgMaskAny  uint32 = 3 // (arg & value) != 0
	ArgMaskNone uint32 = 4 // (arg & value) == 0
)

// NoArg marks an unused argument index.
const (
	NoArg          uint32 = 0xFFFFFFFF
	MaxSyscallArgs uint32 = 6
)

const (
	PatternLen         = 64 // buffer size; patterns are at most PatternLen-1 bytes
	CommLen            = 16
	MaxBindingsPerHook = 8
)

// Fixed map capacities (zero-allocation budget, set at load time).
const (
	MaxRules            uint32 = 16
	MaxTransitions      uint32 = 1024
	MaxTrackedWorkloads uint32 = 16384
)

// AuditRingBytes is the byte size of AG_AUDIT; mirrors AUDIT_RING_BYTES in bpf/ariguard-ebpf.
const AuditRingBytes = 256 * 1024

// BPFMapBytes is the pre-allocated, constant memory budget of the AG_* contract
// maps: for each map, max_entries * (key_size + value_size), from the fixed specs
// here (plus the audit ring's byte size). It does not vary with the number of
// tracked workloads.
func BPFMapBytes() uint64 {
	const u32 = 4 // array map key width
	var (
		fsmKey       = uint64(unsafe.Sizeof(FsmKey{}))
		fsmState     = uint64(unsafe.Sizeof(FsmState{}))
		transition   = uint64(unsafe.Sizeof(Transition{}))
		hookBindings = uint64(unsafe.Sizeof(HookBindings{}))
		rule         = uint64(unsafe.Sizeof(Rule{}))
		policy       = uint64(unsafe.Sizeof(Policy{}))
	)
	total := uint64(0)
	total += uint64(MaxTrackedWorkloads) * (fsmKey + fsmState) // AG_STATE
	total += uint64(MaxTransitions) * (u32 + transition)       // AG_TRANSITIONS
	total += uint64(NumHooks) * (u32 + hookBindings)           // AG_BINDINGS
	total += uint64(MaxRules) * (u32 + rule)                   // AG_RULES
	total += 1 * (u32 + policy)                                // AG_POLICY
	total += uint64(MaxTrackedWorkloads) * (8 + 1)             // AG_PODS (u64 -> u8)
	total += uint64(NumMetrics) * (u32 + 8)                    // AG_METRICS (u64 per index)
	total += 1 * (u32 + uint64(PatternLen))                    // AG_SCRATCH ([u8; PatternLen])
	total += AuditRingBytes                                    // AG_AUDIT
	return total
}

// AG_METRICS per-CPU counter indices.
const (
	MetricEvents       uint32 = 0
	MetricKills        uint32 = 1
	MetricAuditDropped uint32 = 2
	MetricDenies       uint32 = 3
	NumMetrics         uint32 = 4
)

// FsmKey keys AG_STATE; ID is the cgroup id or the tgid per the rule's scope. 16 bytes.
type FsmKey struct {
	ID   uint64
	Rule uint32
	_    uint32
}

// FsmState is the current state of one (workload, rule) pair. 16 bytes.
type FsmState struct {
	State     uint32
	LastEvent uint32
	UpdatedNs uint64
}

// Transition is one table cell: (state, event) -> (next_state, action). 8 bytes.
type Transition struct {
	NextState uint32
	Action    uint32
}

// Binding raises Event in Rule when its hook fires and both predicates hold.
// Same layout on the wire and in the kernel map. 104 bytes.
type Binding struct {
	Hook     uint32
	Rule     uint32
	Event    uint32
	PathArg  uint32
	PathKind uint32
	PathLen  uint32
	ArgIndex uint32
	ArgOp    uint32
	ArgValue uint64
	Pattern  [PatternLen]byte
}

// HookBindings is the AG_BINDINGS value, indexed by hook. 840 bytes.
type HookBindings struct {
	Count   uint32
	_       uint32
	Entries [MaxBindingsPerHook]Binding
}

// Rule is one AG_RULES entry; its cells start at TransBase in AG_TRANSITIONS. 32 bytes.
type Rule struct {
	NumStates    uint32
	NumEvents    uint32
	TransBase    uint32
	Scope        uint32
	TerminalFrom uint32
	_            uint32
	WindowNs     uint64
}

// Policy is AG_POLICY[0]; NumRules = 0 disables evaluation. Enforce = 1 applies
// mitigations, 0 is detect-only (dry run). 8 bytes.
type Policy struct {
	NumRules uint32
	Enforce  uint32
}

// AuditRecord is emitted to AG_AUDIT on a state change or a non-observe action. 72 bytes.
type AuditRecord struct {
	CgroupID  uint64
	TsNs      uint64
	Pid       uint32
	Ppid      uint32
	Hook      uint32
	Rule      uint32
	Event     uint32
	FromState uint32
	ToState   uint32
	Action    uint32
	Enforced  uint32
	Comm      [CommLen]byte
}
