package fsm

// Mirror of bpf/statewall-common (ABI v3). Struct and field names must match the
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

// SW_METRICS per-CPU counter indices.
const (
	MetricEvents       uint32 = 0
	MetricKills        uint32 = 1
	MetricAuditDropped uint32 = 2
	NumMetrics         uint32 = 3
)

// FsmKey keys SW_STATE; ID is the cgroup id or the tgid per the rule's scope. 16 bytes.
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

// HookBindings is the SW_BINDINGS value, indexed by hook. 840 bytes.
type HookBindings struct {
	Count   uint32
	_       uint32
	Entries [MaxBindingsPerHook]Binding
}

// Rule is one SW_RULES entry; its cells start at TransBase in SW_TRANSITIONS. 32 bytes.
type Rule struct {
	NumStates    uint32
	NumEvents    uint32
	TransBase    uint32
	Scope        uint32
	TerminalFrom uint32
	_            uint32
	WindowNs     uint64
}

// Policy is SW_POLICY[0]; NumRules = 0 disables evaluation. Enforce = 1 applies
// mitigations, 0 is detect-only (dry run). 8 bytes.
type Policy struct {
	NumRules uint32
	Enforce  uint32
}

// AuditRecord is emitted to SW_AUDIT on a state change or a non-observe action. 64 bytes.
type AuditRecord struct {
	CgroupID  uint64
	TsNs      uint64
	Pid       uint32
	Hook      uint32
	Rule      uint32
	Event     uint32
	FromState uint32
	ToState   uint32
	Action    uint32
	Enforced  uint32
	Comm      [CommLen]byte
}
