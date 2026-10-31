package fsm

// FSM states, ordered by severity. Mirror of bpf/statewall-common.
const (
	StateNormal           uint32 = 0
	StateSuspicious       uint32 = 1
	StateEscalating       uint32 = 2
	StateBreakoutImminent uint32 = 3
	StateCompromised      uint32 = 4
)

// Mitigation actions, ordered by severity.
const (
	ActionObserve  uint32 = 0
	ActionThrottle uint32 = 1
	ActionDeny     uint32 = 2
	ActionKill     uint32 = 3
)

// Hook points (one tracepoint program each). Index into the bindings map.
const (
	HookOpenat  uint32 = 0
	HookSetns   uint32 = 1
	HookUnshare uint32 = 2
	HookMount   uint32 = 3
	HookExecve  uint32 = 4
	HookPtrace  uint32 = 5
	NumHooks    uint32 = 6
)

// Binding predicates.
const (
	MatchAny        uint32 = 0
	MatchPathPrefix uint32 = 1
)

const (
	PatternLen         = 64
	MaxBindingsPerHook = 4
)

// Fixed map capacities (zero-allocation budget, set at load time).
const (
	MaxTransitions      uint32 = 1024
	MaxTrackedWorkloads uint32 = 16384
)

// FsmKey keys the per-workload state map. #[repr(C)], 8 bytes.
type FsmKey struct {
	CgroupID uint64
}

// FsmState is the current FSM state for a workload. #[repr(C)], 16 bytes.
type FsmState struct {
	State     uint32
	LastEvent uint32
	UpdatedNs uint64
}

// Transition is one table entry: (state, event) -> (next_state, action). #[repr(C)], 8 bytes.
type Transition struct {
	NextState uint32
	Action    uint32
}

// Binding maps a hook firing to an event, optionally gated by a path predicate.
// Same layout on the wire and in the kernel map. #[repr(C)], 80 bytes.
type Binding struct {
	Hook       uint32
	Event      uint32
	MatchKind  uint32
	PatternLen uint32
	Pattern    [PatternLen]byte
}

// HookBindings is the bindings map value, indexed by hook. #[repr(C)], 328 bytes.
type HookBindings struct {
	Count   uint32
	_       uint32
	Entries [MaxBindingsPerHook]Binding
}

// Dims holds the active policy dimensions; WindowNs = 0 disables expiry. #[repr(C)], 16 bytes.
type Dims struct {
	NumStates uint32
	NumEvents uint32
	WindowNs  uint64
}

// AuditRecord is emitted to the ring buffer on every transition. #[repr(C)], 40 bytes.
type AuditRecord struct {
	CgroupID  uint64
	TsNs      uint64
	Pid       uint32
	Hook      uint32
	Event     uint32
	FromState uint32
	ToState   uint32
	Action    uint32
}
