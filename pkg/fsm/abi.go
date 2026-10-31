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
