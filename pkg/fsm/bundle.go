package fsm

import (
	"encoding/binary"
	"fmt"
)

// Policy bundle format v2 — see docs/architecture.md.
const (
	bundleMagic      uint32 = 0x53544254 // "STBT"
	bundleVersion    uint32 = 2
	bundleHeaderSize        = 32
	bindingSize             = 80
	transitionSize          = 8
)

// Bundle is a compiled policy: dimensions, dense transition table, hook bindings.
type Bundle struct {
	Dims        Dims
	Transitions []Transition // len == NumStates*NumEvents, index = state*NumEvents + event
	Bindings    []Binding
}

// At returns the transition for (state, event).
func (b *Bundle) At(state, event uint32) Transition {
	return b.Transitions[state*b.Dims.NumEvents+event]
}

// Marshal encodes the bundle into the v2 binary format.
func (b *Bundle) Marshal() ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, bundleHeaderSize+len(b.Transitions)*transitionSize+len(b.Bindings)*bindingSize)
	le := binary.LittleEndian
	le.PutUint32(buf[0:], bundleMagic)
	le.PutUint32(buf[4:], bundleVersion)
	le.PutUint32(buf[8:], b.Dims.NumStates)
	le.PutUint32(buf[12:], b.Dims.NumEvents)
	le.PutUint32(buf[16:], uint32(len(b.Bindings)))
	le.PutUint64(buf[24:], b.Dims.WindowNs)
	off := bundleHeaderSize
	for _, tr := range b.Transitions {
		le.PutUint32(buf[off:], tr.NextState)
		le.PutUint32(buf[off+4:], tr.Action)
		off += transitionSize
	}
	for _, bd := range b.Bindings {
		le.PutUint32(buf[off:], bd.Hook)
		le.PutUint32(buf[off+4:], bd.Event)
		le.PutUint32(buf[off+8:], bd.MatchKind)
		le.PutUint32(buf[off+12:], bd.PatternLen)
		copy(buf[off+16:off+bindingSize], bd.Pattern[:])
		off += bindingSize
	}
	return buf, nil
}

// UnmarshalBundle decodes and validates a v2 bundle.
func UnmarshalBundle(data []byte) (*Bundle, error) {
	if len(data) < bundleHeaderSize {
		return nil, fmt.Errorf("fsm: data too short for header: %d bytes", len(data))
	}
	le := binary.LittleEndian
	if magic := le.Uint32(data[0:]); magic != bundleMagic {
		return nil, fmt.Errorf("fsm: bad magic 0x%08x", magic)
	}
	if version := le.Uint32(data[4:]); version != bundleVersion {
		return nil, fmt.Errorf("fsm: unsupported version %d", version)
	}
	if reserved := le.Uint32(data[20:]); reserved != 0 {
		return nil, fmt.Errorf("fsm: reserved header field = %d, want 0", reserved)
	}
	b := &Bundle{Dims: Dims{
		NumStates: le.Uint32(data[8:]),
		NumEvents: le.Uint32(data[12:]),
		WindowNs:  le.Uint64(data[24:]),
	}}
	numTransitions := uint64(b.Dims.NumStates) * uint64(b.Dims.NumEvents)
	numBindings := uint64(le.Uint32(data[16:]))
	want := numTransitions*transitionSize + numBindings*bindingSize
	if got := uint64(len(data) - bundleHeaderSize); got != want {
		return nil, fmt.Errorf("fsm: body size %d != expected %d", got, want)
	}

	b.Transitions = make([]Transition, numTransitions)
	off := bundleHeaderSize
	for i := range b.Transitions {
		b.Transitions[i] = Transition{
			NextState: le.Uint32(data[off:]),
			Action:    le.Uint32(data[off+4:]),
		}
		off += transitionSize
	}
	b.Bindings = make([]Binding, numBindings)
	for i := range b.Bindings {
		bd := &b.Bindings[i]
		bd.Hook = le.Uint32(data[off:])
		bd.Event = le.Uint32(data[off+4:])
		bd.MatchKind = le.Uint32(data[off+8:])
		bd.PatternLen = le.Uint32(data[off+12:])
		copy(bd.Pattern[:], data[off+16:off+bindingSize])
		off += bindingSize
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return b, nil
}

// Validate checks the bundle against the kernel capacity limits.
func (b *Bundle) Validate() error {
	d := b.Dims
	if d.NumStates == 0 || d.NumEvents == 0 {
		return fmt.Errorf("fsm: empty dimensions %dx%d", d.NumStates, d.NumEvents)
	}
	total := uint64(d.NumStates) * uint64(d.NumEvents)
	if total > uint64(MaxTransitions) {
		return fmt.Errorf("fsm: %d transitions exceed max %d", total, MaxTransitions)
	}
	if uint64(len(b.Transitions)) != total {
		return fmt.Errorf("fsm: transition count %d != num_states*num_events %d", len(b.Transitions), total)
	}
	for i, tr := range b.Transitions {
		if tr.NextState >= d.NumStates {
			return fmt.Errorf("fsm: transition %d: next_state %d out of range", i, tr.NextState)
		}
		if tr.Action > ActionKill {
			return fmt.Errorf("fsm: transition %d: unknown action %d", i, tr.Action)
		}
	}
	var perHook [NumHooks]int
	for i, bd := range b.Bindings {
		if bd.Hook >= NumHooks {
			return fmt.Errorf("fsm: binding %d: unknown hook %d", i, bd.Hook)
		}
		if bd.Event >= d.NumEvents {
			return fmt.Errorf("fsm: binding %d: event %d out of range", i, bd.Event)
		}
		switch bd.MatchKind {
		case MatchAny:
		case MatchPathPrefix:
			if bd.PatternLen == 0 {
				return fmt.Errorf("fsm: binding %d: empty path prefix", i)
			}
		default:
			return fmt.Errorf("fsm: binding %d: unknown match kind %d", i, bd.MatchKind)
		}
		if bd.PatternLen > PatternLen {
			return fmt.Errorf("fsm: binding %d: pattern_len %d exceeds %d", i, bd.PatternLen, PatternLen)
		}
		perHook[bd.Hook]++
		if perHook[bd.Hook] > MaxBindingsPerHook {
			return fmt.Errorf("fsm: hook %d has more than %d bindings", bd.Hook, MaxBindingsPerHook)
		}
	}
	return nil
}

// GroupBindings groups bindings by hook into SW_BINDINGS map values.
func (b *Bundle) GroupBindings() ([NumHooks]HookBindings, error) {
	var out [NumHooks]HookBindings
	if err := b.Validate(); err != nil {
		return out, err
	}
	for _, bd := range b.Bindings {
		hb := &out[bd.Hook]
		hb.Entries[hb.Count] = bd
		hb.Count++
	}
	return out, nil
}
