package fsm

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Policy bundle format v3 — see docs/architecture.md (Phase 1.5).
const (
	bundleMagic      uint32 = 0x53544254 // "STBT"
	bundleVersion    uint32 = 3
	bundleHeaderSize        = 32
	ruleSize                = 32
	transitionSize          = 8
	bindingSize             = 104
)

// Bundle is a compiled policy: rules, their transition cells, hook bindings, names.
type Bundle struct {
	Rules       []Rule
	Transitions []Transition // rule r owns [r.TransBase, r.TransBase + r.NumStates*r.NumEvents)
	Bindings    []Binding
	Meta        Meta
}

// Meta carries the names the kernel does not need (rules, states, events).
type Meta struct {
	Rules []RuleMeta `json:"rules"`
}

// RuleMeta names one rule's states and events, in index order.
// Fields are in key order so the JSON matches the compiler's sorted output.
type RuleMeta struct {
	Events []string `json:"events"`
	Name   string   `json:"name"`
	Scope  string   `json:"scope"`
	States []string `json:"states"`
}

var scopeNames = map[uint32]string{ScopeCgroup: "cgroup", ScopeProcess: "process"}

type bundleHeader struct {
	Magic          uint32
	Version        uint32
	NumRules       uint32
	NumTransitions uint32
	NumBindings    uint32
	MetaLen        uint32
	Reserved       uint64
}

// Marshal encodes the bundle into the v3 binary format.
func (b *Bundle) Marshal() ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	meta, err := b.encodeMeta()
	if err != nil {
		return nil, err
	}
	hdr := bundleHeader{
		Magic:          bundleMagic,
		Version:        bundleVersion,
		NumRules:       uint32(len(b.Rules)),
		NumTransitions: uint32(len(b.Transitions)),
		NumBindings:    uint32(len(b.Bindings)),
		MetaLen:        uint32(len(meta)),
	}
	size := bundleHeaderSize + len(b.Rules)*ruleSize + len(b.Transitions)*transitionSize +
		len(b.Bindings)*bindingSize + len(meta)
	out := make([]byte, 0, size)
	for _, v := range []any{hdr, b.Rules, b.Transitions, b.Bindings} {
		if out, err = binary.Append(out, binary.LittleEndian, v); err != nil {
			return nil, fmt.Errorf("fsm: encode bundle: %w", err)
		}
	}
	return append(out, meta...), nil
}

func (b *Bundle) encodeMeta() ([]byte, error) {
	m := b.Meta
	if m.Rules == nil {
		m.Rules = []RuleMeta{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("fsm: encode metadata: %w", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// UnmarshalBundle decodes and validates a v3 bundle.
func UnmarshalBundle(data []byte) (*Bundle, error) {
	if len(data) < bundleHeaderSize {
		return nil, fmt.Errorf("fsm: bundle is %d bytes, shorter than the %d-byte header", len(data), bundleHeaderSize)
	}
	var hdr bundleHeader
	if _, err := binary.Decode(data[:bundleHeaderSize], binary.LittleEndian, &hdr); err != nil {
		return nil, fmt.Errorf("fsm: decode header: %w", err)
	}
	if hdr.Magic != bundleMagic {
		return nil, fmt.Errorf("fsm: bad magic %#x", hdr.Magic)
	}
	if hdr.Version != bundleVersion {
		return nil, fmt.Errorf("fsm: unsupported bundle version %d, want %d", hdr.Version, bundleVersion)
	}
	if hdr.Reserved != 0 {
		return nil, errors.New("fsm: reserved header field is not zero")
	}
	want := uint64(bundleHeaderSize) + uint64(hdr.NumRules)*ruleSize +
		uint64(hdr.NumTransitions)*transitionSize + uint64(hdr.NumBindings)*bindingSize +
		uint64(hdr.MetaLen)
	if uint64(len(data)) != want {
		return nil, fmt.Errorf("fsm: bundle is %d bytes, header says %d", len(data), want)
	}

	b := &Bundle{
		Rules:       make([]Rule, hdr.NumRules),
		Transitions: make([]Transition, hdr.NumTransitions),
		Bindings:    make([]Binding, hdr.NumBindings),
	}
	off := bundleHeaderSize
	for _, v := range []any{b.Rules, b.Transitions, b.Bindings} {
		n, err := binary.Decode(data[off:], binary.LittleEndian, v)
		if err != nil {
			return nil, fmt.Errorf("fsm: decode bundle: %w", err)
		}
		off += n
	}
	dec := json.NewDecoder(bytes.NewReader(data[off:]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b.Meta); err != nil {
		return nil, fmt.Errorf("fsm: decode metadata: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("fsm: trailing data after metadata")
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return b, nil
}

// Validate checks the bundle against the kernel capacity limits.
func (b *Bundle) Validate() error {
	if len(b.Rules) > int(MaxRules) {
		return fmt.Errorf("fsm: %d rules, max is %d", len(b.Rules), MaxRules)
	}
	if len(b.Transitions) > int(MaxTransitions) {
		return fmt.Errorf("fsm: %d transitions, max is %d", len(b.Transitions), MaxTransitions)
	}
	if len(b.Meta.Rules) != len(b.Rules) {
		return fmt.Errorf("fsm: metadata names %d rules, bundle has %d", len(b.Meta.Rules), len(b.Rules))
	}
	for i, r := range b.Rules {
		if err := b.validateRule(i, r); err != nil {
			return err
		}
	}
	var perHook [NumHooks]int
	for i, bd := range b.Bindings {
		if err := b.validateBinding(bd); err != nil {
			return fmt.Errorf("fsm: binding %d: %w", i, err)
		}
		if perHook[bd.Hook]++; perHook[bd.Hook] > MaxBindingsPerHook {
			return fmt.Errorf("fsm: hook %d has more than %d bindings", bd.Hook, MaxBindingsPerHook)
		}
	}
	return nil
}

func (b *Bundle) validateRule(i int, r Rule) error {
	if r.NumStates == 0 || r.NumEvents == 0 {
		return fmt.Errorf("fsm: rule %d has no states or no events", i)
	}
	if _, ok := scopeNames[r.Scope]; !ok {
		return fmt.Errorf("fsm: rule %d has unknown scope %d", i, r.Scope)
	}
	if r.TerminalFrom > r.NumStates {
		return fmt.Errorf("fsm: rule %d terminal_from %d > num_states %d", i, r.TerminalFrom, r.NumStates)
	}
	end := uint64(r.TransBase) + uint64(r.NumStates)*uint64(r.NumEvents)
	if end > uint64(len(b.Transitions)) {
		return fmt.Errorf("fsm: rule %d transitions [%d, %d) outside the table of %d", i, r.TransBase, end, len(b.Transitions))
	}
	for _, t := range b.Transitions[r.TransBase:end] {
		if t.NextState >= r.NumStates || t.Action > ActionKill {
			return fmt.Errorf("fsm: rule %d has an invalid cell %+v", i, t)
		}
	}
	m := b.Meta.Rules[i]
	if len(m.States) != int(r.NumStates) || len(m.Events) != int(r.NumEvents) {
		return fmt.Errorf("fsm: rule %d metadata names %d states and %d events, want %d and %d",
			i, len(m.States), len(m.Events), r.NumStates, r.NumEvents)
	}
	if m.Scope != scopeNames[r.Scope] {
		return fmt.Errorf("fsm: rule %d metadata scope %q, want %q", i, m.Scope, scopeNames[r.Scope])
	}
	return nil
}

func (b *Bundle) validateBinding(bd Binding) error {
	if bd.Hook >= NumHooks {
		return fmt.Errorf("unknown hook %d", bd.Hook)
	}
	if bd.Rule >= uint32(len(b.Rules)) {
		return fmt.Errorf("rule %d out of range", bd.Rule)
	}
	if bd.Event >= b.Rules[bd.Rule].NumEvents {
		return fmt.Errorf("event %d out of range for rule %d", bd.Event, bd.Rule)
	}
	switch bd.PathKind {
	case PathAny:
		if bd.PathArg != NoArg || bd.PathLen != 0 {
			return errors.New("PATH_ANY needs path_arg NO_ARG and path_len 0")
		}
	case PathPrefix, PathSunPrefix:
		if bd.PathArg >= MaxSyscallArgs {
			return fmt.Errorf("path_arg %d out of range", bd.PathArg)
		}
		if bd.PathLen == 0 || bd.PathLen > PatternLen-1 {
			return fmt.Errorf("path_len %d not in 1..%d", bd.PathLen, PatternLen-1)
		}
	default:
		return fmt.Errorf("unknown path kind %d", bd.PathKind)
	}
	switch {
	case bd.ArgOp > ArgMaskNone:
		return fmt.Errorf("unknown arg op %d", bd.ArgOp)
	case bd.ArgOp == ArgAny && bd.ArgIndex != NoArg:
		return errors.New("ARG_ANY needs arg_index NO_ARG")
	case bd.ArgOp != ArgAny && bd.ArgIndex >= MaxSyscallArgs:
		return fmt.Errorf("arg_index %d out of range", bd.ArgIndex)
	}
	return nil
}

// GroupBindings groups bindings by hook into SW_BINDINGS values.
func (b *Bundle) GroupBindings() ([NumHooks]HookBindings, error) {
	var out [NumHooks]HookBindings
	for _, bd := range b.Bindings {
		if bd.Hook >= NumHooks {
			return out, fmt.Errorf("fsm: unknown hook %d", bd.Hook)
		}
		hb := &out[bd.Hook]
		if hb.Count >= MaxBindingsPerHook {
			return out, fmt.Errorf("fsm: hook %d has more than %d bindings", bd.Hook, MaxBindingsPerHook)
		}
		hb.Entries[hb.Count] = bd
		hb.Count++
	}
	return out, nil
}

// Policy returns the SW_POLICY value that activates this bundle.
func (b *Bundle) Policy() Policy { return Policy{NumRules: uint32(len(b.Rules))} }

// At returns rule's transition for (state, event).
func (b *Bundle) At(rule, state, event uint32) Transition {
	r := b.Rules[rule]
	return b.Transitions[r.TransBase+state*r.NumEvents+event]
}
