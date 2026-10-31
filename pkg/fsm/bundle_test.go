package fsm

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func pattern(s string) (p [PatternLen]byte) {
	copy(p[:], s)
	return p
}

// sampleBundle: rule 0 (cgroup, 2 states x 2 events), rule 1 (process, 3 x 1).
func sampleBundle() *Bundle {
	return &Bundle{
		Rules: []Rule{
			{NumStates: 2, NumEvents: 2, TransBase: 0, Scope: ScopeCgroup, TerminalFrom: 1, WindowNs: 30e9},
			{NumStates: 3, NumEvents: 1, TransBase: 4, Scope: ScopeProcess, TerminalFrom: 3, WindowNs: 10e9},
		},
		Transitions: []Transition{
			{1, ActionObserve}, {0, ActionObserve}, {1, ActionObserve}, {1, ActionKill},
			{1, ActionObserve}, {2, ActionDeny}, {2, ActionObserve},
		},
		Bindings: []Binding{
			{Hook: HookOpenat, Rule: 0, Event: 0, PathArg: 1, PathKind: PathPrefix, PathLen: 4,
				ArgIndex: NoArg, ArgOp: ArgAny, Pattern: pattern("/run")},
			{Hook: HookMount, Rule: 0, Event: 1, PathArg: NoArg, PathKind: PathAny,
				ArgIndex: 3, ArgOp: ArgMaskNone, ArgValue: 0x1E0000},
			{Hook: HookOpenat, Rule: 1, Event: 0, PathArg: NoArg, PathKind: PathAny,
				ArgIndex: NoArg, ArgOp: ArgAny},
		},
		Meta: Meta{Rules: []RuleMeta{
			{Name: "a", Scope: "cgroup", States: []string{"s0", "s1"}, Events: []string{"e0", "e1"}},
			{Name: "b", Scope: "process", States: []string{"x", "y", "z"}, Events: []string{"go"}},
		}},
	}
}

const sampleMeta = `{"rules":[{"events":["e0","e1"],"name":"a","scope":"cgroup","states":["s0","s1"]},` +
	`{"events":["go"],"name":"b","scope":"process","states":["x","y","z"]}]}`

func TestMarshalRoundTrip(t *testing.T) {
	data, err := sampleBundle().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := 32 + 2*ruleSize + 7*transitionSize + 3*bindingSize + len(sampleMeta)
	if len(data) != want {
		t.Fatalf("len = %d, want %d", len(data), want)
	}
	if got := string(data[len(data)-len(sampleMeta):]); got != sampleMeta {
		t.Fatalf("metadata = %s, want %s", got, sampleMeta)
	}
	b, err := UnmarshalBundle(data)
	if err != nil {
		t.Fatal(err)
	}
	again, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, data) {
		t.Fatal("round trip is not byte-identical")
	}
	if got := b.At(1, 1, 0); got != (Transition{2, ActionDeny}) {
		t.Errorf("At(1,1,0) = %+v", got)
	}
	if b.Bindings[1].ArgValue != 0x1E0000 || b.Bindings[0].Pattern != pattern("/run") {
		t.Errorf("bindings = %+v", b.Bindings)
	}
	if b.Policy().NumRules != 2 {
		t.Errorf("Policy = %+v", b.Policy())
	}
}

func TestMarshalHeaderBytes(t *testing.T) {
	data, err := sampleBundle().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x54, 0x42, 0x54, 0x53, // magic "STBT" LE
		3, 0, 0, 0, // version
		2, 0, 0, 0, // num_rules
		7, 0, 0, 0, // num_transitions
		3, 0, 0, 0, // num_bindings
		byte(len(sampleMeta)), 0, 0, 0, // meta_len
		0, 0, 0, 0, 0, 0, 0, 0, // reserved
	}
	if !bytes.Equal(data[:32], want) {
		t.Fatalf("header = % x, want % x", data[:32], want)
	}
	rule1 := data[32+ruleSize : 32+2*ruleSize]
	if binary.LittleEndian.Uint32(rule1[8:]) != 4 || binary.LittleEndian.Uint64(rule1[24:]) != 10e9 {
		t.Errorf("rule 1 = % x", rule1)
	}
}

func TestMarshalEmpty(t *testing.T) {
	data, err := (&Bundle{}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data[32:]); got != `{"rules":[]}` {
		t.Fatalf("metadata = %s", got)
	}
	if _, err := UnmarshalBundle(data); err != nil {
		t.Fatal(err)
	}
}

func TestGroupBindings(t *testing.T) {
	b := sampleBundle()
	g, err := b.GroupBindings()
	if err != nil {
		t.Fatal(err)
	}
	if g[HookOpenat].Count != 2 || g[HookMount].Count != 1 || g[HookExecve].Count != 0 {
		t.Fatalf("counts openat=%d mount=%d execve=%d", g[HookOpenat].Count, g[HookMount].Count, g[HookExecve].Count)
	}
	if g[HookOpenat].Entries[0] != b.Bindings[0] || g[HookOpenat].Entries[1] != b.Bindings[2] {
		t.Error("openat bindings out of order")
	}
	if g[HookMount].Entries[0] != b.Bindings[1] {
		t.Error("mount binding mismatch")
	}

	for range MaxBindingsPerHook {
		b.Bindings = append(b.Bindings, b.Bindings[1])
	}
	if _, err := b.GroupBindings(); err == nil {
		t.Error("9 mount bindings accepted")
	}
	b.Bindings = []Binding{{Hook: NumHooks}}
	if _, err := b.GroupBindings(); err == nil {
		t.Error("unknown hook accepted")
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(b *Bundle)
		msg    string
	}{
		{"too many rules", func(b *Bundle) {
			for range MaxRules {
				b.Rules = append(b.Rules, b.Rules[1])
				b.Meta.Rules = append(b.Meta.Rules, b.Meta.Rules[1])
			}
		}, "rules, max"},
		{"too many transitions", func(b *Bundle) {
			b.Transitions = append(b.Transitions, make([]Transition, MaxTransitions)...)
		}, "transitions, max"},
		{"meta rule count", func(b *Bundle) { b.Meta.Rules = b.Meta.Rules[:1] }, "metadata names 1 rules"},
		{"no states", func(b *Bundle) { b.Rules[1].NumStates = 0 }, "no states"},
		{"no events", func(b *Bundle) { b.Rules[0].NumEvents = 0 }, "no states or no events"},
		{"scope", func(b *Bundle) { b.Rules[0].Scope = 2 }, "unknown scope"},
		{"terminal_from", func(b *Bundle) { b.Rules[1].TerminalFrom = 4 }, "terminal_from"},
		{"range end", func(b *Bundle) { b.Rules[1].TransBase = 5 }, "outside the table"},
		{"range overflow", func(b *Bundle) { b.Rules[1].NumStates = 1 << 31; b.Rules[1].NumEvents = 4 }, "outside the table"},
		{"next state", func(b *Bundle) { b.Transitions[6].NextState = 3 }, "invalid cell"},
		{"action", func(b *Bundle) { b.Transitions[0].Action = ActionKill + 1 }, "invalid cell"},
		{"meta states", func(b *Bundle) { b.Meta.Rules[1].States = b.Meta.Rules[1].States[:2] }, "metadata names 2 states"},
		{"meta events", func(b *Bundle) { b.Meta.Rules[0].Events = nil }, "and 0 events"},
		{"meta scope", func(b *Bundle) { b.Meta.Rules[0].Scope = "process" }, "metadata scope"},
		{"hook", func(b *Bundle) { b.Bindings[0].Hook = NumHooks }, "unknown hook"},
		{"rule", func(b *Bundle) { b.Bindings[0].Rule = 2 }, "rule 2 out of range"},
		{"event", func(b *Bundle) { b.Bindings[2].Event = 1 }, "event 1 out of range"},
		{"path kind", func(b *Bundle) { b.Bindings[0].PathKind = 3 }, "unknown path kind"},
		{"path any arg", func(b *Bundle) { b.Bindings[1].PathArg = 1 }, "PATH_ANY"},
		{"path any len", func(b *Bundle) { b.Bindings[1].PathLen = 1 }, "PATH_ANY"},
		{"path arg", func(b *Bundle) { b.Bindings[0].PathArg = MaxSyscallArgs }, "path_arg 6"},
		{"path arg no_arg", func(b *Bundle) { b.Bindings[0].PathArg = NoArg }, "path_arg"},
		{"path len 0", func(b *Bundle) { b.Bindings[0].PathLen = 0 }, "path_len 0"},
		{"path len 64", func(b *Bundle) { b.Bindings[0].PathLen = PatternLen }, "path_len 64"},
		{"sun path len", func(b *Bundle) { b.Bindings[0].PathKind = PathSunPrefix; b.Bindings[0].PathLen = 0 }, "path_len 0"},
		{"arg op", func(b *Bundle) { b.Bindings[1].ArgOp = ArgMaskNone + 1 }, "unknown arg op"},
		{"arg any index", func(b *Bundle) { b.Bindings[0].ArgIndex = 0 }, "ARG_ANY"},
		{"arg index", func(b *Bundle) { b.Bindings[1].ArgIndex = MaxSyscallArgs }, "arg_index 6"},
		{"arg index no_arg", func(b *Bundle) { b.Bindings[1].ArgIndex = NoArg }, "arg_index"},
		{"per hook", func(b *Bundle) {
			for range MaxBindingsPerHook {
				b.Bindings = append(b.Bindings, b.Bindings[1])
			}
		}, "more than 8 bindings"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := sampleBundle()
			c.mutate(b)
			err := b.Validate()
			if err == nil || !strings.Contains(err.Error(), c.msg) {
				t.Fatalf("Validate() = %v, want error containing %q", err, c.msg)
			}
			if _, err := b.Marshal(); err == nil {
				t.Fatal("Marshal accepted an invalid bundle")
			}
		})
	}
}

func TestUnmarshalRejects(t *testing.T) {
	good, err := sampleBundle().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	metaOff := len(good) - len(sampleMeta)
	edit := func(f func(d []byte) []byte) []byte {
		return f(bytes.Clone(good))
	}
	put32 := func(off int, v uint32) []byte {
		return edit(func(d []byte) []byte { binary.LittleEndian.PutUint32(d[off:], v); return d })
	}
	withMeta := func(m string) []byte {
		d := append(bytes.Clone(good[:metaOff]), m...)
		binary.LittleEndian.PutUint32(d[20:], uint32(len(m)))
		return d
	}
	cases := []struct {
		name string
		data []byte
		msg  string
	}{
		{"empty", nil, "shorter than"},
		{"short header", good[:31], "shorter than"},
		{"magic", put32(0, 0x53544255), "bad magic"},
		{"version 2", put32(4, 2), "unsupported bundle version 2"},
		{"reserved", edit(func(d []byte) []byte { d[31] = 1; return d }), "reserved"},
		{"truncated", good[:len(good)-1], "header says"},
		{"trailing byte", append(bytes.Clone(good), 0), "header says"},
		{"huge counts", put32(12, 0xFFFFFFFF), "header says"},
		{"meta_len", put32(20, uint32(len(sampleMeta)+1)), "header says"},
		{"bad json", withMeta(`{"rules":[`), "decode metadata"},
		{"unknown json field", withMeta(strings.Replace(sampleMeta, `"name":"a"`, `"nom":"a"`, 1)), "decode metadata"},
		{"trailing json", withMeta(sampleMeta + `{}`), "trailing data"},
		{"invalid bundle", withMeta(`{"rules":[]}`), "metadata names 0 rules"},
		{"invalid binding", put32(32+2*ruleSize+7*transitionSize, NumHooks), "unknown hook"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := UnmarshalBundle(c.data)
			if err == nil || !strings.Contains(err.Error(), c.msg) {
				t.Fatalf("UnmarshalBundle() = %v, want error containing %q", err, c.msg)
			}
		})
	}
}
