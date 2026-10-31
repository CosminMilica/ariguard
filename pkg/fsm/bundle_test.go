package fsm

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func pathBinding(hook, event uint32, prefix string) Binding {
	b := Binding{Hook: hook, Event: event, MatchKind: MatchPathPrefix, PatternLen: uint32(len(prefix))}
	copy(b.Pattern[:], prefix)
	return b
}

func sampleBundle() *Bundle {
	b := &Bundle{Dims: Dims{NumStates: 5, NumEvents: 3, WindowNs: 7}}
	b.Transitions = make([]Transition, 15)
	for i := range b.Transitions {
		b.Transitions[i] = Transition{NextState: uint32(i % 5), Action: uint32(i % 4)}
	}
	b.Bindings = []Binding{
		pathBinding(HookOpenat, 0, "/run/docker.sock"),
		{Hook: HookSetns, Event: 1, MatchKind: MatchAny},
		{Hook: HookExecve, Event: 2, MatchKind: MatchAny},
	}
	return b
}

func TestBundleRoundTrip(t *testing.T) {
	orig := sampleBundle()
	data, err := orig.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := bundleHeaderSize + 15*transitionSize + 3*bindingSize; len(data) != want {
		t.Fatalf("encoded size = %d, want %d", len(data), want)
	}
	got, err := UnmarshalBundle(data)
	if err != nil {
		t.Fatalf("UnmarshalBundle: %v", err)
	}
	if got.Dims != orig.Dims {
		t.Fatalf("dims = %+v, want %+v", got.Dims, orig.Dims)
	}
	data2, err := got.Marshal()
	if err != nil {
		t.Fatalf("Marshal (2): %v", err)
	}
	if !bytes.Equal(data, data2) {
		t.Fatal("re-marshal not byte-identical")
	}
}

func TestBundleHeaderBytes(t *testing.T) {
	b := &Bundle{
		Dims:        Dims{NumStates: 1, NumEvents: 1, WindowNs: 0x0102030405060708},
		Transitions: []Transition{{NextState: 0, Action: 3}},
		Bindings:    []Binding{{Hook: HookMount, Event: 0, MatchKind: MatchAny}},
	}
	data, err := b.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := []byte{
		0x54, 0x42, 0x54, 0x53, // magic "STBT" LE
		0x02, 0x00, 0x00, 0x00, // version 2
		0x01, 0x00, 0x00, 0x00, // num_states 1
		0x01, 0x00, 0x00, 0x00, // num_events 1
		0x01, 0x00, 0x00, 0x00, // num_bindings 1
		0x00, 0x00, 0x00, 0x00, // reserved
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // window_ns
		0x00, 0x00, 0x00, 0x00, // next_state 0
		0x03, 0x00, 0x00, 0x00, // action 3
		0x03, 0x00, 0x00, 0x00, // hook mount
		0x00, 0x00, 0x00, 0x00, // event 0
		0x00, 0x00, 0x00, 0x00, // match_kind any
		0x00, 0x00, 0x00, 0x00, // pattern_len 0
	}
	want = append(want, make([]byte, PatternLen)...)
	if !bytes.Equal(data, want) {
		t.Fatalf("bytes = % x, want % x", data, want)
	}
}

func TestGroupBindings(t *testing.T) {
	groups, err := sampleBundle().GroupBindings()
	if err != nil {
		t.Fatalf("GroupBindings: %v", err)
	}
	counts := [NumHooks]uint32{HookOpenat: 1, HookSetns: 1, HookExecve: 1}
	for h := range groups {
		if groups[h].Count != counts[h] {
			t.Errorf("hook %d count = %d, want %d", h, groups[h].Count, counts[h])
		}
	}
	if groups[HookSetns].Entries[0].Event != 1 {
		t.Errorf("setns entry event = %d, want 1", groups[HookSetns].Entries[0].Event)
	}
}

func TestUnmarshalBundleRejects(t *testing.T) {
	valid, err := sampleBundle().Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	mutate := func(f func([]byte) []byte) []byte {
		return f(append([]byte(nil), valid...))
	}
	bindingsOff := bundleHeaderSize + 15*transitionSize

	cases := []struct {
		name string
		data []byte
	}{
		{"short data", []byte{1, 2, 3}},
		{"bad magic", mutate(func(d []byte) []byte { d[0] = 0; return d })},
		{"version 1", mutate(func(d []byte) []byte { binary.LittleEndian.PutUint32(d[4:], 1); return d })},
		{"reserved set", mutate(func(d []byte) []byte { d[20] = 1; return d })},
		{"truncated body", valid[:len(valid)-1]},
		{"trailing bytes", append(append([]byte(nil), valid...), 0)},
		{"oversize", func() []byte {
			d := make([]byte, bundleHeaderSize+1025*transitionSize)
			binary.LittleEndian.PutUint32(d[0:], bundleMagic)
			binary.LittleEndian.PutUint32(d[4:], bundleVersion)
			binary.LittleEndian.PutUint32(d[8:], 1025)
			binary.LittleEndian.PutUint32(d[12:], 1)
			return d
		}()},
		{"zero dims", mutate(func(d []byte) []byte {
			binary.LittleEndian.PutUint32(d[8:], 0)
			return d[:bundleHeaderSize+3*bindingSize]
		})},
		{"next_state out of range", mutate(func(d []byte) []byte { d[bundleHeaderSize] = 5; return d })},
		{"bad action", mutate(func(d []byte) []byte { d[bundleHeaderSize+4] = 4; return d })},
		{"bad hook", mutate(func(d []byte) []byte { d[bindingsOff] = byte(NumHooks); return d })},
		{"bad event", mutate(func(d []byte) []byte { d[bindingsOff+4] = 3; return d })},
		{"bad match kind", mutate(func(d []byte) []byte { d[bindingsOff+8] = 2; return d })},
		{"pattern too long", mutate(func(d []byte) []byte { d[bindingsOff+12] = PatternLen + 1; return d })},
		{"empty prefix", mutate(func(d []byte) []byte { d[bindingsOff+12] = 0; return d })},
	}
	for _, c := range cases {
		if _, err := UnmarshalBundle(c.data); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}

func TestValidateBindingsPerHook(t *testing.T) {
	b := sampleBundle()
	for i := 0; i < MaxBindingsPerHook; i++ {
		b.Bindings = append(b.Bindings, Binding{Hook: HookSetns, Event: 1, MatchKind: MatchAny})
	}
	if err := b.Validate(); err == nil {
		t.Fatal("expected error for too many bindings on one hook")
	}
	if _, err := b.Marshal(); err == nil {
		t.Fatal("Marshal accepted an invalid bundle")
	}
}
