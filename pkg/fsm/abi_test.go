package fsm

import (
	"bytes"
	"testing"
	"unsafe"
)

// Guards against ABI drift vs bpf/statewall-common #[repr(C)] layouts.
func TestStructSizes(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"FsmKey", unsafe.Sizeof(FsmKey{}), 8},
		{"FsmState", unsafe.Sizeof(FsmState{}), 16},
		{"Transition", unsafe.Sizeof(Transition{}), 8},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("sizeof(%s) = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestFieldOffsets(t *testing.T) {
	var s FsmState
	if off := unsafe.Offsetof(s.State); off != 0 {
		t.Errorf("FsmState.State offset = %d, want 0", off)
	}
	if off := unsafe.Offsetof(s.LastEvent); off != 4 {
		t.Errorf("FsmState.LastEvent offset = %d, want 4", off)
	}
	if off := unsafe.Offsetof(s.UpdatedNs); off != 8 {
		t.Errorf("FsmState.UpdatedNs offset = %d, want 8", off)
	}

	var tr Transition
	if off := unsafe.Offsetof(tr.Action); off != 4 {
		t.Errorf("Transition.Action offset = %d, want 4", off)
	}
}

func TestTableRoundTrip(t *testing.T) {
	orig := &Table{
		NumStates: 5,
		NumEvents: 3,
	}
	orig.Transitions = make([]Transition, orig.NumStates*orig.NumEvents)
	for i := range orig.Transitions {
		orig.Transitions[i] = Transition{
			NextState: uint32(i % 5),
			Action:    uint32(i % 4),
		}
	}

	data, err := orig.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if len(data) != tableHeaderSize+15*entrySize {
		t.Fatalf("encoded size = %d, want %d", len(data), tableHeaderSize+15*entrySize)
	}

	got, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.NumStates != orig.NumStates || got.NumEvents != orig.NumEvents {
		t.Fatalf("dims = %dx%d, want %dx%d", got.NumStates, got.NumEvents, orig.NumStates, orig.NumEvents)
	}
	for i := range orig.Transitions {
		if got.Transitions[i] != orig.Transitions[i] {
			t.Fatalf("entry %d = %+v, want %+v", i, got.Transitions[i], orig.Transitions[i])
		}
	}

	// Re-marshal must be byte-identical.
	data2, err := got.Marshal()
	if err != nil {
		t.Fatalf("Marshal (2): %v", err)
	}
	if !bytes.Equal(data, data2) {
		t.Fatal("re-marshal not byte-identical")
	}
}

func TestTableHeaderBytes(t *testing.T) {
	tbl := &Table{NumStates: 1, NumEvents: 1, Transitions: []Transition{{NextState: 2, Action: 3}}}
	data, err := tbl.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := []byte{
		0x54, 0x42, 0x54, 0x53, // magic "STBT" LE
		0x01, 0x00, 0x00, 0x00, // version 1
		0x01, 0x00, 0x00, 0x00, // num_states 1
		0x01, 0x00, 0x00, 0x00, // num_events 1
		0x02, 0x00, 0x00, 0x00, // next_state 2
		0x03, 0x00, 0x00, 0x00, // action 3
	}
	if !bytes.Equal(data, want) {
		t.Fatalf("bytes = % x, want % x", data, want)
	}
}

func TestUnmarshalRejects(t *testing.T) {
	if _, err := Unmarshal([]byte{1, 2, 3}); err == nil {
		t.Error("expected error for short data")
	}
	bad := make([]byte, tableHeaderSize)
	// zero magic
	if _, err := Unmarshal(bad); err == nil {
		t.Error("expected error for bad magic")
	}
}
