package fsm

import (
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
		{"Binding", unsafe.Sizeof(Binding{}), 80},
		{"HookBindings", unsafe.Sizeof(HookBindings{}), 328},
		{"Dims", unsafe.Sizeof(Dims{}), 16},
		{"AuditRecord", unsafe.Sizeof(AuditRecord{}), 40},
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

	var b Binding
	if off := unsafe.Offsetof(b.Pattern); off != 16 {
		t.Errorf("Binding.Pattern offset = %d, want 16", off)
	}

	var hb HookBindings
	if off := unsafe.Offsetof(hb.Entries); off != 8 {
		t.Errorf("HookBindings.Entries offset = %d, want 8", off)
	}

	var d Dims
	if off := unsafe.Offsetof(d.WindowNs); off != 8 {
		t.Errorf("Dims.WindowNs offset = %d, want 8", off)
	}

	var a AuditRecord
	if off := unsafe.Offsetof(a.Pid); off != 16 {
		t.Errorf("AuditRecord.Pid offset = %d, want 16", off)
	}
	if off := unsafe.Offsetof(a.Action); off != 36 {
		t.Errorf("AuditRecord.Action offset = %d, want 36", off)
	}
}
