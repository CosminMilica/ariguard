package fsm

import (
	"testing"
	"unsafe"
)

// Guards against ABI drift vs bpf/ariguard-common #[repr(C)] layouts.
func TestStructSizes(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"FsmKey", unsafe.Sizeof(FsmKey{}), 16},
		{"FsmState", unsafe.Sizeof(FsmState{}), 16},
		{"Transition", unsafe.Sizeof(Transition{}), 8},
		{"Binding", unsafe.Sizeof(Binding{}), 104},
		{"HookBindings", unsafe.Sizeof(HookBindings{}), 840},
		{"Rule", unsafe.Sizeof(Rule{}), 32},
		{"Policy", unsafe.Sizeof(Policy{}), 8},
		{"AuditRecord", unsafe.Sizeof(AuditRecord{}), 64},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("sizeof(%s) = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestFieldOffsets(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"FsmKey.Rule", unsafe.Offsetof(FsmKey{}.Rule), 8},
		{"FsmState.UpdatedNs", unsafe.Offsetof(FsmState{}.UpdatedNs), 8},
		{"Transition.Action", unsafe.Offsetof(Transition{}.Action), 4},
		{"Binding.PathArg", unsafe.Offsetof(Binding{}.PathArg), 12},
		{"Binding.ArgOp", unsafe.Offsetof(Binding{}.ArgOp), 28},
		{"Binding.ArgValue", unsafe.Offsetof(Binding{}.ArgValue), 32},
		{"Binding.Pattern", unsafe.Offsetof(Binding{}.Pattern), 40},
		{"HookBindings.Entries", unsafe.Offsetof(HookBindings{}.Entries), 8},
		{"Rule.TerminalFrom", unsafe.Offsetof(Rule{}.TerminalFrom), 16},
		{"Rule.WindowNs", unsafe.Offsetof(Rule{}.WindowNs), 24},
		{"AuditRecord.Pid", unsafe.Offsetof(AuditRecord{}.Pid), 16},
		{"AuditRecord.Rule", unsafe.Offsetof(AuditRecord{}.Rule), 24},
		{"AuditRecord.Action", unsafe.Offsetof(AuditRecord{}.Action), 40},
		{"AuditRecord.Comm", unsafe.Offsetof(AuditRecord{}.Comm), 48},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("offsetof(%s) = %d, want %d", c.name, c.got, c.want)
		}
	}
}
