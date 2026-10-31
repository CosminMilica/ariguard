package hooks

import (
	"testing"

	"github.com/CosminMilica/ariguard/pkg/fsm"
)

func TestNames(t *testing.T) {
	want := []string{
		"openat", "setns", "unshare", "mount", "execve", "ptrace", "connect", "dup2",
		"dup3", "memfd_create", "execveat", "fsmount", "move_mount", "init_module", "finit_module", "bpf",
	}
	if len(want) != int(fsm.NumHooks) {
		t.Fatalf("%d names, want %d", len(want), fsm.NumHooks)
	}
	for i, w := range want {
		if got := Name(uint32(i)); got != w {
			t.Errorf("Name(%d) = %q, want %q", i, got, w)
		}
	}
	if got := Name(fsm.NumHooks); got != "16" {
		t.Errorf("Name(NumHooks) = %q, want \"16\"", got)
	}
	if got := Program(fsm.HookMemfdCreate); got != "sw_memfd_create" {
		t.Errorf("Program = %q", got)
	}
	if got := Tracepoint(fsm.HookMoveMount); got != "sys_enter_move_mount" {
		t.Errorf("Tracepoint = %q", got)
	}
}
