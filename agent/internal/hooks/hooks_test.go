package hooks

import (
	"testing"

	"github.com/CosminMilica/statewall/pkg/fsm"
)

func TestNames(t *testing.T) {
	want := []string{"openat", "setns", "unshare", "mount", "execve", "ptrace"}
	for i, w := range want {
		if got := Name(uint32(i)); got != w {
			t.Errorf("Name(%d) = %q, want %q", i, got, w)
		}
	}
	if got := Name(fsm.NumHooks); got != "6" {
		t.Errorf("Name(NumHooks) = %q, want \"6\"", got)
	}
	if got := Program(fsm.HookExecve); got != "sw_execve" {
		t.Errorf("Program = %q", got)
	}
	if got := Tracepoint(fsm.HookPtrace); got != "sys_enter_ptrace" {
		t.Errorf("Tracepoint = %q", got)
	}
}
