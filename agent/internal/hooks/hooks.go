// Package hooks names the FSM hook points; index = fsm.Hook* constant.
package hooks

import (
	"strconv"

	"github.com/CosminMilica/statewall/pkg/fsm"
)

// Names maps each fsm.Hook* constant to its syscall name.
var Names = [fsm.NumHooks]string{
	fsm.HookOpenat:  "openat",
	fsm.HookSetns:   "setns",
	fsm.HookUnshare: "unshare",
	fsm.HookMount:   "mount",
	fsm.HookExecve:  "execve",
	fsm.HookPtrace:  "ptrace",
}

// Name returns the hook name, or the decimal value for unknown hooks.
func Name(h uint32) string {
	if h < fsm.NumHooks {
		return Names[h]
	}
	return strconv.FormatUint(uint64(h), 10)
}

// Program is the BPF program name for a hook.
func Program(h uint32) string { return "sw_" + Names[h] }

// Tracepoint is the syscalls tracepoint name for a hook.
func Tracepoint(h uint32) string { return "sys_enter_" + Names[h] }
