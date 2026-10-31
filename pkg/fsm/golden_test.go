package fsm

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Cross-language check: decode the policy the Python compiler emitted (make golden).
func TestGoldenPolicy(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "policy.bin"))
	if err != nil {
		t.Fatal(err)
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
		t.Fatal("Go re-encoding differs from the Python golden")
	}

	rules := []struct {
		name   string
		rule   Rule
		states []string
		events []string
	}{
		{"container-escape",
			Rule{NumStates: 5, NumEvents: 4, TransBase: 0, Scope: ScopeCgroup, TerminalFrom: 4, WindowNs: 30e9},
			[]string{"normal", "suspicious", "escalating", "breakout_imminent", "compromised"},
			[]string{"runtime_socket_open", "namespace_manipulation", "host_mount", "critical_execve"}},
		{"fileless-exec",
			Rule{NumStates: 3, NumEvents: 2, TransBase: 20, Scope: ScopeProcess, TerminalFrom: 2, WindowNs: 30e9},
			[]string{"normal", "memfd_created", "compromised"},
			[]string{"memfd", "memfd_exec"}},
		{"reverse-shell",
			Rule{NumStates: 4, NumEvents: 3, TransBase: 26, Scope: ScopeProcess, TerminalFrom: 3, WindowNs: 10e9},
			[]string{"normal", "connected", "stdio_redirected", "compromised"},
			[]string{"outbound_connect", "stdio_redirect", "shell_exec"}},
	}
	if len(b.Rules) != len(rules) || len(b.Transitions) != 38 || len(b.Bindings) != 24 {
		t.Fatalf("rules=%d transitions=%d bindings=%d", len(b.Rules), len(b.Transitions), len(b.Bindings))
	}
	for i, want := range rules {
		m := b.Meta.Rules[i]
		if m.Name != want.name || b.Rules[i] != want.rule {
			t.Errorf("rule %d = %s %+v, want %s %+v", i, m.Name, b.Rules[i], want.name, want.rule)
		}
		if !reflect.DeepEqual(m.States, want.states) || !reflect.DeepEqual(m.Events, want.events) {
			t.Errorf("rule %d names = %v %v", i, m.States, m.Events)
		}
	}

	cells := []struct {
		rule, state, event uint32
		want               Transition
	}{
		{0, 0, 0, Transition{1, ActionObserve}},
		{0, 1, 1, Transition{2, ActionThrottle}},
		{0, 2, 2, Transition{3, ActionDeny}},
		{0, 3, 3, Transition{4, ActionKill}},
		{0, 4, 0, Transition{4, ActionObserve}},
		{1, 0, 0, Transition{1, ActionObserve}},
		{1, 1, 1, Transition{2, ActionKill}},
		{2, 0, 0, Transition{1, ActionObserve}},
		{2, 1, 1, Transition{2, ActionObserve}},
		{2, 2, 2, Transition{3, ActionKill}},
		{2, 0, 2, Transition{0, ActionObserve}},
	}
	for _, c := range cells {
		if got := b.At(c.rule, c.state, c.event); got != c.want {
			t.Errorf("At(%d,%d,%d) = %+v, want %+v", c.rule, c.state, c.event, got, c.want)
		}
	}

	g, err := b.GroupBindings()
	if err != nil {
		t.Fatal(err)
	}
	counts := map[uint32]uint32{
		HookOpenat: 3, HookSetns: 1, HookUnshare: 1, HookMount: 1, HookExecve: 7, HookConnect: 4,
		HookDup2: 1, HookDup3: 1, HookMemfdCreate: 1, HookExecveat: 2, HookFsmount: 1, HookMoveMount: 1,
	}
	for h := range NumHooks {
		if g[h].Count != counts[h] {
			t.Errorf("hook %d has %d bindings, want %d", h, g[h].Count, counts[h])
		}
	}

	sockets := []string{"/run/containerd/containerd.sock", "/var/run/docker.sock", "/run/docker.sock"}
	for i, s := range sockets {
		e := g[HookConnect].Entries[i]
		want := Binding{Hook: HookConnect, Rule: 0, Event: 0, PathArg: 1, PathKind: PathSunPrefix,
			PathLen: uint32(len(s)), ArgIndex: NoArg, ArgOp: ArgAny, Pattern: pattern(s)}
		if e != want {
			t.Errorf("connect binding %d = %+v", i, e)
		}
	}
	if e := g[HookConnect].Entries[3]; e.Rule != 2 || e.PathKind != PathAny || e.ArgOp != ArgAny {
		t.Errorf("reverse-shell connect binding = %+v", e)
	}

	mount := g[HookMount].Entries[0]
	if mount.Rule != 0 || mount.Event != 2 || mount.PathKind != PathAny ||
		mount.ArgIndex != 3 || mount.ArgOp != ArgMaskNone || mount.ArgValue != 0x1E0000 {
		t.Errorf("mount binding = %+v", mount)
	}
	for _, e := range g[HookDup2].Entries[:1] {
		if e.Rule != 2 || e.ArgIndex != 1 || e.ArgOp != ArgLe || e.ArgValue != 2 {
			t.Errorf("dup2 binding = %+v", e)
		}
	}
	if e := g[HookExecveat].Entries[1]; e.Rule != 1 || e.ArgIndex != 4 || e.ArgOp != ArgMaskAny || e.ArgValue != 0x1000 {
		t.Errorf("fileless execveat binding = %+v", e)
	}
	var shells []string
	for _, e := range g[HookExecve].Entries[3:7] {
		if e.Rule != 2 || e.PathArg != 0 || e.PathKind != PathPrefix {
			t.Errorf("shell binding = %+v", e)
		}
		shells = append(shells, string(e.Pattern[:e.PathLen]))
	}
	if got := strings.Join(shells, " "); got != "/bin/sh /bin/bash /usr/bin/sh /usr/bin/bash" {
		t.Errorf("shell prefixes = %s", got)
	}
}
