package sink

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/CosminMilica/ariguard/agent/internal/audit"
	"github.com/CosminMilica/ariguard/pkg/fsm"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type recorder struct {
	mu     sync.Mutex
	bodies map[string][][]byte
	status int
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.bodies == nil {
		r.bodies = map[string][][]byte{}
	}
	r.bodies[req.URL.Path] = append(r.bodies[req.URL.Path], b)
	if r.status != 0 {
		w.WriteHeader(r.status)
	}
}

func TestRegisterPayload(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	s := New(srv.URL+"/", Registration{Node: "n1", Kernel: "6.8", Enforce: true, HooksAttached: 15, HooksTotal: 16, AuditRingBytes: 4096, MetricsAddr: "10.0.0.1:9102"}, quiet)
	s.SetBundle([]Rule{{Name: "r", Scope: "cgroup", NumStates: 5, WindowNs: 9, TerminalAction: "kill"}})
	s.Register(context.Background())
	var got map[string]any
	if err := json.Unmarshal(rec.bodies["/api/v1/register"][0], &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"node", "kernel", "enforce", "hooks_attached", "hooks_total", "audit_ring_bytes", "metrics_addr", "bundle", "ts_ns"} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing %q in %v", k, got)
		}
	}
	rule := got["bundle"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if rule["terminal_action"] != "kill" || rule["num_states"] != float64(5) || rule["scope"] != "cgroup" {
		t.Errorf("rule %v", rule)
	}
}

func TestQuarantine(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	s := New(srv.URL, Registration{Node: "n1"}, quiet)
	s.Quarantine(context.Background(), "ariguard-eval", "attacker", "reverse-shell", "on")
	bodies := rec.bodies["/api/v1/quarantine"]
	if len(bodies) != 1 {
		t.Fatalf("got %d quarantine posts, want 1", len(bodies))
	}
	var got map[string]any
	if err := json.Unmarshal(bodies[0], &got); err != nil {
		t.Fatal(err)
	}
	if got["node"] != "n1" || got["namespace"] != "ariguard-eval" || got["pod"] != "attacker" ||
		got["rule"] != "reverse-shell" || got["mode"] != "on" {
		t.Errorf("quarantine body = %v", got)
	}
	if _, ok := got["ts_ns"]; !ok {
		t.Error("missing ts_ns")
	}
	var nilS *Sink
	nilS.Quarantine(context.Background(), "x", "y", "z", "on") // nil sink must be a no-op
}

func TestAuditBatching(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	s := New(srv.URL, Registration{Node: "n1"}, quiet)
	for i := 0; i < 70; i++ {
		_, _ = s.Write([]byte(`{"ts_ns":1,"pod":"p","comm":"sh"}` + "\n"))
	}
	_, _ = s.Write([]byte("garbage\n"))
	s.Flush(context.Background())
	bodies := rec.bodies["/api/v1/audit"]
	if len(bodies) != 2 {
		t.Fatalf("posts = %d, want 2", len(bodies))
	}
	var first []map[string]any
	if err := json.Unmarshal(bodies[0], &first); err != nil {
		t.Fatal(err)
	}
	if len(first) != BatchSize || first[0]["node"] != "n1" || first[0]["pod"] != "p" || first[0]["comm"] != "sh" {
		t.Errorf("first batch %d %v", len(first), first[0])
	}
}

func TestFailureRequeues(t *testing.T) {
	rec := &recorder{status: 500}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	s := New(srv.URL, Registration{Node: "n"}, quiet)
	s.Emit(audit.Event{Pod: "p"})
	s.Flush(context.Background())
	if len(s.buf) != 1 {
		t.Fatalf("buffer = %d, want 1 after failed post", len(s.buf))
	}
	rec.mu.Lock()
	rec.status = 0
	rec.mu.Unlock()
	s.Flush(context.Background())
	if len(s.buf) != 0 {
		t.Fatalf("buffer = %d, want 0", len(s.buf))
	}
}

func TestNilSinkAndUnreachable(t *testing.T) {
	var s *Sink
	s.Emit(audit.Event{})
	s.Register(context.Background())
	_, _ = s.Write([]byte("x"))
	u := New("http://127.0.0.1:1", Registration{}, quiet)
	u.Emit(audit.Event{})
	u.Flush(context.Background())
	u.Register(context.Background())
}

func TestRulesFromBundle(t *testing.T) {
	var etc [fsm.PatternLen]byte
	copy(etc[:], "/etc/")
	b := fsm.Bundle{
		Rules: []fsm.Rule{{NumStates: 2, NumEvents: 2, TransBase: 0, Scope: fsm.ScopeProcess, TerminalFrom: 1, WindowNs: 7}},
		Transitions: []fsm.Transition{
			{NextState: 0, Action: fsm.ActionObserve}, // s0,e0: identity observe, omitted
			{NextState: 1, Action: fsm.ActionDeny},    // s0,e1: deny -> tripped
			{NextState: 1, Action: fsm.ActionObserve}, // s1,e0: identity observe, omitted
			{NextState: 1, Action: fsm.ActionKill},    // s1,e1: kill, stays tripped
		},
		Bindings: []fsm.Binding{
			// event 1 ("exec"): a ptrace arg predicate and an openat path prefix.
			{Hook: fsm.HookPtrace, Rule: 0, Event: 1, PathArg: fsm.NoArg, PathKind: fsm.PathAny, ArgIndex: 0, ArgOp: fsm.ArgEq, ArgValue: 16},
			{Hook: fsm.HookOpenat, Rule: 0, Event: 1, PathArg: 0, PathKind: fsm.PathPrefix, PathLen: 5, ArgIndex: fsm.NoArg, ArgOp: fsm.ArgAny, Pattern: etc},
		},
		Meta: fsm.Meta{Rules: []fsm.RuleMeta{{Name: "escape", States: []string{"ok", "tripped"}, Events: []string{"open", "exec"}}}},
	}
	got := RulesFromBundle(b)[0]
	exec := []string{"ptrace arg0 == 16", "openat path^=/etc/"}
	want := Rule{
		Name:           "escape",
		Scope:          "process",
		NumStates:      2,
		WindowNs:       7,
		TerminalAction: "kill",
		States:         []string{"ok", "tripped"},
		Events:         []string{"open", "exec"},
		TerminalFrom:   1,
		Transitions: []RuleTransition{
			{From: "ok", Event: "exec", To: "tripped", Action: "deny", Syscalls: exec},
			{From: "tripped", Event: "exec", To: "tripped", Action: "kill", Syscalls: exec},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v want %+v", got, want)
	}
}

func TestBindingPredicate(t *testing.T) {
	var sun [fsm.PatternLen]byte
	copy(sun[:], "/run/x")
	var etc [fsm.PatternLen]byte
	copy(etc[:], "/etc/")
	cases := []struct {
		name string
		bd   fsm.Binding
		want string
	}{
		{"path_prefix", fsm.Binding{PathKind: fsm.PathPrefix, Pattern: etc}, " path^=/etc/"},
		{"sun_prefix", fsm.Binding{PathKind: fsm.PathSunPrefix, Pattern: sun}, " sun_path^=/run/x"},
		{"arg_any", fsm.Binding{PathKind: fsm.PathAny, ArgOp: fsm.ArgAny}, ""},
		{"arg_eq", fsm.Binding{PathKind: fsm.PathAny, ArgOp: fsm.ArgEq, ArgIndex: 0, ArgValue: 16}, " arg0 == 16"},
		{"arg_le", fsm.Binding{PathKind: fsm.PathAny, ArgOp: fsm.ArgLe, ArgIndex: 1, ArgValue: 2}, " arg1 <= 2"},
		{"mask_any", fsm.Binding{PathKind: fsm.PathAny, ArgOp: fsm.ArgMaskAny, ArgIndex: 3, ArgValue: 0x10000}, " arg3 & 0x10000 != 0"},
		{"mask_none", fsm.Binding{PathKind: fsm.PathAny, ArgOp: fsm.ArgMaskNone, ArgIndex: 3, ArgValue: 0x1e0000}, " arg3 & 0x1e0000 == 0"},
		{"unknown_op", fsm.Binding{PathKind: fsm.PathAny, ArgOp: 99}, ""},
	}
	for _, c := range cases {
		if got := bindingPredicate(c.bd); got != c.want {
			t.Errorf("%s: bindingPredicate = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRulesFromBundleNoMeta(t *testing.T) {
	// No Meta: states/events fall back to generated names, scope from the numeric map;
	// duplicate bindings for the same (rule,event) collapse to one syscall description.
	b := fsm.Bundle{
		Rules: []fsm.Rule{{NumStates: 2, NumEvents: 1, TransBase: 0, Scope: fsm.ScopeCgroup, TerminalFrom: 1}},
		Transitions: []fsm.Transition{
			{NextState: 1, Action: fsm.ActionKill}, // s0,e0 -> kill
			{NextState: 1, Action: fsm.ActionObserve},
		},
		Bindings: []fsm.Binding{
			{Hook: fsm.HookExecve, Rule: 0, Event: 0, PathArg: fsm.NoArg, PathKind: fsm.PathAny, ArgIndex: fsm.NoArg, ArgOp: fsm.ArgAny},
			{Hook: fsm.HookExecve, Rule: 0, Event: 0, PathArg: fsm.NoArg, PathKind: fsm.PathAny, ArgIndex: fsm.NoArg, ArgOp: fsm.ArgAny},
		},
	}
	got := RulesFromBundle(b)[0]
	if got.Name != "0" || got.Scope != "cgroup" {
		t.Errorf("name/scope fallback: got name=%q scope=%q", got.Name, got.Scope)
	}
	if len(got.States) != 2 || got.States[0] != "state0" || got.Events[0] != "event0" {
		t.Errorf("generated names: states=%v events=%v", got.States, got.Events)
	}
	if len(got.Transitions) != 1 || got.Transitions[0].To != "state1" {
		t.Fatalf("transitions = %+v", got.Transitions)
	}
	if sys := got.Transitions[0].Syscalls; len(sys) != 1 || sys[0] != "execve" {
		t.Errorf("dedup syscalls = %v, want [execve]", sys)
	}
}

func TestEnvHelpers(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if got := NodeName(env(map[string]string{"NODE_NAME": "a"})); got != "a" {
		t.Errorf("node %q", got)
	}
	cases := []struct {
		env  map[string]string
		addr string
		want string
	}{
		{map[string]string{"ARIGUARD_METRICS_ADVERTISE": "x:1", "POD_IP": "1.2.3.4"}, ":9102", "x:1"},
		{map[string]string{"POD_IP": "1.2.3.4"}, ":9102", "1.2.3.4:9102"},
		{nil, ":9102", ":9102"},
	}
	for _, c := range cases {
		if got := AdvertiseAddr(c.addr, env(c.env)); got != c.want {
			t.Errorf("got %q want %q", got, c.want)
		}
	}
}

func TestObserveThrottle(t *testing.T) {
	cur := time.Unix(1000, 0)
	s := New("http://unused", Registration{Node: "n"}, quiet)
	s.now = func() time.Time { return cur }
	obs := audit.Event{CgroupID: 1, Rule: "r", To: "2", Action: "observe"}

	s.Emit(obs)
	s.Emit(obs)
	cur = cur.Add(9 * time.Second)
	s.Emit(obs)
	if len(s.buf) != 1 {
		t.Fatalf("repeats within interval: buffered %d, want 1", len(s.buf))
	}

	kill := obs
	kill.Action = "kill"
	s.Emit(kill)
	s.Emit(kill)
	if len(s.buf) != 3 {
		t.Fatalf("non-observe must always pass: buffered %d, want 3", len(s.buf))
	}

	other := obs
	other.To = "3"
	s.Emit(other)
	other.CgroupID = 9
	s.Emit(other)
	if len(s.buf) != 5 {
		t.Fatalf("new state must pass: buffered %d, want 5", len(s.buf))
	}

	cur = cur.Add(2 * time.Second)
	s.Emit(obs)
	if len(s.buf) != 6 {
		t.Fatalf("after interval: buffered %d, want 6", len(s.buf))
	}
}

func TestObserveThrottleBounded(t *testing.T) {
	s := New("http://unused", Registration{Node: "n"}, quiet)
	for i := range 3 * maxThrottle {
		s.Emit(audit.Event{CgroupID: uint64(i), Rule: "r", Action: "observe"})
	}
	if len(s.seen) > maxThrottle {
		t.Fatalf("seen map grew to %d, cap %d", len(s.seen), maxThrottle)
	}
}
