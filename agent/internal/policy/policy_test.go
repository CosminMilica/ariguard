package policy

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/CosminMilica/ariguard/pkg/fsm"
)

type recorder struct {
	ops      []string
	policies []fsm.Policy
	failAt   int
}

func (r *recorder) record(op string) error {
	r.ops = append(r.ops, op)
	if r.failAt > 0 && len(r.ops) == r.failAt {
		return errors.New("boom")
	}
	return nil
}

func (r *recorder) PutPolicy(p fsm.Policy) error {
	r.policies = append(r.policies, p)
	return r.record("policy")
}

func (r *recorder) PutRule(i uint32, _ fsm.Rule) error {
	return r.record(fmt.Sprintf("rule/%d", i))
}

func (r *recorder) PutTransition(i uint32, _ fsm.Transition) error {
	return r.record(fmt.Sprintf("transition/%d", i))
}

func (r *recorder) PutBindings(h uint32, _ fsm.HookBindings) error {
	return r.record(fmt.Sprintf("bindings/%d", h))
}

func anyBinding(hook, rule, event uint32) fsm.Binding {
	return fsm.Binding{Hook: hook, Rule: rule, Event: event, PathArg: fsm.NoArg, ArgIndex: fsm.NoArg}
}

// testBundle: rule 0 (cgroup, 2 states x 2 events) and rule 1 (process, 2 states x 1 event).
func testBundle() *fsm.Bundle {
	var p [fsm.PatternLen]byte
	copy(p[:], "/etc/")
	open := anyBinding(fsm.HookOpenat, 0, 0)
	open.PathArg, open.PathKind, open.PathLen, open.Pattern = 1, fsm.PathPrefix, 5, p
	return &fsm.Bundle{
		Rules: []fsm.Rule{
			{NumStates: 2, NumEvents: 2, TransBase: 0, Scope: fsm.ScopeCgroup, TerminalFrom: 1, WindowNs: 1_000_000_000},
			{NumStates: 2, NumEvents: 1, TransBase: 4, Scope: fsm.ScopeProcess, TerminalFrom: 2, WindowNs: 1_000_000_000},
		},
		Transitions: []fsm.Transition{
			{NextState: 1}, {NextState: 0},
			{NextState: 1}, {NextState: 1, Action: fsm.ActionThrottle},
			{NextState: 1}, {NextState: 1},
		},
		Bindings: []fsm.Binding{open, anyBinding(fsm.HookExecve, 0, 1), anyBinding(fsm.HookMemfdCreate, 1, 0)},
		Meta: fsm.Meta{Rules: []fsm.RuleMeta{
			{Name: "a", Scope: "cgroup", States: []string{"s0", "s1"}, Events: []string{"e0", "e1"}},
			{Name: "b", Scope: "process", States: []string{"s0", "s1"}, Events: []string{"e0"}},
		}},
	}
}

func skipIfStub(t *testing.T, b *fsm.Bundle) {
	t.Helper()
	if err := b.Validate(); err != nil && strings.Contains(err.Error(), "not implemented") {
		t.Skip("fsm bundle API not implemented yet")
	}
}

func wantOps(b *fsm.Bundle) []string {
	want := []string{"policy"}
	for i := range b.Rules {
		want = append(want, fmt.Sprintf("rule/%d", i))
	}
	for i := range b.Transitions {
		want = append(want, fmt.Sprintf("transition/%d", i))
	}
	for h := 0; h < int(fsm.NumHooks); h++ {
		want = append(want, fmt.Sprintf("bindings/%d", h))
	}
	return append(want, "policy")
}

func TestApplyOrdering(t *testing.T) {
	b := testBundle()
	skipIfStub(t, b)
	r := &recorder{}
	if err := Apply(r, b); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	want := wantOps(b)
	if strings.Join(r.ops, ",") != strings.Join(want, ",") {
		t.Fatalf("ops = %v\nwant %v", r.ops, want)
	}
	if r.policies[0] != (fsm.Policy{}) {
		t.Errorf("first AG_POLICY write = %+v, want zero", r.policies[0])
	}
	if last := r.policies[len(r.policies)-1]; last != b.Policy() || last.NumRules != 2 {
		t.Errorf("last AG_POLICY write = %+v, want %+v", last, b.Policy())
	}
}

func TestApplyStopsOnWriteError(t *testing.T) {
	b := testBundle()
	skipIfStub(t, b)
	n := len(wantOps(b))
	for failAt := 1; failAt <= n; failAt++ {
		r := &recorder{failAt: failAt}
		if err := Apply(r, b); err == nil {
			t.Fatalf("failAt %d: Apply succeeded, want error", failAt)
		}
		if len(r.ops) != failAt {
			t.Errorf("failAt %d: ops = %v, want stop at the failing write", failAt, r.ops)
		}
		published := failAt == n
		if !published && len(r.policies) != 1 {
			t.Errorf("failAt %d: AG_POLICY writes = %+v, want only the disabling one", failAt, r.policies)
		}
	}
}

func TestApplyInvalidBundleWritesNothing(t *testing.T) {
	invalid := map[string]func(*fsm.Bundle){
		"binding rule out of range": func(b *fsm.Bundle) { b.Bindings[0].Rule = 2 },
		"too many rules":            func(b *fsm.Bundle) { b.Rules = make([]fsm.Rule, fsm.MaxRules+1) },
		"rule range past the table": func(b *fsm.Bundle) { b.Rules[1].TransBase = 5 },
	}
	for name, mutate := range invalid {
		t.Run(name, func(t *testing.T) {
			b := testBundle()
			mutate(b)
			r := &recorder{}
			if err := Apply(r, b); err == nil {
				t.Fatal("Apply succeeded, want validation error")
			}
			if len(r.ops) != 0 {
				t.Errorf("ops = %v, want none", r.ops)
			}
		})
	}
}

func TestApplyEnforce(t *testing.T) {
	b := testBundle()
	skipIfStub(t, b)
	for _, enforce := range []bool{false, true} {
		r := &recorder{}
		if err := Apply(r, b, WithEnforce(enforce)); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if r.policies[0] != (fsm.Policy{}) {
			t.Errorf("enforce=%v: first write = %+v, want zero", enforce, r.policies[0])
		}
		last := r.policies[len(r.policies)-1]
		want := b.Policy()
		if enforce {
			want.Enforce = 1
		}
		if last != want {
			t.Errorf("enforce=%v: published %+v, want %+v", enforce, last, want)
		}
	}
}
