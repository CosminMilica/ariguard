package policy

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/CosminMilica/statewall/pkg/fsm"
)

type recorder struct {
	ops    []string
	dims   []fsm.Dims
	failAt int
}

func (r *recorder) record(op string) error {
	r.ops = append(r.ops, op)
	if r.failAt > 0 && len(r.ops) == r.failAt {
		return errors.New("boom")
	}
	return nil
}

func (r *recorder) PutDims(d fsm.Dims) error {
	r.dims = append(r.dims, d)
	return r.record("dims")
}

func (r *recorder) PutTransition(i uint32, _ fsm.Transition) error {
	return r.record(fmt.Sprintf("transition/%d", i))
}

func (r *recorder) PutBindings(h uint32, _ fsm.HookBindings) error {
	return r.record(fmt.Sprintf("bindings/%d", h))
}

func testBundle() *fsm.Bundle {
	var p [fsm.PatternLen]byte
	copy(p[:], "/etc/")
	return &fsm.Bundle{
		Dims: fsm.Dims{NumStates: 2, NumEvents: 2, WindowNs: 1_000_000_000},
		Transitions: []fsm.Transition{
			{NextState: fsm.StateNormal}, {NextState: fsm.StateSuspicious},
			{NextState: fsm.StateSuspicious}, {NextState: fsm.StateSuspicious, Action: fsm.ActionObserve},
		},
		Bindings: []fsm.Binding{
			{Hook: fsm.HookOpenat, Event: 0, MatchKind: fsm.MatchPathPrefix, PatternLen: 5, Pattern: p},
			{Hook: fsm.HookExecve, Event: 1, MatchKind: fsm.MatchAny},
		},
	}
}

func skipIfStub(t *testing.T, b *fsm.Bundle) {
	t.Helper()
	if err := b.Validate(); err != nil && strings.Contains(err.Error(), "not implemented") {
		t.Skip("fsm bundle API not implemented yet")
	}
}

func TestApplyOrdering(t *testing.T) {
	b := testBundle()
	skipIfStub(t, b)
	r := &recorder{}
	if err := Apply(r, b); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	want := []string{"dims", "transition/0", "transition/1", "transition/2", "transition/3"}
	for h := 0; h < int(fsm.NumHooks); h++ {
		want = append(want, fmt.Sprintf("bindings/%d", h))
	}
	want = append(want, "dims")
	if strings.Join(r.ops, ",") != strings.Join(want, ",") {
		t.Fatalf("ops = %v\nwant %v", r.ops, want)
	}
	if r.dims[0] != (fsm.Dims{}) {
		t.Errorf("first SW_DIMS write = %+v, want zero", r.dims[0])
	}
	if r.dims[1] != b.Dims {
		t.Errorf("last SW_DIMS write = %+v, want %+v", r.dims[1], b.Dims)
	}
}

func TestApplyStopsOnWriteError(t *testing.T) {
	b := testBundle()
	skipIfStub(t, b)
	r := &recorder{failAt: 3}
	if err := Apply(r, b); err == nil {
		t.Fatal("Apply succeeded, want error")
	}
	if len(r.ops) != 3 || len(r.dims) != 1 {
		t.Errorf("ops = %v, want stop after 3 writes with dims never published", r.ops)
	}
}

func TestApplyInvalidBundleWritesNothing(t *testing.T) {
	b := testBundle()
	b.Dims.NumStates = fsm.MaxTransitions + 1
	r := &recorder{}
	if err := Apply(r, b); err == nil {
		t.Fatal("Apply succeeded, want validation error")
	}
	if len(r.ops) != 0 {
		t.Errorf("ops = %v, want none", r.ops)
	}
}
