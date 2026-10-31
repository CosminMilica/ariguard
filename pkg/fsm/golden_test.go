package fsm

import (
	"os"
	"path/filepath"
	"testing"
)

// TestGoldenCrossLanguage verifies the Go reader decodes a transition table
// produced by the Python compiler (testdata/golden/container-escape.bin),
// proving both implementations agree on the v1 binary ABI.
//
// Regenerate the golden with: make golden
func TestGoldenCrossLanguage(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "golden", "container-escape.bin")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v (regenerate with `make golden`)", err)
	}

	tbl, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}

	if tbl.NumStates != 5 || tbl.NumEvents != 4 {
		t.Fatalf("header = %dx%d, want 5x4", tbl.NumStates, tbl.NumEvents)
	}

	// Event indices follow declaration order in container-escape.yml.
	const (
		evRuntimeSocketOpen uint32 = 0
		evNamespaceManip    uint32 = 1
		evHostMount         uint32 = 2
		evCriticalExecve    uint32 = 3
	)

	cases := []struct {
		name         string
		state, event uint32
		want         Transition
	}{
		{"socket open", StateNormal, evRuntimeSocketOpen, Transition{StateSuspicious, ActionObserve}},
		{"namespace manip", StateSuspicious, evNamespaceManip, Transition{StateEscalating, ActionThrottle}},
		{"host mount", StateEscalating, evHostMount, Transition{StateBreakoutImminent, ActionDeny}},
		{"critical execve", StateBreakoutImminent, evCriticalExecve, Transition{StateCompromised, ActionKill}},
		// Unspecified pairs default to (same state, observe).
		{"default", StateNormal, evHostMount, Transition{StateNormal, ActionObserve}},
	}

	for _, c := range cases {
		if got := tbl.At(c.state, c.event); got != c.want {
			t.Errorf("%s: At(%d,%d) = %+v, want %+v", c.name, c.state, c.event, got, c.want)
		}
	}
}
