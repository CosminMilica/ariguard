package fsm

import (
	"os"
	"path/filepath"
	"testing"
)

// TestGoldenCrossLanguage verifies the Go reader decodes a policy bundle
// produced by the Python compiler (testdata/golden/container-escape.bin),
// proving both implementations agree on the v2 binary format.
//
// Regenerate the golden with: make golden
func TestGoldenCrossLanguage(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "golden", "container-escape.bin")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v (regenerate with `make golden`)", err)
	}

	b, err := UnmarshalBundle(data)
	if err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}

	if b.Dims.NumStates != 5 || b.Dims.NumEvents != 4 {
		t.Fatalf("dims = %dx%d, want 5x4", b.Dims.NumStates, b.Dims.NumEvents)
	}
	if b.Dims.WindowNs != 30_000_000_000 {
		t.Errorf("WindowNs = %d, want 30s", b.Dims.WindowNs)
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
		if got := b.At(c.state, c.event); got != c.want {
			t.Errorf("%s: At(%d,%d) = %+v, want %+v", c.name, c.state, c.event, got, c.want)
		}
	}

	groups, err := b.GroupBindings()
	if err != nil {
		t.Fatalf("GroupBindings: %v", err)
	}
	openat := groups[HookOpenat]
	prefixes := []string{"/run/containerd/containerd.sock", "/var/run/docker.sock", "/run/docker.sock"}
	if openat.Count != uint32(len(prefixes)) {
		t.Fatalf("openat bindings = %d, want %d", openat.Count, len(prefixes))
	}
	for i, p := range prefixes {
		bd := openat.Entries[i]
		if bd.Event != evRuntimeSocketOpen || bd.MatchKind != MatchPathPrefix {
			t.Errorf("openat[%d] = event %d kind %d, want event %d kind %d",
				i, bd.Event, bd.MatchKind, evRuntimeSocketOpen, MatchPathPrefix)
		}
		if got := string(bd.Pattern[:bd.PatternLen]); got != p {
			t.Errorf("openat[%d] pattern = %q, want %q", i, got, p)
		}
	}
}
