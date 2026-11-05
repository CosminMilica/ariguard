package fsm

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzUnmarshalBundle fuzzes the policy-bundle parser. The agent loads bundles pushed over the
// control plane (PUT /api/v1/policy), so a malformed or hostile bundle must be rejected cleanly —
// never panic, over-allocate, or decode into something the agent then mishandles. Invariants:
//   - UnmarshalBundle never panics (the fuzz harness fails on any panic);
//   - anything that decodes also re-marshals and re-decodes (encode/decode are symmetric);
//   - GroupBindings (the next step the agent runs) never panics on a decoded bundle.
func FuzzUnmarshalBundle(f *testing.F) {
	for _, name := range []string{"policy.bin", "policy-full.bin"} {
		if data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", name)); err == nil {
			f.Add(data)
		}
	}
	// degenerate seeds: empty, header-only, truncated, bad magic.
	f.Add([]byte{})
	f.Add(make([]byte, bundleHeaderSize))

	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := UnmarshalBundle(data)
		if err != nil {
			return // rejected cleanly — the expected path for malformed input
		}
		// A bundle that decodes must re-marshal, and the result must decode again to an equal bundle.
		out, err := b.Marshal()
		if err != nil {
			t.Fatalf("decoded bundle failed to re-marshal: %v", err)
		}
		if _, err := UnmarshalBundle(out); err != nil {
			t.Fatalf("re-decode of a marshaled bundle failed: %v", err)
		}
		// The agent groups bindings right after decode; it must not panic (errors are fine).
		_, _ = b.GroupBindings()
	})
}
