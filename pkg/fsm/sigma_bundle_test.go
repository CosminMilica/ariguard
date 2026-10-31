package fsm

import (
	"os"
	"testing"
)

// TestLoadSigmaBundle decodes the policy bundle compiled from compiler/rules/sigma
// (named by ARIGUARD_SIGMA_BUNDLE) and checks it parses within the kernel limits.
// The ci-compiler gate compiles the Sigma rules and sets the env; the test skips
// when it is unset.
func TestLoadSigmaBundle(t *testing.T) {
	path := os.Getenv("ARIGUARD_SIGMA_BUNDLE")
	if path == "" {
		t.Skip("ARIGUARD_SIGMA_BUNDLE not set, skipping")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sigma bundle %s: %v", path, err)
	}
	b, err := UnmarshalBundle(data)
	if err != nil {
		t.Fatalf("unmarshal sigma bundle: %v", err)
	}
	if len(b.Rules) < 1 {
		t.Fatalf("sigma bundle has %d rules, want >= 1", len(b.Rules))
	}
	if len(b.Rules) > int(MaxRules) {
		t.Errorf("sigma bundle has %d rules, max is %d", len(b.Rules), MaxRules)
	}
	if len(b.Transitions) > int(MaxTransitions) {
		t.Errorf("sigma bundle has %d transitions, max is %d", len(b.Transitions), MaxTransitions)
	}
}
