//go:build integration && linux

// Behavioral gate for generated rules: load a compiled bundle into the running
// kernel and, for each driver file, prove its rule detects the attack chain and
// stays silent on the benign twin. This is the "tested + reproducible" guarantee
// behind the rule-generation pipeline. Needs root; run in a VM (see ci-rulegen).
package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/CosminMilica/ariguard/pkg/fsm"
)

const (
	genBundleEnv  = "ARIGUARD_GEN_BUNDLE"  // path to the compiled bundle under test
	genDriversEnv = "ARIGUARD_GEN_DRIVERS" // directory of *.test.json drivers
	driverSuffix  = ".test.json"
)

// driver is one generated rule's behavioral test: the attack chain must drive
// the named rule to its terminal state; the benign twin must not. Steps use the
// runSteps vocabulary in chain_test.go.
type driver struct {
	Rule   string   `json:"rule"`
	Attack []string `json:"attack"`
	Benign []string `json:"benign"`
	path   string   // source file, for diagnostics
}

// TestBehavioralGate runs every driver against the bundle in ARIGUARD_GEN_BUNDLE.
// It is a no-op (skips) until a bundle is set and drivers exist, so it is safe to
// wire into CI before any rules are generated.
func TestBehavioralGate(t *testing.T) {
	bundlePath := os.Getenv(genBundleEnv)
	if bundlePath == "" {
		t.Skipf("set %s to a compiled bundle to run the behavioral gate", genBundleEnv)
	}
	driversDir := envOr(genDriversEnv, filepath.Join(repoRoot(t), "testdata", "generated"))
	drivers, err := loadDrivers(driversDir)
	if err != nil {
		t.Fatalf("load drivers from %s: %v", driversDir, err)
	}
	if len(drivers) == 0 {
		t.Skipf("no %s drivers in %s", driverSuffix, driversDir)
	}

	raw, err := os.ReadFile(bundlePath)
	if errors.Is(err, os.ErrNotExist) {
		// ci-rulegen skips the compile when there are no generated rules yet, so
		// the bundle may not exist. Stay a no-op rather than fail.
		t.Skipf("bundle %s does not exist (no generated rules compiled yet)", bundlePath)
	}
	if err != nil {
		t.Fatalf("read bundle %s: %v", bundlePath, err)
	}
	bundle, err := fsm.UnmarshalBundle(raw)
	if err != nil {
		t.Fatalf("decode bundle %s: %v", bundlePath, err)
	}

	h := newHarness(t, loadObject(t), bundle)

	for _, d := range drivers {
		t.Run(d.Rule, func(t *testing.T) {
			ri := slices.IndexFunc(bundle.Meta.Rules, func(m fsm.RuleMeta) bool { return m.Name == d.Rule })
			if ri < 0 {
				t.Fatalf("%s names rule %q, not in bundle (have %v)", filepath.Base(d.path), d.Rule, ruleNames(bundle))
			}
			terminal := bundle.Rules[ri].TerminalFrom
			stateNames := bundle.Meta.Rules[ri].States

			attack := states(h.run(t, d.Attack...), d.Rule)
			if !reachedTerminal(stateNames, terminal, attack) {
				t.Fatalf("attack %v: rule %q reached %v, want terminal %q",
					d.Attack, d.Rule, attack, terminalName(stateNames, terminal))
			}

			benign := states(h.run(t, d.Benign...), d.Rule)
			if reachedTerminal(stateNames, terminal, benign) {
				t.Fatalf("benign %v: rule %q reached %v, must not reach terminal %q",
					d.Benign, d.Rule, benign, terminalName(stateNames, terminal))
			}
		})
	}
}

// loadDrivers reads every *.test.json in dir, sorted by path. A missing dir is
// not an error: it yields no drivers (the gate then skips).
func loadDrivers(dir string) ([]driver, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []driver
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), driverSuffix) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var d driver
		if err := dec.Decode(&d); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if d.Rule == "" {
			return nil, fmt.Errorf("%s: missing rule name", e.Name())
		}
		d.path = p
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b driver) int { return strings.Compare(a.path, b.path) })
	return out, nil
}

// reachedTerminal reports whether any observed state is at or past the rule's
// terminal state index (TerminalFrom), mirroring the kernel's terminal test.
func reachedTerminal(stateNames []string, terminal uint32, observed []string) bool {
	for _, s := range observed {
		if idx := slices.Index(stateNames, s); idx >= 0 && uint32(idx) >= terminal {
			return true
		}
	}
	return false
}

func terminalName(stateNames []string, terminal uint32) string {
	if int(terminal) < len(stateNames) {
		return stateNames[terminal]
	}
	return fmt.Sprintf("state#%d", terminal)
}

func ruleNames(b *fsm.Bundle) []string {
	names := make([]string, len(b.Meta.Rules))
	for i, m := range b.Meta.Rules {
		names[i] = m.Name
	}
	return names
}
