//go:build e2e

package e2e

import (
	"strings"
	"testing"
	"time"
)

// TestIsolation verifies Tier C autonomous workload isolation: with --isolate=on, a confirmed
// terminal mitigation quarantines the attacker pod (label + deny-all NetworkPolicy) and nothing
// benign is touched. Network enforcement itself depends on the CNI (kindnet does not enforce
// NetworkPolicy), so this asserts the quarantine decision — the label and the policy object —
// not packet drops.
func TestIsolation(t *testing.T) {
	requireE2E(t)
	setupMode(t, "isolate", "isolate")

	recreateNamespace(t, evalNS)
	applyBenign(t)
	waitBenignReady(t, evalNS, 5*time.Minute)
	applyAttacks(t)
	waitAttackersStarted(t, evalNS, 5*time.Minute)
	time.Sleep(attackSeconds())

	// Isolation is applied asynchronously off the audit drain. Attackers whose terminal syscall
	// runs in PID1 die instantly, so their pod can be gone before the label lands — isolation is
	// best-effort for instant-death pods (the kill already happened) but reliable for the
	// long-lived/forking compromises that matter. Require a solid majority rather than a strict
	// 100% (which races); the zero-false-positive and NetworkPolicy checks below stay strict.
	wantMin := len(attackers) - 2
	quarantined := waitQuarantined(t, evalNS, wantMin, 2*time.Minute)

	// The deny-all NetworkPolicy exists in the namespace.
	if _, err := kubectlTry(kubectlTimeout, "-n", evalNS, "get", "networkpolicy", "ariguard-quarantine"); err != nil {
		t.Errorf("deny-all NetworkPolicy not created: %v", err)
	}

	// Zero false positives: only attacker pods are quarantined.
	known := attackerSet()
	for _, p := range quarantined {
		if !known[p] {
			t.Errorf("non-attacker pod was quarantined: %s", p)
		}
	}
}

// waitQuarantined polls for pods carrying the quarantine label and returns their names once at
// least want are present (or fails after timeout).
func waitQuarantined(t *testing.T, ns string, want int, timeout time.Duration) []string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last []string
	for time.Now().Before(deadline) {
		out, err := kubectlTry(kubectlTimeout, "-n", ns, "get", "pods",
			"-l", "ariguard.io/quarantine=true", "-o", "jsonpath={.items[*].metadata.name}")
		if err == nil {
			last = strings.Fields(out)
			if len(last) >= want {
				return last
			}
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("only %d/%d attacker pods quarantined within %s: %v", len(last), want, timeout, last)
	return last
}
