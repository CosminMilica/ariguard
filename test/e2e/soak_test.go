//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSoak drives sustained, concurrent waves of every attack chain (plus benign) for
// ARIGUARD_SOAK_SECONDS and asserts the systems guarantees under load: memory stays flat
// (bpf_map_bytes constant), no audit events are dropped, every chain is still detected and
// enforced at least once, and nothing benign is ever enforced (zero false positives). It is
// the "1000 compromised services" stress gate; it skips unless ARIGUARD_SOAK_SECONDS is set.
func TestSoak(t *testing.T) {
	requireE2E(t)
	secs := envInt("ARIGUARD_SOAK_SECONDS", 0)
	if secs <= 0 {
		t.Skip("set ARIGUARD_SOAK_SECONDS>0 to run the soak/load gate")
	}
	concurrency := envInt("ARIGUARD_E2E_CONCURRENCY", 3)
	interval := time.Duration(envInt("ARIGUARD_SOAK_INTERVAL_SECONDS", 15)) * time.Second

	dir, agentPod := setupMode(t, "enforce", "enforce")
	if _, enforce := readPolicy(t); enforce != 1 {
		t.Fatalf("soak needs enforce mode, AG_POLICY.enforce=%d", enforce)
	}
	recreateNamespace(t, evalNS)
	applyBenign(t)
	waitBenignReady(t, evalNS, 5*time.Minute)

	// Baselines: the memory budget is pre-allocated and must not move; drops must stay at 0.
	baseMapBytes := scrapeMetric(t, agentPod, "ariguard_bpf_map_bytes")
	baseDropped := scrapeMetric(t, agentPod, "ariguard_audit_dropped_total")
	t.Logf("soak start: %ds, concurrency=%d, interval=%s, bpf_map_bytes=%d", secs, concurrency, interval, baseMapBytes)

	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	waves := 0
	for time.Now().Before(deadline) {
		waves++
		for _, a := range attackers {
			for i := 0; i < concurrency; i++ {
				spawnInstance(t, a, fmt.Sprintf("%d-%d", waves, i))
			}
		}
		time.Sleep(interval)
		// Flat memory + zero drops must hold throughout the run, not only at the end.
		if mb := scrapeMetric(t, agentPod, "ariguard_bpf_map_bytes"); mb != baseMapBytes {
			t.Fatalf("wave %d: bpf_map_bytes changed under load %d -> %d (memory not flat)", waves, baseMapBytes, mb)
		}
		if d := scrapeMetric(t, agentPod, "ariguard_audit_dropped_total"); d != baseDropped {
			t.Fatalf("wave %d: ariguard_audit_dropped_total rose %d -> %d (events dropped under load)", waves, baseDropped, d)
		}
		pruneFinished(t, evalNS)
	}
	t.Logf("soak: %d waves x %d attack pods x %d instances", waves, len(attackers), concurrency)

	// Efficacy + zero false positives under load (check_audit --soak tolerates instances cut
	// short by pruning, but keeps the "nothing benign enforced/terminal" guarantees strict).
	audit := collectAudit(t, agentPod, dir)
	checkSoak(t, audit)

	if mb := scrapeMetric(t, agentPod, "ariguard_bpf_map_bytes"); mb != baseMapBytes {
		t.Errorf("bpf_map_bytes not flat end to end: %d -> %d", baseMapBytes, mb)
	}
	if d := scrapeMetric(t, agentPod, "ariguard_audit_dropped_total"); d != baseDropped {
		t.Errorf("ariguard_audit_dropped_total nonzero after soak: %d -> %d", baseDropped, d)
	}
}

// spawnInstance creates a uniquely-named copy of an attacker manifest so many instances of the
// same chain run concurrently. "name: <base>" is unique per manifest (the container is named
// "attacker"), so a single text replace renames both block- and flow-style metadata without a
// YAML dependency in the runner.
func spawnInstance(t *testing.T, attacker, uid string) {
	t.Helper()
	src := filepath.Join(repoRoot(), "testdata/workloads/attack", attacker+".yaml")
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	doc := strings.Replace(string(b), "name: "+attacker, "name: "+attacker+"-"+uid, 1)
	f := filepath.Join(t.TempDir(), attacker+"-"+uid+".yaml")
	if err := os.WriteFile(f, []byte(doc), 0o644); err != nil {
		t.Fatalf("write %s: %v", f, err)
	}
	_, _ = kubectlTry(kubectlTimeout, "create", "-f", f) // best-effort; soak tolerates transient create failures
}

// pruneFinished removes completed/killed pods so the node does not fill up during the soak.
func pruneFinished(t *testing.T, ns string) {
	t.Helper()
	for _, phase := range []string{"Succeeded", "Failed"} {
		_, _ = kubectlTry(kubectlTimeout, "-n", ns, "delete", "pod", "--field-selector", "status.phase=="+phase, "--wait=false")
	}
}

func checkSoak(t *testing.T, auditPath string) {
	t.Helper()
	args := []string{
		filepath.Join(repoRoot(), "testdata/scripts/check_audit.py"),
		"--expectations", filepath.Join(repoRoot(), "testdata/expectations.json"),
		"--enforce", "--soak", auditPath,
	}
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	out, errOut, err := run(ctx, "python3", args...)
	t.Logf("check_audit.py --soak:\n%s", out)
	if err != nil {
		t.Fatalf("check_audit.py --soak failed: %v\n%s", err, errOut)
	}
}
