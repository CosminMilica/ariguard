//go:build e2e

// Package e2e is the Statewall end-to-end gate: it builds a fresh agent image,
// deploys the DaemonSet into the kind cluster, runs the benign + attack
// workloads, and asserts from the three sources of truth — the BPF maps in the
// VM host kernel (bpftool), the audit JSONL (check_audit.py), and Kubernetes pod
// state / Prometheus metrics. Detect mode proves detection without side effects;
// enforce mode proves attackers are killed and nothing else is touched.
//
// It runs inside the Lima VM against the kind cluster. Without a reachable
// cluster and a BTF kernel it SKIPS, unless STATEWALL_REQUIRE_E2E=1 (CI), where
// the same condition is a hard failure. See README.md.
package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	systemNS    = "statewall-system" // DaemonSet namespace (kustomize base)
	evalNS      = "statewall-eval"   // workload namespace, pinned by expectations.json
	dsName      = "statewall-agent"
	agentLabel  = "app.kubernetes.io/name=statewall-agent"
	metricsPort = "9102"
)

// attackers are the four attack workloads; order matches testdata/workloads/attack.
var attackers = []string{"container-escape", "container-escape-connect", "reverse-seq", "fileless-seq"}

// podPhaseKillExpected lists the attackers whose terminal syscall runs in their
// main process, so a SIGKILL takes the pod to Failed. reverse-seq and
// fileless-seq fork and run the chain in a short-lived child (os.fork in the
// workloads), so bpf_send_signal(SIGKILL) kills only that child and the pod may
// stay Running; for those the kill is proven by the audit record (enforced=true
// on the terminal step, checked by check_audit.py --enforce) and the kills
// metric, with pod phase recorded only as a secondary signal.
var podPhaseKillExpected = map[string]bool{
	"container-escape":         true,
	"container-escape-connect": true,
}

// swMaps are dumped to the artifacts dir on teardown. SW_AUDIT is a ring buffer
// that bpftool cannot dump; the failing dump is ignored.
var swMaps = []string{"SW_POLICY", "SW_RULES", "SW_TRANSITIONS", "SW_BINDINGS", "SW_STATE", "SW_PODS", "SW_METRICS", "SW_SCRATCH"}

var (
	imageOnce sync.Once
	imageErr  error
)

func TestDetectMode(t *testing.T) {
	dir, agentPod := setupMode(t, "detect", "detect")

	// SW_POLICY: detect-only, three rules loaded.
	numRules, enforce := readPolicy(t)
	if enforce != 0 {
		t.Errorf("SW_POLICY.enforce = %d, want 0 in detect mode", enforce)
	}
	if numRules != 3 {
		t.Errorf("SW_POLICY.num_rules = %d, want 3", numRules)
	}
	assertMapNonEmpty(t, "SW_RULES")
	assertMapNonEmpty(t, "SW_TRANSITIONS")

	recreateNamespace(t, evalNS)
	applyBenign(t)
	waitBenignReady(t, evalNS, 5*time.Minute)
	applyAttacks(t)
	waitAttackersStarted(t, evalNS, 5*time.Minute)
	time.Sleep(attackSeconds())
	dumpAttackLogs(t)

	audit := collectAudit(t, agentPod, dir)
	runChecker(t, audit, false)

	// Detection only: nothing is killed.
	for _, a := range attackers {
		ph, err := podPhase(evalNS, a)
		if err != nil {
			t.Errorf("attacker %s phase: %v", a, err)
			continue
		}
		if ph == "Failed" {
			t.Errorf("attacker %s is Failed in detect mode; detection must not kill", a)
		}
	}
	if kills := scrapeKills(t, agentPod); kills != 0 {
		t.Errorf("statewall_kills_total = %d in detect mode, want 0", kills)
	}
}

func TestEnforceMode(t *testing.T) {
	dir, agentPod := setupMode(t, "enforce", "enforce")

	// SW_POLICY: enforcing, three rules loaded.
	numRules, enforce := readPolicy(t)
	if enforce != 1 {
		t.Errorf("SW_POLICY.enforce = %d, want 1 in enforce mode", enforce)
	}
	if numRules != 3 {
		t.Errorf("SW_POLICY.num_rules = %d, want 3", numRules)
	}
	assertMapNonEmpty(t, "SW_RULES")
	assertMapNonEmpty(t, "SW_TRANSITIONS")

	recreateNamespace(t, evalNS)
	applyBenign(t)
	waitBenignReady(t, evalNS, 5*time.Minute)

	// Baselines captured before the attacks: nothing should regress.
	baseEval := listPods(t, evalNS)
	baseSystem := listPods(t, "kube-system")
	baseKills := scrapeKills(t, agentPod)

	applyAttacks(t)
	waitAttackersStarted(t, evalNS, 5*time.Minute)
	time.Sleep(attackSeconds())

	// Pod phase is a reliable kill signal only for the non-forking attackers.
	for _, a := range attackers {
		if podPhaseKillExpected[a] {
			waitPodPhase(t, evalNS, a, "Failed", 90*time.Second)
		} else {
			ph, _ := podPhase(evalNS, a)
			t.Logf("attacker %s phase=%s (kill proven via audit + metric, not pod phase)", a, ph)
		}
	}
	dumpAttackLogs(t)

	audit := collectAudit(t, agentPod, dir)
	// check_audit.py --enforce: every attacker's terminal record has enforced=true
	// and nothing non-attacker is enforced. By decision F5 the kernel sets
	// enforced=1 only when the cgroup is in SW_PODS, so this proves per-pod
	// attribution and the SW_PODS gate end to end.
	runChecker(t, audit, true)

	// SW_PODS carries the tracked pod cgroups. A direct pod->cgroup-id mapping is
	// not resolved here (it depends on the node's cgroup driver layout); instead
	// non-emptiness is asserted and attribution is proven by check_audit.py above
	// (attacker kills landed, benign/host did not — see the undisturbed check).
	pods := bpftoolMapDump(t, "SW_PODS")
	if len(pods) < len(attackers) {
		t.Errorf("SW_PODS has %d entries, want >= %d (one per tracked pod cgroup)", len(pods), len(attackers))
	}

	// Kill counter rose by exactly one per attacker.
	kills := scrapeKills(t, agentPod)
	if got := kills - baseKills; got != uint64(len(attackers)) {
		t.Errorf("statewall_kills_total rose by %d (%d -> %d), want %d", got, baseKills, kills, len(attackers))
	}

	// Collateral check: benign and kube-system pods neither failed nor restarted.
	assertUndisturbed(t, evalNS, baseEval, attackerSet())
	assertUndisturbed(t, "kube-system", baseSystem, nil)
}

// setupMode gates, builds a fresh image, deploys the overlay and returns the
// artifacts dir and agent pod name. Teardown is always registered first.
func setupMode(t *testing.T, overlay, mode string) (dir, agentPod string) {
	t.Helper()
	requireE2E(t)
	ensureImage(t)
	dir = artifactsDir(t, mode)
	overlayPath := filepath.Join(repoRoot(), "deploy/k8s/overlays", overlay)
	t.Cleanup(func() {
		dumpArtifacts(t, dir)
		_, _ = kubectlTry(kubectlTimeout, "delete", "namespace", evalNS, "--ignore-not-found", "--wait=false")
		_, _ = kubectlTry(kubectlTimeout, "delete", "-k", overlayPath, "--ignore-not-found", "--wait=false")
	})
	deployAgent(t, overlay)
	agentPod = agentPodName(t)
	return dir, agentPod
}

// requireE2E skips (or, under STATEWALL_REQUIRE_E2E=1, fails) unless the kind
// cluster is reachable and the kernel exposes BTF.
func requireE2E(t *testing.T) {
	t.Helper()
	required := os.Getenv("STATEWALL_REQUIRE_E2E") == "1"
	gate := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if required {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
	if _, err := kubectlTry(shortTimeout, "get", "nodes"); err != nil {
		gate("kind cluster not reachable (kubectl get nodes): %v", err)
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		gate("kernel has no BTF at /sys/kernel/btf/vmlinux: %v", err)
	}
}

// ensureImage builds the agent image fresh and loads it into kind, once per run.
func ensureImage(t *testing.T) {
	t.Helper()
	imageOnce.Do(func() {
		t.Logf("building fresh image: make image kind-load")
		imageErr = makeTarget(buildTimeout, "image", "kind-load")
	})
	if imageErr != nil {
		t.Fatalf("make image kind-load: %v", imageErr)
	}
}

func deployAgent(t *testing.T, overlay string) {
	t.Helper()
	overlayPath := filepath.Join(repoRoot(), "deploy/k8s/overlays", overlay)
	// Clean slate so the other mode's DaemonSet (and its kernel maps) is gone.
	_, _ = kubectlTry(kubectlTimeout, "delete", "namespace", systemNS, "--ignore-not-found", "--wait=true", "--timeout=120s")
	waitNamespaceGone(t, systemNS, 3*time.Minute)
	kubectl(t, "apply", "-k", overlayPath)
	waitDaemonSetReady(t, systemNS, dsName, 5*time.Minute)
}

func agentPodName(t *testing.T) string {
	t.Helper()
	out := kubectl(t, "-n", systemNS, "get", "pods", "-l", agentLabel, "-o", "jsonpath={.items[0].metadata.name}")
	name := strings.TrimSpace(out)
	if name == "" {
		t.Fatal("no statewall-agent pod found")
	}
	return name
}

// readPolicy returns SW_POLICY[0] (num_rules, enforce).
func readPolicy(t *testing.T) (numRules, enforce uint32) {
	t.Helper()
	entries := bpftoolMapDump(t, "SW_POLICY")
	if len(entries) == 0 {
		t.Fatal("SW_POLICY is empty")
	}
	nr, en, err := policyFields(entries[0])
	if err != nil {
		t.Fatalf("decode SW_POLICY: %v", err)
	}
	return nr, en
}

func assertMapNonEmpty(t *testing.T, mapName string) {
	t.Helper()
	if n := nonZeroEntries(bpftoolMapDump(t, mapName)); n == 0 {
		t.Errorf("%s has no populated entries", mapName)
	}
}

// --- workloads -------------------------------------------------------------

func applyBenign(t *testing.T) {
	t.Helper()
	kubectl(t, "apply", "-f", filepath.Join(repoRoot(), "testdata/workloads/benign"))
}

func applyAttacks(t *testing.T) {
	t.Helper()
	for _, a := range attackers {
		kubectl(t, "apply", "-f", filepath.Join(repoRoot(), "testdata/workloads/attack", a+".yaml"))
	}
}

func dumpAttackLogs(t *testing.T) {
	t.Helper()
	for _, a := range attackers {
		if out, err := kubectlTry(kubectlTimeout, "-n", evalNS, "logs", "pod/"+a); err == nil {
			t.Logf("logs %s/%s:\n%s", evalNS, a, out)
		}
	}
}

// --- audit + checker -------------------------------------------------------

func collectAudit(t *testing.T, pod, dir string) string {
	t.Helper()
	logs := kubectl(t, "-n", systemNS, "logs", pod)
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, []byte(logs), 0o644); err != nil {
		t.Fatalf("write audit: %v", err)
	}
	return path
}

func runChecker(t *testing.T, auditPath string, enforce bool) {
	t.Helper()
	args := []string{
		filepath.Join(repoRoot(), "testdata/scripts/check_audit.py"),
		"--expectations", filepath.Join(repoRoot(), "testdata/expectations.json"),
	}
	if enforce {
		args = append(args, "--enforce")
	}
	args = append(args, auditPath)
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	defer cancel()
	out, errOut, err := run(ctx, "python3", args...)
	t.Logf("check_audit.py (enforce=%v):\n%s", enforce, out)
	if err != nil {
		t.Fatalf("check_audit.py failed (enforce=%v): %v\n%s", enforce, err, errOut)
	}
}

// --- metrics ---------------------------------------------------------------

func scrapeKills(t *testing.T, pod string) uint64 {
	t.Helper()
	return scrapeMetric(t, pod, "statewall_kills_total")
}

// scrapeMetric reads /metrics from inside the agent pod over bash's /dev/tcp (no
// curl in the image, no host port). It retries while the server is coming up.
func scrapeMetric(t *testing.T, pod, metric string) uint64 {
	t.Helper()
	script := fmt.Sprintf(`exec 3<>/dev/tcp/127.0.0.1/%s; printf 'GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n' >&3; cat <&3`, metricsPort)
	deadline := time.Now().Add(shortTimeout)
	var last error
	for time.Now().Before(deadline) {
		out, err := kubectlTry(shortTimeout, "-n", systemNS, "exec", pod, "--", "bash", "-c", script)
		if err == nil {
			if v, ok := parseMetric(out, metric); ok {
				return v
			}
			last = fmt.Errorf("metric %s not found in:\n%s", metric, out)
		} else {
			last = err
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("scrape %s: %v", metric, last)
	return 0
}

func parseMetric(body, metric string) (uint64, bool) {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(metric) + `\s+(\d+)\s*$`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// --- pod state -------------------------------------------------------------

type podInfo struct {
	phase    string
	restarts int
}

func listPods(t *testing.T, ns string) map[string]podInfo {
	t.Helper()
	const jp = `jsonpath={range .items[*]}{.metadata.name}{"|"}{.status.phase}{"|"}{range .status.containerStatuses[*]}{.restartCount}{","}{end}{"\n"}{end}`
	out := kubectl(t, "-n", ns, "get", "pods", "-o", jp)
	res := map[string]podInfo{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		f := strings.SplitN(line, "|", 3)
		if len(f) < 2 {
			continue
		}
		pi := podInfo{phase: f[1]}
		if len(f) == 3 {
			for _, r := range strings.Split(f[2], ",") {
				if r == "" {
					continue
				}
				n, _ := strconv.Atoi(r)
				pi.restarts += n
			}
		}
		res[f[0]] = pi
	}
	return res
}

func podPhase(ns, name string) (string, error) {
	out, err := kubectlTry(shortTimeout, "-n", ns, "get", "pod", name, "-o", "jsonpath={.status.phase}")
	return strings.TrimSpace(out), err
}

func waitPodPhase(t *testing.T, ns, name, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		ph, _ := podPhase(ns, name)
		last = ph
		if ph == want {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Errorf("pod %s/%s phase = %q, want %q within %s", ns, name, last, want, timeout)
}

// waitBenignReady waits for every pod in ns to reach Ready, retrying so pods
// created by the benign Deployments are picked up as they appear.
func waitBenignReady(t *testing.T, ns string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		out, err := kubectlTry(kubectlTimeout, "-n", ns, "wait", "--for=condition=Ready", "pod", "--all", "--timeout=30s")
		if err == nil {
			return
		}
		last = strings.TrimSpace(out + " " + err.Error())
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("benign pods in %s not Ready within %s (last: %q)", ns, timeout, last)
}

func waitAttackersStarted(t *testing.T, ns string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for _, a := range attackers {
		var last string
		started := false
		for time.Now().Before(deadline) {
			ph, _ := podPhase(ns, a)
			last = ph
			if ph == "Running" || ph == "Succeeded" || ph == "Failed" {
				started = true
				break
			}
			time.Sleep(2 * time.Second)
		}
		if !started {
			t.Fatalf("attacker %s did not start (phase %q)", a, last)
		}
	}
}

// assertUndisturbed fails if any pod not in exclude is Failed or has more
// restarts than its baseline (new pods have an implicit baseline of 0).
func assertUndisturbed(t *testing.T, ns string, baseline map[string]podInfo, exclude map[string]bool) {
	t.Helper()
	for name, info := range listPods(t, ns) {
		if exclude[name] {
			continue
		}
		if info.phase == "Failed" {
			t.Errorf("%s/%s is Failed; enforcement disturbed a non-attacker pod", ns, name)
		}
		if info.restarts > baseline[name].restarts {
			t.Errorf("%s/%s restarts rose %d -> %d; enforcement disturbed a non-attacker pod",
				ns, name, baseline[name].restarts, info.restarts)
		}
	}
}

func attackerSet() map[string]bool {
	s := map[string]bool{}
	for _, a := range attackers {
		s[a] = true
	}
	return s
}

// --- namespace lifecycle ---------------------------------------------------

func recreateNamespace(t *testing.T, ns string) {
	t.Helper()
	_, _ = kubectlTry(kubectlTimeout, "delete", "namespace", ns, "--ignore-not-found", "--wait=true", "--timeout=120s")
	waitNamespaceGone(t, ns, 3*time.Minute)
	kubectl(t, "create", "namespace", ns)
}

func waitNamespaceGone(t *testing.T, ns string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := kubectlTry(shortTimeout, "get", "namespace", ns, "-o", "jsonpath={.status.phase}"); err != nil {
			return // not found: gone
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("namespace %s still present after %s", ns, timeout)
}

func waitDaemonSetReady(t *testing.T, ns, name string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		out, err := kubectlTry(shortTimeout, "-n", ns, "get", "ds", name, "-o",
			"jsonpath={.status.numberReady}/{.status.desiredNumberScheduled}")
		if err == nil {
			last = strings.TrimSpace(out)
			p := strings.SplitN(last, "/", 2)
			if len(p) == 2 && p[0] == p[1] && p[0] != "" && p[0] != "0" {
				return
			}
		} else {
			last = err.Error()
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("daemonset %s/%s not ready within %s (last ready/desired: %q)", ns, name, timeout, last)
}

// --- artifacts -------------------------------------------------------------

func artifactsDir(t *testing.T, mode string) string {
	t.Helper()
	base := os.Getenv("STATEWALL_E2E_ARTIFACTS")
	if base == "" {
		base = t.TempDir()
	}
	dir := filepath.Join(base, mode)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir artifacts: %v", err)
	}
	return dir
}

// dumpArtifacts captures pod logs, events, attack-pod descriptions and the SW_*
// map dumps before teardown. Best-effort: dump failures are logged, not fatal.
func dumpArtifacts(t *testing.T, dir string) {
	t.Helper()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Logf("write %s: %v", name, err)
		}
	}
	if pod, err := kubectlTry(shortTimeout, "-n", systemNS, "get", "pods", "-l", agentLabel, "-o", "jsonpath={.items[0].metadata.name}"); err == nil {
		if name := strings.TrimSpace(pod); name != "" {
			if logs, err := kubectlTry(kubectlTimeout, "-n", systemNS, "logs", name); err == nil {
				write("agent.log", logs)
			}
		}
	}
	if ev, err := kubectlTry(kubectlTimeout, "-n", evalNS, "get", "events", "--sort-by=.lastTimestamp"); err == nil {
		write("events.txt", ev)
	}
	for _, a := range attackers {
		if d, err := kubectlTry(kubectlTimeout, "-n", evalNS, "describe", "pod", a); err == nil {
			write("describe-"+a+".txt", d)
		}
	}
	for _, m := range swMaps {
		if out, err := runTry(shortTimeout, "sudo", "-n", "bpftool", "map", "dump", "name", m, "-j"); err == nil {
			write(m+".json", out)
		}
	}
	t.Logf("artifacts written to %s", dir)
}

// --- helpers ---------------------------------------------------------------

func attackSeconds() time.Duration {
	return time.Duration(envInt("STATEWALL_E2E_ATTACK_SECONDS", 30)) * time.Second
}

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
