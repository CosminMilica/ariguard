package responder

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/CosminMilica/ariguard/agent/internal/audit"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func kill(ns, pod string) audit.Event {
	return audit.Event{Namespace: ns, Pod: pod, Action: "kill", Enforced: true, Rule: "reverse-shell"}
}

func newPod(ns, pod string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: pod, Namespace: ns}}
}

// waitLabeled polls until the pod carries the quarantine label, or fails after timeout.
func waitLabeled(t *testing.T, c *fake.Clientset, ns, pod string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p, err := c.CoreV1().Pods(ns).Get(context.Background(), pod, metav1.GetOptions{})
		if err == nil && p.Labels[QuarantineLabel] == "true" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pod %s/%s not labeled %s within timeout", ns, pod, QuarantineLabel)
}

func hasNetpol(c *fake.Clientset, ns string) bool {
	_, err := c.NetworkingV1().NetworkPolicies(ns).Get(context.Background(), netpolName, metav1.GetOptions{})
	return err == nil
}

func TestParseMode(t *testing.T) {
	cases := map[string]Mode{"": ModeOff, "off": ModeOff, "dryrun": ModeDryRun, "dry-run": ModeDryRun, "on": ModeOn, "enforce": ModeOn}
	for in, want := range cases {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseMode("bogus"); err == nil {
		t.Error("ParseMode(bogus) should error")
	}
}

func TestParseFallback(t *testing.T) {
	cases := map[string]Fallback{"": FallbackOff, "off": FallbackOff, "none": FallbackOff, "evict": FallbackEvict, "delete": FallbackEvict}
	for in, want := range cases {
		if got, err := ParseFallback(in); err != nil || got != want {
			t.Errorf("ParseFallback(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseFallback("bogus"); err == nil {
		t.Error("ParseFallback(bogus) should error")
	}
}

func TestEvictFallbackDeletesPod(t *testing.T) {
	c := fake.NewSimpleClientset(newPod("ariguard-eval", "attacker"))
	r := New(c, ModeOn, FallbackEvict, nil, nil, nil, nil, quiet)
	r.React(context.Background(), kill("ariguard-eval", "attacker"))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := c.CoreV1().Pods("ariguard-eval").Get(context.Background(), "attacker", metav1.GetOptions{}); apierrors.IsNotFound(err) {
			if !hasNetpol(c, "ariguard-eval") {
				t.Error("evict fallback should still create the deny-all NetworkPolicy")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("evict fallback should delete the quarantined pod")
}

func TestReleaseLoopUnquarantinesMutedPod(t *testing.T) {
	c := fake.NewSimpleClientset(newPod("ariguard-eval", "attacker"))
	var muted bool
	released := make(chan string, 1)
	r := New(c, ModeOn, FallbackOff, func(string) bool { return muted }, nil, nil,
		func(ns, pod string) { released <- ns + "/" + pod }, quiet)
	r.React(context.Background(), kill("ariguard-eval", "attacker"))
	waitLabeled(t, c, "ariguard-eval", "attacker")

	muted = true
	r.reconcileReleases(context.Background())

	p, err := c.CoreV1().Pods("ariguard-eval").Get(context.Background(), "attacker", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get pod: %v", err)
	}
	if p.Labels[QuarantineLabel] != "" {
		t.Error("released pod must not keep the quarantine label")
	}
	select {
	case got := <-released:
		if got != "ariguard-eval/attacker" {
			t.Errorf("release reported %q", got)
		}
	default:
		t.Error("release callback not fired")
	}
	r.mu.Lock()
	n := len(r.seen)
	r.mu.Unlock()
	if n != 0 {
		t.Errorf("seen has %d entries after release, want 0", n)
	}
}

func TestObserveNamespaceSkipsQuarantine(t *testing.T) {
	c := fake.NewSimpleClientset(newPod("ariguard-honeypot", "decoy"))
	r := New(c, ModeOn, FallbackOff, nil, func(ns string) bool { return ns == "ariguard-honeypot" }, nil, nil, quiet)
	r.React(context.Background(), kill("ariguard-honeypot", "decoy"))

	p, err := c.CoreV1().Pods("ariguard-honeypot").Get(context.Background(), "decoy", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get pod: %v", err)
	}
	if p.Labels[QuarantineLabel] != "" {
		t.Error("a pod in an observe-only namespace must not be quarantined")
	}
	r.mu.Lock()
	n := len(r.seen)
	r.mu.Unlock()
	if n != 0 {
		t.Errorf("observe-only namespace should not be tracked as quarantined, seen=%d", n)
	}
}

func TestReleaseLoopReleasesObservedNamespace(t *testing.T) {
	c := fake.NewSimpleClientset(newPod("ariguard-eval", "attacker"))
	var observe bool
	released := make(chan string, 1)
	r := New(c, ModeOn, FallbackOff, nil, func(string) bool { return observe }, nil,
		func(ns, pod string) { released <- ns + "/" + pod }, quiet)
	r.React(context.Background(), kill("ariguard-eval", "attacker"))
	waitLabeled(t, c, "ariguard-eval", "attacker")

	observe = true // the namespace is now observe-only -> the quarantined pod must be released
	r.reconcileReleases(context.Background())

	p, err := c.CoreV1().Pods("ariguard-eval").Get(context.Background(), "attacker", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get pod: %v", err)
	}
	if p.Labels[QuarantineLabel] != "" {
		t.Error("released pod must not keep the quarantine label")
	}
	select {
	case got := <-released:
		if got != "ariguard-eval/attacker" {
			t.Errorf("release reported %q", got)
		}
	default:
		t.Error("release callback not fired")
	}
}

func TestNewOffIsNil(t *testing.T) {
	if r := New(fake.NewSimpleClientset(), ModeOff, FallbackOff, nil, nil, nil, nil, quiet); r != nil {
		t.Error("New with ModeOff should return nil")
	}
	if r := New(nil, ModeOn, FallbackOff, nil, nil, nil, nil, quiet); r != nil {
		t.Error("New with nil client should return nil")
	}
}

func TestReactOnQuarantines(t *testing.T) {
	c := fake.NewSimpleClientset(newPod("ariguard-eval", "attacker"))
	r := New(c, ModeOn, FallbackOff, nil, nil, nil, nil, quiet)
	r.React(context.Background(), kill("ariguard-eval", "attacker"))
	waitLabeled(t, c, "ariguard-eval", "attacker")
	if !hasNetpol(c, "ariguard-eval") {
		t.Error("ModeOn should create the deny-all NetworkPolicy")
	}
}

func TestReactDryRunLabelsButNoNetpol(t *testing.T) {
	c := fake.NewSimpleClientset(newPod("ariguard-eval", "attacker"))
	r := New(c, ModeDryRun, FallbackOff, nil, nil, nil, nil, quiet)
	r.React(context.Background(), kill("ariguard-eval", "attacker"))
	waitLabeled(t, c, "ariguard-eval", "attacker")
	if hasNetpol(c, "ariguard-eval") {
		t.Error("ModeDryRun must not create a NetworkPolicy")
	}
}

func TestReactSkips(t *testing.T) {
	cases := []struct {
		name string
		ev   audit.Event
	}{
		{"not enforced", audit.Event{Namespace: "ariguard-eval", Pod: "a", Action: "kill", Enforced: false}},
		{"observe action", audit.Event{Namespace: "ariguard-eval", Pod: "a", Action: "observe", Enforced: true}},
		{"system namespace", kill("kube-system", "a")},
		{"empty pod", kill("ariguard-eval", "")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := fake.NewSimpleClientset(newPod(tc.ev.Namespace, "a"))
			r := New(c, ModeOn, FallbackOff, nil, nil, nil, nil, quiet)
			r.React(context.Background(), tc.ev)
			time.Sleep(100 * time.Millisecond)
			if p, err := c.CoreV1().Pods(tc.ev.Namespace).Get(context.Background(), "a", metav1.GetOptions{}); err == nil && p.Labels[QuarantineLabel] != "" {
				t.Errorf("%s: pod should not be quarantined", tc.name)
			}
		})
	}
}

func TestReactRespectsMute(t *testing.T) {
	c := fake.NewSimpleClientset(newPod("ariguard-eval", "muted"))
	r := New(c, ModeOn, FallbackOff, func(key string) bool { return key == "ariguard-eval/muted" }, nil, nil, nil, quiet)
	r.React(context.Background(), kill("ariguard-eval", "muted"))
	time.Sleep(100 * time.Millisecond)
	if p, _ := c.CoreV1().Pods("ariguard-eval").Get(context.Background(), "muted", metav1.GetOptions{}); p.Labels[QuarantineLabel] != "" {
		t.Error("a muted pod must not be quarantined")
	}
}

func TestReactIdempotent(t *testing.T) {
	c := fake.NewSimpleClientset(newPod("ariguard-eval", "attacker"))
	r := New(c, ModeOn, FallbackOff, nil, nil, nil, nil, quiet)
	for i := 0; i < 3; i++ {
		r.React(context.Background(), kill("ariguard-eval", "attacker"))
	}
	waitLabeled(t, c, "ariguard-eval", "attacker")
	if _, err := c.NetworkingV1().NetworkPolicies("ariguard-eval").Get(context.Background(), netpolName, metav1.GetOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			t.Fatal("NetworkPolicy missing")
		}
	}
	// the seen-set must have collapsed the repeats to a single quarantined pod
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.seen) != 1 {
		t.Errorf("seen has %d entries, want 1 (idempotent)", len(r.seen))
	}
}
