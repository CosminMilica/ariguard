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

func TestNewOffIsNil(t *testing.T) {
	if r := New(fake.NewSimpleClientset(), ModeOff, nil, nil, quiet); r != nil {
		t.Error("New with ModeOff should return nil")
	}
	if r := New(nil, ModeOn, nil, nil, quiet); r != nil {
		t.Error("New with nil client should return nil")
	}
}

func TestReactOnQuarantines(t *testing.T) {
	c := fake.NewSimpleClientset(newPod("ariguard-eval", "attacker"))
	r := New(c, ModeOn, nil, nil, quiet)
	r.React(context.Background(), kill("ariguard-eval", "attacker"))
	waitLabeled(t, c, "ariguard-eval", "attacker")
	if !hasNetpol(c, "ariguard-eval") {
		t.Error("ModeOn should create the deny-all NetworkPolicy")
	}
}

func TestReactDryRunLabelsButNoNetpol(t *testing.T) {
	c := fake.NewSimpleClientset(newPod("ariguard-eval", "attacker"))
	r := New(c, ModeDryRun, nil, nil, quiet)
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
			r := New(c, ModeOn, nil, nil, quiet)
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
	r := New(c, ModeOn, func(pod string) bool { return pod == "muted" }, nil, quiet)
	r.React(context.Background(), kill("ariguard-eval", "muted"))
	time.Sleep(100 * time.Millisecond)
	if p, _ := c.CoreV1().Pods("ariguard-eval").Get(context.Background(), "muted", metav1.GetOptions{}); p.Labels[QuarantineLabel] != "" {
		t.Error("a muted pod must not be quarantined")
	}
}

func TestReactIdempotent(t *testing.T) {
	c := fake.NewSimpleClientset(newPod("ariguard-eval", "attacker"))
	r := New(c, ModeOn, nil, nil, quiet)
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
