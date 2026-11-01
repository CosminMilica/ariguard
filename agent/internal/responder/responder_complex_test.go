package responder

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/CosminMilica/ariguard/agent/internal/audit"
)

func deny(ns, pod string) audit.Event {
	return audit.Event{Namespace: ns, Pod: pod, Action: "deny", Enforced: true, Rule: "container-escape"}
}

// An enforced deny (not only a kill) must also quarantine.
func TestReactDenyAlsoQuarantines(t *testing.T) {
	c := fake.NewSimpleClientset(newPod("ariguard-eval", "esc"))
	New(c, ModeOn, nil, nil, quiet).React(context.Background(), deny("ariguard-eval", "esc"))
	waitLabeled(t, c, "ariguard-eval", "esc")
}

// Quarantine must preserve the pod's existing labels, only adding the marker.
func TestReactPreservesExistingLabels(t *testing.T) {
	pod := newPod("ariguard-eval", "attacker")
	pod.Labels = map[string]string{"app": "attacker", "team": "sec"}
	c := fake.NewSimpleClientset(pod)
	New(c, ModeOn, nil, nil, quiet).React(context.Background(), kill("ariguard-eval", "attacker"))
	waitLabeled(t, c, "ariguard-eval", "attacker")
	p, _ := c.CoreV1().Pods("ariguard-eval").Get(context.Background(), "attacker", metav1.GetOptions{})
	if p.Labels["app"] != "attacker" || p.Labels["team"] != "sec" {
		t.Errorf("existing labels lost: %v", p.Labels)
	}
	if p.Annotations[ruleAnnotation] != "reverse-shell" || p.Annotations[atAnnotation] == "" {
		t.Errorf("quarantine annotations missing: %v", p.Annotations)
	}
}

// The deny-all NetworkPolicy must select quarantined pods and allow nothing in either direction.
func TestNetworkPolicySpec(t *testing.T) {
	c := fake.NewSimpleClientset(newPod("ariguard-eval", "attacker"))
	New(c, ModeOn, nil, nil, quiet).React(context.Background(), kill("ariguard-eval", "attacker"))
	waitLabeled(t, c, "ariguard-eval", "attacker")
	np, err := c.NetworkingV1().NetworkPolicies("ariguard-eval").Get(context.Background(), netpolName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get netpol: %v", err)
	}
	if np.Spec.PodSelector.MatchLabels[QuarantineLabel] != "true" {
		t.Errorf("podSelector = %v, want %s=true", np.Spec.PodSelector.MatchLabels, QuarantineLabel)
	}
	if len(np.Spec.PolicyTypes) != 2 {
		t.Errorf("policyTypes = %v, want [Ingress Egress]", np.Spec.PolicyTypes)
	}
	if len(np.Spec.Ingress) != 0 || len(np.Spec.Egress) != 0 {
		t.Errorf("deny-all must have no ingress/egress rules, got ingress=%d egress=%d", len(np.Spec.Ingress), len(np.Spec.Egress))
	}
}

// The report callback fires once, after a successful quarantine, with the right fields.
func TestReactReportsOnSuccess(t *testing.T) {
	c := fake.NewSimpleClientset(newPod("ariguard-eval", "attacker"))
	var mu sync.Mutex
	var got []string
	report := func(ns, pod, rule, mode string) {
		mu.Lock()
		got = append(got, fmt.Sprintf("%s/%s/%s/%s", ns, pod, rule, mode))
		mu.Unlock()
	}
	r := New(c, ModeOn, nil, report, quiet)
	for i := 0; i < 3; i++ {
		r.React(context.Background(), kill("ariguard-eval", "attacker"))
	}
	waitLabeled(t, c, "ariguard-eval", "attacker")
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("report called %d times, want 1 (idempotent): %v", len(got), got)
	}
	if got[0] != "ariguard-eval/attacker/reverse-shell/on" {
		t.Errorf("report args = %q", got[0])
	}
}

// A transient API failure must not mark the pod as handled: a later event retries and succeeds.
func TestReactRetriesAfterFailure(t *testing.T) {
	c := fake.NewSimpleClientset(newPod("ariguard-eval", "attacker"))
	var calls int32
	c.PrependReactor("patch", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return true, nil, fmt.Errorf("transient API error")
		}
		return false, nil, nil // subsequent calls fall through to the default (success)
	})
	r := New(c, ModeOn, nil, nil, quiet)

	r.React(context.Background(), kill("ariguard-eval", "attacker"))
	// After the failed attempt the pod must be eligible again (seen cleared).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		empty := len(r.seen) == 0
		r.mu.Unlock()
		if empty {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.mu.Lock()
	n := len(r.seen)
	r.mu.Unlock()
	if n != 0 {
		t.Fatalf("after a failed quarantine seen=%d, want 0 (retryable)", n)
	}

	r.React(context.Background(), kill("ariguard-eval", "attacker"))
	waitLabeled(t, c, "ariguard-eval", "attacker")
}

// Concurrent events on the same and different pods stay idempotent and race-free (go test -race).
func TestReactConcurrent(t *testing.T) {
	pods := []string{"a", "b", "c", "d", "e"}
	objs := make([]runtime.Object, len(pods))
	for i, p := range pods {
		objs[i] = newPod("ariguard-eval", p)
	}
	c := fake.NewSimpleClientset(objs...)
	r := New(c, ModeOn, nil, nil, quiet)

	var wg sync.WaitGroup
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r.React(context.Background(), kill("ariguard-eval", pods[i%len(pods)]))
		}(i)
	}
	wg.Wait()

	for _, p := range pods {
		waitLabeled(t, c, "ariguard-eval", p)
	}
	r.mu.Lock()
	n := len(r.seen)
	r.mu.Unlock()
	if n != len(pods) {
		t.Errorf("seen=%d, want %d (one entry per distinct pod)", n, len(pods))
	}
}

// Pods in different namespaces are each isolated, with a deny-all NetworkPolicy per namespace.
func TestReactMultipleNamespaces(t *testing.T) {
	c := fake.NewSimpleClientset(
		newPod("ns-a", "attacker"), newPod("ns-a", "attacker2"), newPod("ns-b", "attacker"),
	)
	r := New(c, ModeOn, nil, nil, quiet)
	r.React(context.Background(), kill("ns-a", "attacker"))
	r.React(context.Background(), kill("ns-a", "attacker2"))
	r.React(context.Background(), kill("ns-b", "attacker"))
	waitLabeled(t, c, "ns-a", "attacker")
	waitLabeled(t, c, "ns-a", "attacker2")
	waitLabeled(t, c, "ns-b", "attacker")
	for _, ns := range []string{"ns-a", "ns-b"} {
		if _, err := c.NetworkingV1().NetworkPolicies(ns).Get(context.Background(), netpolName, metav1.GetOptions{}); err != nil {
			t.Errorf("namespace %s missing deny-all NetworkPolicy: %v", ns, err)
		}
	}
}
