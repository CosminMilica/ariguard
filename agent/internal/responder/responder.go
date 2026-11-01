// Package responder performs autonomous workload isolation: when the data plane confirms a
// terminal mitigation (an enforced kill or deny) for a pod, the product quarantines that pod so
// a compromise cannot spread, without an operator in the loop. Isolation cuts the blast radius
// (a deny-all NetworkPolicy) and labels the pod, leaving it in place for investigation rather
// than deleting it.
package responder

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	netv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/CosminMilica/ariguard/agent/internal/audit"
)

// Mode selects how far isolation goes.
type Mode int

const (
	ModeOff    Mode = iota // no isolation
	ModeDryRun             // label the pod only, apply no NetworkPolicy (observe the decision)
	ModeOn                 // label + apply a deny-all NetworkPolicy
)

// ParseMode maps the --isolate flag value to a Mode.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "", "off":
		return ModeOff, nil
	case "dryrun", "dry-run":
		return ModeDryRun, nil
	case "on", "enforce":
		return ModeOn, nil
	default:
		return ModeOff, fmt.Errorf("invalid isolate mode %q (want off|dryrun|on)", s)
	}
}

func (m Mode) String() string {
	switch m {
	case ModeDryRun:
		return "dryrun"
	case ModeOn:
		return "on"
	default:
		return "off"
	}
}

const (
	// QuarantineLabel marks an isolated pod and is the NetworkPolicy's podSelector.
	QuarantineLabel = "ariguard.io/quarantine"
	ruleAnnotation  = "ariguard.io/quarantine-rule"
	atAnnotation    = "ariguard.io/quarantined-at"
	netpolName      = "ariguard-quarantine"
	apiTimeout      = 10 * time.Second
)

// systemNamespaces are never auto-isolated (the node's own control plane and AriGuard itself).
var systemNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
	"ariguard-system": true,
}

// Responder isolates pods on confirmed terminal mitigations. Safe for concurrent use.
type Responder struct {
	client kubernetes.Interface
	mode   Mode
	muted  func(pod string) bool
	log    *slog.Logger

	mu   sync.Mutex
	seen map[string]bool // namespace/pod already quarantined (idempotent)
}

// New returns a Responder, or nil when mode is off (the stream then skips reaction entirely).
func New(client kubernetes.Interface, mode Mode, muted func(string) bool, log *slog.Logger) *Responder {
	if mode == ModeOff || client == nil {
		return nil
	}
	return &Responder{client: client, mode: mode, muted: muted, log: log, seen: map[string]bool{}}
}

// React quarantines the pod behind a confirmed terminal mitigation. It returns immediately and
// does the API calls in the background so it never blocks the audit drain.
func (r *Responder) React(ctx context.Context, e audit.Event) {
	if r == nil {
		return
	}
	if !e.Enforced || (e.Action != "kill" && e.Action != "deny") {
		return
	}
	if e.Pod == "" || e.Namespace == "" || systemNamespaces[e.Namespace] {
		return
	}
	if r.muted != nil && r.muted(e.Pod) {
		return
	}
	key := e.Namespace + "/" + e.Pod
	r.mu.Lock()
	if r.seen[key] {
		r.mu.Unlock()
		return
	}
	r.seen[key] = true
	r.mu.Unlock()

	go func(ns, pod, rule string) {
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), apiTimeout)
		defer cancel()
		if err := r.quarantine(bg, ns, pod, rule); err != nil {
			r.log.Warn("quarantine failed", "pod", key, "err", err)
			r.mu.Lock()
			delete(r.seen, key) // allow a later event to retry
			r.mu.Unlock()
			return
		}
		r.log.Info("workload quarantined", "pod", key, "rule", rule, "mode", r.mode.String())
	}(e.Namespace, e.Pod, e.Rule)
}

// quarantine labels the pod (both modes) and, in ModeOn, ensures a deny-all NetworkPolicy that
// selects quarantined pods in the namespace.
func (r *Responder) quarantine(ctx context.Context, ns, pod, rule string) error {
	patch := fmt.Sprintf(
		`{"metadata":{"labels":{%q:"true"},"annotations":{%q:%q,%q:%q}}}`,
		QuarantineLabel, ruleAnnotation, rule, atAnnotation, time.Now().UTC().Format(time.RFC3339),
	)
	if _, err := r.client.CoreV1().Pods(ns).Patch(ctx, pod, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("label pod: %w", err)
	}
	if r.mode == ModeDryRun {
		return nil
	}
	return r.ensureDenyAll(ctx, ns)
}

// ensureDenyAll creates the namespace's deny-all NetworkPolicy (ingress + egress) targeting
// quarantined pods, idempotently.
func (r *Responder) ensureDenyAll(ctx context.Context, ns string) error {
	np := &netv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      netpolName,
			Namespace: ns,
			Labels:    map[string]string{"app.kubernetes.io/managed-by": "ariguard"},
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{QuarantineLabel: "true"}},
			// No ingress and no egress rules with both policy types selected = deny all traffic.
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress, netv1.PolicyTypeEgress},
		},
	}
	_, err := r.client.NetworkingV1().NetworkPolicies(ns).Create(ctx, np, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("create deny-all NetworkPolicy: %w", err)
	}
	return nil
}
