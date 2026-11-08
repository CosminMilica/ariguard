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
	"strings"
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

// Fallback selects an extra action for CNIs that don't enforce NetworkPolicy (e.g. kindnet):
// the deny-all policy object is created but ignored, so network isolation needs another lever.
type Fallback int

const (
	FallbackOff   Fallback = iota // trust NetworkPolicy to isolate (default)
	FallbackEvict                 // also delete the pod, so its network connections are cut now
)

// ParseFallback maps the --isolate-fallback flag value to a Fallback.
func ParseFallback(s string) (Fallback, error) {
	switch s {
	case "", "off", "none":
		return FallbackOff, nil
	case "evict", "delete":
		return FallbackEvict, nil
	default:
		return FallbackOff, fmt.Errorf("invalid isolate fallback %q (want off|evict)", s)
	}
}

func (f Fallback) String() string {
	if f == FallbackEvict {
		return "evict"
	}
	return "off"
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
	client    kubernetes.Interface
	mode      Mode
	fallback  Fallback
	muted     func(pod string) bool
	observeNs func(ns string) bool             // observe-only namespaces: never quarantined
	report    func(ns, pod, rule, mode string) // optional: notify the console of a quarantine
	release   func(ns, pod string)             // optional: notify the console of a release
	log       *slog.Logger

	mu   sync.Mutex
	seen map[string]bool // namespace/pod already quarantined (idempotent)
}

// New returns a Responder, or nil when mode is off (the stream then skips reaction entirely).
// report and release, when non-nil, are called after a successful quarantine / release (e.g. to
// tell the console). observeNs, when non-nil, marks namespaces that are detected but never
// quarantined (an already-isolated pod in one is released, like a mute).
func New(client kubernetes.Interface, mode Mode, fallback Fallback, muted func(string) bool, observeNs func(string) bool, report func(ns, pod, rule, mode string), release func(ns, pod string), log *slog.Logger) *Responder {
	if mode == ModeOff || client == nil {
		return nil
	}
	return &Responder{client: client, mode: mode, fallback: fallback, muted: muted, observeNs: observeNs, report: report, release: release, log: log, seen: map[string]bool{}}
}

// isMuted reports whether the "namespace/pod" workload is muted (C4: mutes are namespace-scoped, so
// two pods with the same name in different namespaces do not share a mute).
func (r *Responder) isMuted(ns, pod string) bool {
	return r.muted != nil && r.muted(ns+"/"+pod)
}
func (r *Responder) isObserved(ns string) bool { return r.observeNs != nil && r.observeNs(ns) }

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
	if r.isMuted(e.Namespace, e.Pod) || r.isObserved(e.Namespace) {
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
		if r.report != nil {
			r.report(ns, pod, rule, r.mode.String())
		}
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
	if err := r.ensureDenyAll(ctx, ns); err != nil {
		return err
	}
	if r.fallback == FallbackEvict {
		if err := r.evict(ctx, ns, pod); err != nil {
			return fmt.Errorf("evict pod: %w", err)
		}
		r.log.Info("quarantined pod evicted (NetworkPolicy fallback)", "pod", ns+"/"+pod)
	}
	return nil
}

// evict deletes the pod so its network connections are cut immediately, for CNIs that ignore the
// deny-all NetworkPolicy. A controller-managed pod is recreated clean; if it re-offends the kernel
// kill fires again. An already-gone pod is treated as success.
func (r *Responder) evict(ctx context.Context, ns, pod string) error {
	err := r.client.CoreV1().Pods(ns).Delete(ctx, pod, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
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

// ReleaseLoop periodically un-quarantines pods the operator has muted, making isolation
// reversible: the mute list is the single operator lever (no kill, no quarantine, and release of
// an already-isolated pod). It runs until ctx is done. A nil Responder is a no-op.
func (r *Responder) ReleaseLoop(ctx context.Context, interval time.Duration) {
	if r == nil || (r.muted == nil && r.observeNs == nil) {
		return
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			r.reconcileReleases(ctx)
		}
	}
}

// reconcileReleases releases every quarantined pod that is now muted.
func (r *Responder) reconcileReleases(ctx context.Context) {
	r.mu.Lock()
	var toRelease []string
	for key := range r.seen {
		ns, pod, ok := splitKey(key)
		if ok && (r.isMuted(ns, pod) || r.isObserved(ns)) {
			toRelease = append(toRelease, key)
		}
	}
	r.mu.Unlock()

	for _, key := range toRelease {
		ns, pod, _ := splitKey(key)
		bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), apiTimeout)
		err := r.doRelease(bg, ns, pod)
		cancel()
		if err != nil {
			r.log.Warn("release failed", "pod", key, "err", err)
			continue
		}
		r.mu.Lock()
		delete(r.seen, key)
		r.mu.Unlock()
		r.log.Info("workload released", "pod", key)
		if r.release != nil {
			r.release(ns, pod)
		}
	}
}

// doRelease removes the quarantine label and annotations so the pod drops out of the deny-all
// NetworkPolicy's selector. The namespace policy is left in place (it only affects labeled pods).
// An already-gone pod (e.g. evicted) is treated as released.
func (r *Responder) doRelease(ctx context.Context, ns, pod string) error {
	patch := fmt.Sprintf(
		`{"metadata":{"labels":{%q:null},"annotations":{%q:null,%q:null}}}`,
		QuarantineLabel, ruleAnnotation, atAnnotation,
	)
	_, err := r.client.CoreV1().Pods(ns).Patch(ctx, pod, types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

// splitKey splits a "namespace/pod" seen-key.
func splitKey(key string) (ns, pod string, ok bool) {
	i := strings.IndexByte(key, '/')
	if i < 0 {
		return "", "", false
	}
	return key[:i], key[i+1:], true
}
