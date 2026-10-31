//go:build linux

package metricmap

import (
	"context"
	"fmt"
	"sort"

	"github.com/cilium/ebpf"

	"github.com/CosminMilica/ariguard/agent/internal/audit"
	"github.com/CosminMilica/ariguard/agent/internal/metrics"
	"github.com/CosminMilica/ariguard/agent/internal/podmeta"
	"github.com/CosminMilica/ariguard/pkg/fsm"
)

// Reader reads AG_METRICS, summing the per-CPU values. Pods, State, Names and
// Resolver are optional and enable the per-workload state gauge.
type Reader struct {
	M        *ebpf.Map
	Pods     *ebpf.Map
	State    *ebpf.Map
	Names    *audit.Names
	Resolver audit.Pods
	Node     string
}

func (r Reader) Read() (metrics.Counters, error) {
	var out [fsm.NumMetrics]uint64
	for i := range out {
		var percpu []uint64
		if err := r.M.Lookup(uint32(i), &percpu); err != nil {
			return metrics.Counters{}, fmt.Errorf("read AG_METRICS[%d]: %w", i, err)
		}
		for _, v := range percpu {
			out[i] += v
		}
	}
	return metrics.Counters{
		Events:       out[fsm.MetricEvents],
		Kills:        out[fsm.MetricKills],
		Denies:       out[fsm.MetricDenies],
		AuditDropped: out[fsm.MetricAuditDropped],
	}, nil
}

// Workloads joins AG_PODS with the cgroup-scoped entries of AG_STATE. It is
// empty unless Pods, State, Names and Resolver are set.
func (r Reader) Workloads() ([]metrics.Workload, error) {
	if r.Pods == nil || r.State == nil {
		return nil, nil
	}
	enrolled := map[uint64]bool{}
	var cg uint64
	var mark uint8
	it := r.Pods.Iterate()
	for it.Next(&cg, &mark) {
		enrolled[cg] = true
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate AG_PODS: %w", err)
	}

	var rules []fsm.RuleMeta
	if m := r.Names.Load(); m != nil {
		rules = m.Rules
	}
	seen := map[uint64]bool{}
	var out []metrics.Workload
	ctx := context.Background()
	info := func(id uint64) podmeta.Info {
		if r.Resolver == nil {
			return podmeta.Info{}
		}
		return r.Resolver.Lookup(ctx, id)
	}
	comm := func(id uint64, pi podmeta.Info) string {
		if c, ok := r.Names.Comm(id); ok {
			return c
		}
		return pi.Container
	}
	var key fsm.FsmKey
	var st fsm.FsmState
	sit := r.State.Iterate()
	for sit.Next(&key, &st) {
		if !enrolled[key.ID] || int(key.Rule) >= len(rules) || rules[key.Rule].Scope != "cgroup" {
			continue
		}
		seen[key.ID] = true
		pi := info(key.ID)
		out = append(out, metrics.Workload{Pod: pi.Pod, Namespace: pi.Namespace, Node: r.Node, Comm: comm(key.ID, pi), Rule: rules[key.Rule].Name, State: st.State})
	}
	if err := sit.Err(); err != nil {
		return nil, fmt.Errorf("iterate AG_STATE: %w", err)
	}
	for id := range enrolled {
		if !seen[id] {
			pi := info(id)
			out = append(out, metrics.Workload{Pod: pi.Pod, Namespace: pi.Namespace, Node: r.Node, Comm: comm(id, pi)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Pod != b.Pod {
			return a.Pod < b.Pod
		}
		return a.Rule < b.Rule
	})
	return out, nil
}
