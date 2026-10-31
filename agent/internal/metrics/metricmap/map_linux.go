//go:build linux

package metricmap

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/CosminMilica/statewall/agent/internal/metrics"
	"github.com/CosminMilica/statewall/pkg/fsm"
)

// Reader reads SW_METRICS, summing the per-CPU values.
type Reader struct{ M *ebpf.Map }

func (r Reader) Read() (metrics.Counters, error) {
	var out [fsm.NumMetrics]uint64
	for i := range out {
		var percpu []uint64
		if err := r.M.Lookup(uint32(i), &percpu); err != nil {
			return metrics.Counters{}, fmt.Errorf("read SW_METRICS[%d]: %w", i, err)
		}
		for _, v := range percpu {
			out[i] += v
		}
	}
	return metrics.Counters{
		Events:       out[fsm.MetricEvents],
		Kills:        out[fsm.MetricKills],
		AuditDropped: out[fsm.MetricAuditDropped],
	}, nil
}
