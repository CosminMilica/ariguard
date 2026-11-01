// Package metrics exposes the AG_METRICS counters in Prometheus text format.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Counters are the cluster-visible totals summed across CPUs.
type Counters struct {
	Events       uint64
	Kills        uint64
	Denies       uint64
	AuditDropped uint64
}

// Reader returns the current counters.
type Reader interface {
	Read() (Counters, error)
}

// MaxStateIndex is the highest value reported by ariguard_workload_state.
const MaxStateIndex = 4

// Workload is the FSM state of one enrolled pod under one rule.
type Workload struct {
	Pod, Namespace, Node, Comm, Rule string
	State                            uint32
}

// WorkloadReader is implemented by a Reader that can also list workload states.
type WorkloadReader interface {
	Workloads() ([]Workload, error)
}

// ProgramStat is the run-time accounting of one loaded ariguard BPF program.
type ProgramStat struct {
	Name      string
	Runs      uint64
	RuntimeNs uint64
}

// ProgramReader is implemented by a Reader that can also list per-program BPF
// run-time stats. An empty result (BPF statistics disabled) omits the rows.
type ProgramReader interface {
	Programs() ([]ProgramStat, error)
}

// MemoryReader is implemented by a Reader that knows the constant pre-allocated
// BPF map byte budget.
type MemoryReader interface {
	MapBytes() uint64
}

// Handler serves r at any path in Prometheus text exposition format.
func Handler(r Reader) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		c, err := r.Read()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		out := Format(c)
		if wr, ok := r.(WorkloadReader); ok {
			ws, err := wr.Workloads()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			out += FormatWorkloads(ws)
		}
		if mr, ok := r.(MemoryReader); ok {
			out += FormatMemory(mr.MapBytes())
		}
		if pr, ok := r.(ProgramReader); ok {
			ps, err := pr.Programs()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			out += FormatPrograms(ps)
		}
		_, _ = fmt.Fprint(w, out)
	})
}

// Format renders c as Prometheus counters.
func Format(c Counters) string {
	var s string
	for _, m := range []struct {
		name, help string
		v          uint64
	}{
		{"ariguard_events_total", "Syscall events that matched a policy binding.", c.Events},
		{"ariguard_kills_total", "Processes killed by enforcement.", c.Kills},
		{"ariguard_denies_total", "Operations denied (-EPERM) by enforcement.", c.Denies},
		{"ariguard_audit_dropped_total", "Audit records dropped because the ring buffer was full.", c.AuditDropped},
	} {
		s += fmt.Sprintf("# HELP %s %s\n# TYPE %s counter\n%s %d\n", m.name, m.help, m.name, m.name, m.v)
	}
	return s
}

// FormatWorkloads renders ws as the ariguard_workload_state gauge; state indices above MaxStateIndex are clamped.
func FormatWorkloads(ws []Workload) string {
	var b strings.Builder
	b.WriteString("# HELP ariguard_workload_state FSM state of an enrolled workload (0 normal, 1 suspicious, 2 escalating, 3 breakout_imminent, 4 compromised).\n# TYPE ariguard_workload_state gauge\n")
	for _, w := range ws {
		fmt.Fprintf(&b, "ariguard_workload_state{pod=%q,namespace=%q,node=%q,comm=%q,rule=%q} %d\n",
			w.Pod, w.Namespace, w.Node, w.Comm, w.Rule, min(w.State, MaxStateIndex))
	}
	return b.String()
}

// FormatMemory renders the constant pre-allocated BPF map budget as a gauge.
func FormatMemory(bytes uint64) string {
	return fmt.Sprintf("# HELP ariguard_bpf_map_bytes Constant pre-allocated byte budget of the AG_* BPF maps.\n# TYPE ariguard_bpf_map_bytes gauge\nariguard_bpf_map_bytes %d\n", bytes)
}

// FormatPrograms renders ps as per-program BPF run-time counters. An empty slice
// renders nothing, so the rows are omitted when BPF statistics are disabled.
func FormatPrograms(ps []ProgramStat) string {
	if len(ps) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("# HELP ariguard_program_run_time_ns_total Cumulative BPF run time of an ariguard program in nanoseconds.\n# TYPE ariguard_program_run_time_ns_total counter\n")
	for _, p := range ps {
		fmt.Fprintf(&b, "ariguard_program_run_time_ns_total{program=%q} %d\n", p.Name, p.RuntimeNs)
	}
	b.WriteString("# HELP ariguard_program_runs_total Number of times an ariguard program ran.\n# TYPE ariguard_program_runs_total counter\n")
	for _, p := range ps {
		fmt.Fprintf(&b, "ariguard_program_runs_total{program=%q} %d\n", p.Name, p.Runs)
	}
	return b.String()
}

// Serve serves /metrics on addr until ctx is done, then shuts down gracefully.
func Serve(ctx context.Context, addr string, r Reader) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return serve(ctx, ln, r)
}

func serve(ctx context.Context, ln net.Listener, r Reader) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", Handler(r))
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		<-done
		return nil
	}
	return err
}
