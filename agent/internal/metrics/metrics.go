// Package metrics exposes the SW_METRICS counters in Prometheus text format.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Counters are the cluster-visible totals summed across CPUs.
type Counters struct {
	Events       uint64
	Kills        uint64
	AuditDropped uint64
}

// Reader returns the current counters.
type Reader interface {
	Read() (Counters, error)
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
		_, _ = fmt.Fprint(w, Format(c))
	})
}

// Format renders c as Prometheus counters.
func Format(c Counters) string {
	var s string
	for _, m := range []struct {
		name, help string
		v          uint64
	}{
		{"statewall_events_total", "Syscall events that matched a policy binding.", c.Events},
		{"statewall_kills_total", "Processes killed by enforcement.", c.Kills},
		{"statewall_audit_dropped_total", "Audit records dropped because the ring buffer was full.", c.AuditDropped},
	} {
		s += fmt.Sprintf("# HELP %s %s\n# TYPE %s counter\n%s %d\n", m.name, m.help, m.name, m.name, m.v)
	}
	return s
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
