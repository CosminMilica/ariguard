//go:build linux

package ringbuf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"
	cringbuf "github.com/cilium/ebpf/ringbuf"

	"github.com/CosminMilica/ariguard/agent/internal/audit"
	"github.com/CosminMilica/ariguard/agent/internal/podmeta"
)

// Stream reads AG_AUDIT and writes one JSON line per record to w until ctx is done.
// Names are read per record, so a reload takes effect on the next line; pods may be nil.
func Stream(ctx context.Context, m, ppid *ebpf.Map, w io.Writer, names *audit.Names, pods audit.Pods, reactor audit.Reactor, log *slog.Logger) error {
	rd, err := cringbuf.NewReader(m)
	if err != nil {
		return fmt.Errorf("open audit ring buffer: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = rd.Close() })
	defer stop()
	defer func() { _ = rd.Close() }()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, cringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read audit ring buffer: %w", err)
		}
		r, err := audit.Decode(rec.RawSample)
		if err != nil {
			log.Warn("drop audit sample", "err", err)
			continue
		}
		// Detection is global, but the audit stream reports workloads only: the node's
		// own runtime and system cgroups (e.g. containerd managing containers) perform
		// escape-like syscalls legitimately and are not mitigation candidates (F2), so
		// their records are dropped here rather than surfaced as false positives.
		var pod podmeta.Info
		if pods != nil {
			if !pods.IsPod(r.CgroupID) {
				continue
			}
			pod = pods.Lookup(ctx, r.CgroupID)
		}
		ev := audit.NewEvent(r, names.Load(), pod)
		ev.Ppid = lookupPpid(ppid, ev.Pid) // process ancestry, from the fork-populated AG_PPID map
		names.SetComm(ev.CgroupID, ev.Comm)
		if err := audit.WriteLine(w, ev); err != nil {
			return fmt.Errorf("write audit event: %w", err)
		}
		if reactor != nil {
			reactor.React(ctx, ev) // autonomous isolation on a confirmed terminal; non-blocking
		}
	}
}

// lookupPpid returns the parent tgid recorded for pid in AG_PPID (populated on fork), or 0
// if unknown. Synchronous capture at fork time, so it works for short-lived processes too.
func lookupPpid(m *ebpf.Map, pid uint32) uint32 {
	if m == nil {
		return 0
	}
	var parent uint32
	if err := m.Lookup(pid, &parent); err != nil {
		return 0
	}
	return parent
}
