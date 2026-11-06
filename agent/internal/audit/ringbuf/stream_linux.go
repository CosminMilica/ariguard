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
	"github.com/CosminMilica/ariguard/pkg/fsm"
)

// Stream reads AG_AUDIT and writes one JSON line per record to w until ctx is done.
// Names are read per record, so a reload takes effect on the next line; pods may be nil.
func Stream(ctx context.Context, m, ppid, conndst, path, argv *ebpf.Map, w io.Writer, names *audit.Names, pods audit.Pods, reactor audit.Reactor, log *slog.Logger) error {
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
		if r.Hook == fsm.HookConnect {     // observed connect destination (B3), from AG_CONNDST
			if c, ok := lookupConnDst(conndst, ev.Pid); ok {
				ev.DstIP, ev.DstPort = audit.ConnDstFields(c)
				if ev.DstIP != "" && pods != nil { // resolve the destination to a target pod (F2)
					if dst := pods.LookupIP(ctx, ev.DstIP); dst.Pod != "" {
						ev.DstPod, ev.DstNs = dst.Pod, dst.Namespace
					}
				}
			}
		} else if hookHasPath(r.Hook) { // observed path IOC (B3), from AG_PATH
			if p, ok := lookupPath(path, ev.Pid); ok {
				ev.Path = audit.PathString(p)
			}
			if r.Hook == fsm.HookExecve || r.Hook == fsm.HookExecveat { // command line (B3), from AG_ARGV
				if a, ok := lookupArgv(argv, ev.Pid); ok {
					ev.Argv = audit.ArgvString(a)
				}
			}
		}
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

// hookHasPath reports whether the kernel captures a path for this hook into AG_PATH
// (execve/execveat/memfd_create — see stash_path). Other hooks either carry no path or are hot-path
// (openat), so their AG_PATH entry would be stale or absent and must not be attached.
func hookHasPath(hook uint32) bool {
	switch hook {
	case fsm.HookExecve, fsm.HookExecveat, fsm.HookMemfdCreate:
		return true
	}
	return false
}

// lookupPath returns the observed path recorded for pid in AG_PATH (written by handle() on a
// path-matching emit), or ok=false if none. Keyed by tgid, like AG_CONNDST.
func lookupPath(m *ebpf.Map, pid uint32) (fsm.PathVal, bool) {
	if m == nil {
		return fsm.PathVal{}, false
	}
	var p fsm.PathVal
	if err := m.Lookup(pid, &p); err != nil {
		return fsm.PathVal{}, false
	}
	return p, true
}

// lookupArgv returns the exec argv recorded for pid in AG_ARGV (written by the argv programs), or
// ok=false if none. Keyed by tgid, like AG_PATH.
func lookupArgv(m *ebpf.Map, pid uint32) (fsm.ArgvVal, bool) {
	if m == nil {
		return fsm.ArgvVal{}, false
	}
	var a fsm.ArgvVal
	if err := m.Lookup(pid, &a); err != nil {
		return fsm.ArgvVal{}, false
	}
	return a, true
}

// lookupConnDst returns the connect destination recorded for pid in AG_CONNDST (written by
// sw_connect), or ok=false if none. Keyed by tgid, so a later connect on the same tgid can
// overwrite it — acceptable for an IOC, matching the AG_PPID tradeoff.
func lookupConnDst(m *ebpf.Map, pid uint32) (fsm.ConnDst, bool) {
	if m == nil {
		return fsm.ConnDst{}, false
	}
	var c fsm.ConnDst
	if err := m.Lookup(pid, &c); err != nil {
		return fsm.ConnDst{}, false
	}
	return c, true
}
