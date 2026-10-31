//go:build linux

package loader

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/CosminMilica/ariguard/agent/internal/hooks"
	"github.com/CosminMilica/ariguard/pkg/fsm"
)

// Maps are the contract maps of a loaded object.
type Maps struct {
	State       *ebpf.Map
	Transitions *ebpf.Map
	Bindings    *ebpf.Map
	Rules       *ebpf.Map
	Policy      *ebpf.Map
	Audit       *ebpf.Map
	Scratch     *ebpf.Map
	Pods        *ebpf.Map
	Metrics     *ebpf.Map
}

// Object is a loaded ariguard collection and its attached links.
type Object struct {
	Maps  Maps
	coll  *ebpf.Collection
	links []link.Link
	fds   []int
	log   *slog.Logger
}

// Load loads the object at path into the kernel without attaching it.
func Load(path string, log *slog.Logger) (*Object, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, fmt.Errorf("parse object %s: %w", path, err)
	}
	for name, p := range spec.Programs {
		if strings.HasPrefix(name, ProgramPrefix) {
			p.Type = ebpf.TracePoint
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			return nil, fmt.Errorf("load object %s: %+v", path, verr)
		}
		return nil, fmt.Errorf("load object %s: %w", path, err)
	}

	o := &Object{coll: coll, log: log}
	refs := []struct {
		name string
		dst  **ebpf.Map
	}{
		{MapState, &o.Maps.State},
		{MapTransitions, &o.Maps.Transitions},
		{MapBindings, &o.Maps.Bindings},
		{MapRules, &o.Maps.Rules},
		{MapPolicy, &o.Maps.Policy},
		{MapAudit, &o.Maps.Audit},
		{MapScratch, &o.Maps.Scratch},
		{MapPods, &o.Maps.Pods},
		{MapMetrics, &o.Maps.Metrics},
	}
	for _, r := range refs {
		m, ok := coll.Maps[r.name]
		if !ok {
			coll.Close()
			return nil, fmt.Errorf("object %s: required map %s not found (have %s)", path, r.name, mapNames(coll))
		}
		*r.dst = m
	}
	return o, nil
}

// Attach attaches every sw_<hook> program to syscalls/sys_enter_<hook>.
// Missing programs and tracepoints the kernel lacks (E14) are skipped with a warning.
func (o *Object) Attach() error {
	for h := uint32(0); h < fsm.NumHooks; h++ {
		name := hooks.Program(h)
		prog, ok := o.coll.Programs[name]
		if !ok {
			o.log.Warn("program missing, hook not attached", "program", name)
			continue
		}
		l, err := link.Tracepoint("syscalls", hooks.Tracepoint(h), prog, nil)
		if errors.Is(err, os.ErrNotExist) {
			o.log.Warn("tracepoint missing on this kernel, hook not attached", "program", name, "tracepoint", "syscalls/"+hooks.Tracepoint(h))
			continue
		}
		if err != nil {
			return fmt.Errorf("attach %s to syscalls/%s: %w", name, hooks.Tracepoint(h), err)
		}
		o.links = append(o.links, l)
		if err := o.armAllCPUs(hooks.Tracepoint(h)); err != nil {
			return fmt.Errorf("arm syscalls/%s on all CPUs: %w", hooks.Tracepoint(h), err)
		}
		o.log.Info("attached", "program", name, "tracepoint", "syscalls/"+hooks.Tracepoint(h))
	}
	return nil
}

// HooksAttached returns the number of attached hook programs.
func (o *Object) HooksAttached() int { return len(o.links) }

// Close detaches all links and releases the collection.
func (o *Object) Close() error {
	var errs []error
	for _, l := range o.links {
		errs = append(errs, l.Close())
	}
	o.links = nil
	for _, fd := range o.fds {
		errs = append(errs, unix.Close(fd))
	}
	o.fds = nil
	o.coll.Close()
	return errors.Join(errs...)
}

// armAllCPUs opens a bare perf event for the tracepoint on every online CPU.
// Some kernels (seen on 7.0-azure) run syscall tracepoint programs only on CPUs
// that have a perf event open; link.Tracepoint opens one on CPU 0 only.
func (o *Object) armAllCPUs(tracepoint string) error {
	id, err := tracepointID("syscalls", tracepoint)
	if err != nil {
		return err
	}
	cpus, err := onlineCPUs()
	if err != nil {
		return err
	}
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_TRACEPOINT,
		Config: id,
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
	}
	for _, cpu := range cpus {
		fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			return fmt.Errorf("perf_event_open cpu %d: %w", cpu, err)
		}
		o.fds = append(o.fds, fd)
	}
	return nil
}

func tracepointID(group, name string) (uint64, error) {
	for _, root := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		data, err := os.ReadFile(filepath.Join(root, "events", group, name, "id"))
		if err == nil {
			return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		}
	}
	return 0, fmt.Errorf("tracepoint %s/%s: id not found in tracefs", group, name)
}

// onlineCPUs parses /sys/devices/system/cpu/online ("0-3,5").
func onlineCPUs() ([]int, error) {
	data, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return nil, err
	}
	var cpus []int
	for _, part := range strings.Split(strings.TrimSpace(string(data)), ",") {
		lo, hi, found := strings.Cut(part, "-")
		first, err := strconv.Atoi(lo)
		if err != nil {
			return nil, fmt.Errorf("parse online CPUs %q: %w", data, err)
		}
		last := first
		if found {
			if last, err = strconv.Atoi(hi); err != nil {
				return nil, fmt.Errorf("parse online CPUs %q: %w", data, err)
			}
		}
		for c := first; c <= last; c++ {
			cpus = append(cpus, c)
		}
	}
	return cpus, nil
}

func mapNames(coll *ebpf.Collection) string {
	names := make([]string, 0, len(coll.Maps))
	for n := range coll.Maps {
		names = append(names, n)
	}
	return strings.Join(names, ", ")
}
