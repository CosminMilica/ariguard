//go:build linux

package loader

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/CosminMilica/statewall/agent/internal/hooks"
	"github.com/CosminMilica/statewall/pkg/fsm"
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
}

// Object is a loaded statewall collection and its attached links.
type Object struct {
	Maps  Maps
	coll  *ebpf.Collection
	links []link.Link
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
		o.log.Info("attached", "program", name, "tracepoint", "syscalls/"+hooks.Tracepoint(h))
	}
	return nil
}

// Close detaches all links and releases the collection.
func (o *Object) Close() error {
	var errs []error
	for _, l := range o.links {
		errs = append(errs, l.Close())
	}
	o.links = nil
	o.coll.Close()
	return errors.Join(errs...)
}

func mapNames(coll *ebpf.Collection) string {
	names := make([]string, 0, len(coll.Maps))
	for n := range coll.Maps {
		names = append(names, n)
	}
	return strings.Join(names, ", ")
}
