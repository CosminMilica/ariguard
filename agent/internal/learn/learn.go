// Package learn assembles raw learn-mode syscall records (AG_LEARN, F11) into per-(cgroup,tgid)
// traces and posts them to the console so the rule-generation loop can mine novel chains from real
// production traffic and gate them against a real benign baseline.
//
// The kernel emits one record per hooked syscall of an opt-in cgroup (the dedicated sw_<hook>_learn
// programs). The assembler groups those by (cgroup, tgid), closes a trace when the group has been
// idle for a window or grows past a cap, labels it (benign by default, attack when the cgroup also
// tripped a mitigation), and emits it. Assembly is deliberately in user space: the kernel stays a
// dumb, bounded emitter within the verifier budget.
package learn

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/CosminMilica/ariguard/agent/internal/sink"
)

// Record is one hooked syscall of a learn-mode cgroup; it mirrors fsm.LearnRecord.
type Record struct {
	CgroupID uint64
	TsNs     uint64
	Pid      uint32
	Hook     uint32
}

// Meta resolves a cgroup to its pod identity for a trace's source field.
type Meta interface {
	// Pod returns the namespace and pod name for a cgroup, each "" when unknown.
	Pod(cgroup uint64) (namespace, pod string)
}

// Config tunes trace assembly.
type Config struct {
	Window    time.Duration // idle gap after which an open (cgroup,tgid) trace is closed and emitted
	Sweep     time.Duration // how often idle groups are checked (defaults to Window/2)
	MaxEvents int           // flush a trace early once it reaches this many events
	MinEvents int           // drop a closed trace with fewer than this many events (noise floor)
	MaxGroups int           // cap on concurrently open groups; the oldest is evicted past it
}

func (c Config) withDefaults() Config {
	if c.Window <= 0 {
		c.Window = 10 * time.Second
	}
	if c.Sweep <= 0 {
		c.Sweep = c.Window / 2
		if c.Sweep <= 0 {
			c.Sweep = time.Second
		}
	}
	if c.MaxEvents <= 0 {
		c.MaxEvents = 256
	}
	if c.MinEvents <= 0 {
		c.MinEvents = 2
	}
	if c.MaxGroups <= 0 {
		c.MaxGroups = 4096
	}
	return c
}

type key struct {
	cgroup uint64
	tgid   uint32
}

type group struct {
	events  []sink.TraceEvent
	updated time.Time
}

// Assembler batches learn records into traces and emits closed ones. Safe for concurrent Add from
// the ring drainer and Run's sweep.
type Assembler struct {
	cfg    Config
	meta   Meta
	threat *ThreatSet
	node   string
	hook   func(uint32) string
	emit   func(context.Context, []sink.LearnTrace) error
	log    *slog.Logger
	now    func() time.Time

	mu     sync.Mutex
	groups map[key]*group
}

// NewAssembler builds an assembler. meta resolves pod identity (may be nil), threat marks cgroups
// that tripped a mitigation (may be nil = everything benign), hook names a hook index, and emit
// ships a batch of closed traces (e.g. sink.Traces).
func NewAssembler(cfg Config, meta Meta, threat *ThreatSet, node string, hook func(uint32) string, emit func(context.Context, []sink.LearnTrace) error, log *slog.Logger) *Assembler {
	return &Assembler{
		cfg:    cfg.withDefaults(),
		meta:   meta,
		threat: threat,
		node:   node,
		hook:   hook,
		emit:   emit,
		log:    log,
		now:    time.Now,
		groups: map[key]*group{},
	}
}

// Add records one learn event. A full group (>= MaxEvents) is closed and emitted at once; otherwise
// it accumulates until the sweep closes it on idle.
func (a *Assembler) Add(ctx context.Context, r Record) {
	k := key{cgroup: r.CgroupID, tgid: r.Pid}
	ev := sink.TraceEvent{Hook: a.hook(r.Hook), TsNs: r.TsNs}

	a.mu.Lock()
	g := a.groups[k]
	if g == nil {
		if len(a.groups) >= a.cfg.MaxGroups {
			a.evictOldestLocked()
		}
		g = &group{}
		a.groups[k] = g
	}
	g.events = append(g.events, ev)
	g.updated = a.now()
	var full []sink.LearnTrace
	if len(g.events) >= a.cfg.MaxEvents {
		if t, ok := a.closeLocked(k, g); ok {
			full = []sink.LearnTrace{t}
		}
	}
	a.mu.Unlock()

	if len(full) > 0 {
		a.ship(ctx, full)
	}
}

// Run sweeps idle groups into traces every cfg.Sweep until ctx is done, then flushes all open groups.
func (a *Assembler) Run(ctx context.Context) {
	tick := time.NewTicker(a.cfg.Sweep)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			a.ship(context.Background(), a.drain(true))
			return
		case <-tick.C:
			a.ship(ctx, a.drain(false))
		}
	}
}

// drain closes idle groups (or, when all is set, every group) and returns their traces.
func (a *Assembler) drain(all bool) []sink.LearnTrace {
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []sink.LearnTrace
	for k, g := range a.groups {
		if !all && now.Sub(g.updated) < a.cfg.Window {
			continue
		}
		if t, ok := a.closeLocked(k, g); ok {
			out = append(out, t)
		}
	}
	return out
}

// closeLocked removes a group and, if it has enough events, returns it as a labeled trace.
// Callers hold a.mu.
func (a *Assembler) closeLocked(k key, g *group) (sink.LearnTrace, bool) {
	delete(a.groups, k)
	if len(g.events) < a.cfg.MinEvents {
		return sink.LearnTrace{}, false
	}
	label := "benign"
	if a.threat != nil && a.threat.Has(k.cgroup) {
		label = "attack"
	}
	return sink.LearnTrace{
		Label:  label,
		Source: a.source(k),
		Events: g.events,
	}, true
}

// evictOldestLocked drops the least-recently-updated open group to bound memory. Callers hold a.mu.
func (a *Assembler) evictOldestLocked() {
	var oldest key
	var oldestAt time.Time
	first := true
	for k, g := range a.groups {
		if first || g.updated.Before(oldestAt) {
			oldest, oldestAt, first = k, g.updated, false
		}
	}
	if !first {
		delete(a.groups, oldest)
	}
}

// source builds the trace's source field from the node and the cgroup's pod identity.
func (a *Assembler) source(k key) string {
	ns, pod := "", ""
	if a.meta != nil {
		ns, pod = a.meta.Pod(k.cgroup)
	}
	if pod == "" {
		return fmt.Sprintf("learn:%s#%d:%d", a.node, k.cgroup, k.tgid)
	}
	return fmt.Sprintf("learn:%s/%s/%s#%d:%d", a.node, ns, pod, k.cgroup, k.tgid)
}

func (a *Assembler) ship(ctx context.Context, traces []sink.LearnTrace) {
	if len(traces) == 0 || a.emit == nil {
		return
	}
	if err := a.emit(ctx, traces); err != nil {
		a.log.Warn("learn: post traces", "traces", len(traces), "err", err)
	}
}
