package learn

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/CosminMilica/ariguard/agent/internal/hooks"
	"github.com/CosminMilica/ariguard/agent/internal/sink"
	"github.com/CosminMilica/ariguard/pkg/fsm"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type fakeMeta map[uint64][2]string

func (f fakeMeta) Pod(cg uint64) (string, string) {
	v := f[cg]
	return v[0], v[1]
}

// collector captures emitted traces.
type collector struct {
	mu  sync.Mutex
	got []sink.LearnTrace
}

func (c *collector) emit(_ context.Context, ts []sink.LearnTrace) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, ts...)
	return nil
}

func (c *collector) traces() []sink.LearnTrace {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]sink.LearnTrace(nil), c.got...)
}

func TestAssemblerIdleFlush(t *testing.T) {
	c := &collector{}
	now := time.Unix(0, 0)
	a := NewAssembler(Config{Window: time.Second, MinEvents: 2},
		fakeMeta{7: {"prod", "api-0"}}, nil, "node-a", hooks.Name, c.emit, quietLog())
	a.now = func() time.Time { return now }

	a.Add(context.Background(), Record{CgroupID: 7, Pid: 100, Hook: fsm.HookExecve, TsNs: 1})
	a.Add(context.Background(), Record{CgroupID: 7, Pid: 100, Hook: fsm.HookConnect, TsNs: 2})

	// Not yet idle: drain returns nothing.
	if got := a.drain(false); len(got) != 0 {
		t.Fatalf("drain before window: got %d traces", len(got))
	}
	// Past the window: the group closes.
	now = now.Add(2 * time.Second)
	got := a.drain(false)
	if len(got) != 1 {
		t.Fatalf("want 1 trace, got %d", len(got))
	}
	tr := got[0]
	if tr.Label != "benign" {
		t.Errorf("label = %q, want benign", tr.Label)
	}
	if tr.Source != "learn:node-a/prod/api-0#7:100" {
		t.Errorf("source = %q", tr.Source)
	}
	if len(tr.Events) != 2 || tr.Events[0].Hook != "execve" || tr.Events[1].Hook != "connect" {
		t.Errorf("events = %+v", tr.Events)
	}
}

func TestAssemblerThreatLabel(t *testing.T) {
	c := &collector{}
	threat := NewThreatSet(0)
	threat.Mark(9)
	a := NewAssembler(Config{Window: time.Second, MinEvents: 1},
		nil, threat, "n", hooks.Name, c.emit, quietLog())
	now := time.Unix(10, 0)
	a.now = func() time.Time { return now }

	a.Add(context.Background(), Record{CgroupID: 9, Pid: 5, Hook: fsm.HookSetns})
	now = now.Add(2 * time.Second)
	got := a.drain(false)
	if len(got) != 1 || got[0].Label != "attack" {
		t.Fatalf("want 1 attack trace, got %+v", got)
	}
	// A cgroup with no pod metadata falls back to the cgroup#tgid source.
	if got[0].Source != "learn:n#9:5" {
		t.Errorf("source = %q", got[0].Source)
	}
}

func TestAssemblerMaxEventsFlush(t *testing.T) {
	c := &collector{}
	a := NewAssembler(Config{Window: time.Hour, MaxEvents: 3, MinEvents: 1},
		nil, nil, "n", hooks.Name, c.emit, quietLog())
	for i := 0; i < 3; i++ {
		a.Add(context.Background(), Record{CgroupID: 1, Pid: 1, Hook: fsm.HookOpenat})
	}
	got := c.traces()
	if len(got) != 1 || len(got[0].Events) != 3 {
		t.Fatalf("want one 3-event trace on cap, got %+v", got)
	}
}

func TestAssemblerMinEventsDrop(t *testing.T) {
	c := &collector{}
	now := time.Unix(0, 0)
	a := NewAssembler(Config{Window: time.Second, MinEvents: 3},
		nil, nil, "n", hooks.Name, c.emit, quietLog())
	a.now = func() time.Time { return now }
	a.Add(context.Background(), Record{CgroupID: 1, Pid: 1, Hook: fsm.HookOpenat})
	now = now.Add(2 * time.Second)
	if got := a.drain(false); len(got) != 0 {
		t.Fatalf("short trace should be dropped, got %d", len(got))
	}
}

func TestAssemblerSeparatesProcesses(t *testing.T) {
	c := &collector{}
	now := time.Unix(0, 0)
	a := NewAssembler(Config{Window: time.Second, MinEvents: 1},
		nil, nil, "n", hooks.Name, c.emit, quietLog())
	a.now = func() time.Time { return now }
	a.Add(context.Background(), Record{CgroupID: 1, Pid: 1, Hook: fsm.HookOpenat})
	a.Add(context.Background(), Record{CgroupID: 1, Pid: 2, Hook: fsm.HookExecve})
	now = now.Add(2 * time.Second)
	got := a.drain(false)
	if len(got) != 2 {
		t.Fatalf("want 2 traces (one per tgid), got %d", len(got))
	}
}

func TestAssemblerEvictsOldestGroup(t *testing.T) {
	a := NewAssembler(Config{Window: time.Hour, MaxGroups: 2, MinEvents: 1},
		nil, nil, "n", hooks.Name, (&collector{}).emit, quietLog())
	now := time.Unix(0, 0)
	a.now = func() time.Time { now = now.Add(time.Second); return now }
	a.Add(context.Background(), Record{CgroupID: 1, Pid: 1, Hook: fsm.HookOpenat})
	a.Add(context.Background(), Record{CgroupID: 2, Pid: 2, Hook: fsm.HookOpenat})
	a.Add(context.Background(), Record{CgroupID: 3, Pid: 3, Hook: fsm.HookOpenat}) // evicts group 1
	a.mu.Lock()
	_, has1 := a.groups[key{1, 1}]
	n := len(a.groups)
	a.mu.Unlock()
	if has1 || n != 2 {
		t.Fatalf("oldest group not evicted: has1=%v n=%d", has1, n)
	}
}

func TestRunFlushesOnCancel(t *testing.T) {
	c := &collector{}
	a := NewAssembler(Config{Window: time.Hour, Sweep: time.Hour, MinEvents: 1},
		nil, nil, "n", hooks.Name, c.emit, quietLog())
	a.Add(context.Background(), Record{CgroupID: 1, Pid: 1, Hook: fsm.HookOpenat})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	cancel()
	<-done
	if got := c.traces(); len(got) != 1 {
		t.Fatalf("Run should flush open groups on cancel, got %d", len(got))
	}
}

func TestThreatSetEviction(t *testing.T) {
	ts := NewThreatSet(2)
	ts.Mark(1)
	ts.Mark(2)
	ts.Mark(3) // evicts 1
	if ts.Has(1) {
		t.Error("cgroup 1 should have been evicted")
	}
	if !ts.Has(2) || !ts.Has(3) {
		t.Error("cgroups 2 and 3 should be present")
	}
	ts.Mark(2) // re-mark is a no-op, must not grow/evict
	if !ts.Has(3) {
		t.Error("re-marking 2 should not evict 3")
	}
}
