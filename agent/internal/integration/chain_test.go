//go:build integration && linux

// Package integration loads the real BPF object into the running kernel and
// drives syscall chains from a child process in its own cgroup. Needs root.
package integration

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/CosminMilica/statewall/agent/internal/audit"
	"github.com/CosminMilica/statewall/agent/internal/loader"
	"github.com/CosminMilica/statewall/agent/internal/podmeta"
	"github.com/CosminMilica/statewall/agent/internal/policy"
	"github.com/CosminMilica/statewall/agent/internal/policy/kmap"
	"github.com/CosminMilica/statewall/pkg/fsm"
)

const (
	stepsEnv = "STATEWALL_CHAIN_STEPS"
	cpuEnv   = "STATEWALL_CHAIN_CPU"
)

func TestMain(m *testing.M) {
	if steps := os.Getenv(stepsEnv); steps != "" {
		pinToCPU(os.Getenv(cpuEnv))
		runSteps(strings.Split(steps, ","))
		os.Exit(0)
	}
	os.Exit(m.Run())
}

const runtimeSocket = "/var/run/docker.sock"

// pinToCPU keeps every step on one thread bound to cpu ("" = no pinning).
func pinToCPU(cpu string) {
	if cpu == "" {
		return
	}
	n, err := strconv.Atoi(cpu)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad %s %q\n", cpuEnv, cpu)
		os.Exit(2)
	}
	runtime.LockOSThread()
	var set unix.CPUSet
	set.Set(n)
	if err := unix.SchedSetaffinity(0, &set); err != nil {
		fmt.Fprintf(os.Stderr, "pin to cpu %d: %v\n", n, err)
		os.Exit(2)
	}
}

// runSteps issues the syscalls the hooks observe. Their results do not matter:
// sys_enter_* fires before the kernel validates arguments.
func runSteps(steps []string) {
	for _, s := range steps {
		switch s {
		case "socket":
			_, _ = unix.Open(runtimeSocket, unix.O_RDONLY, 0)
		case "connect":
			if fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0); err == nil {
				_ = unix.Connect(fd, &unix.SockaddrUnix{Name: runtimeSocket})
				_ = unix.Close(fd)
			}
		case "other-open":
			_, _ = unix.Open("/etc/hostname", unix.O_RDONLY, 0)
		case "setns":
			_ = unix.Setns(-1, 0)
		case "mount":
			_ = unix.Mount("none", "/nonexistent-statewall", "statewall-none", 0, "")
		case "private-mount":
			_ = unix.Mount("none", "/nonexistent-statewall", "", unix.MS_PRIVATE, "")
		case "memfd":
			_, _ = unix.MemfdCreate("statewall", 0)
		case "execve":
			_ = unix.Exec("/nonexistent-statewall", []string{"x"}, nil)
		case "sleep":
			time.Sleep(200 * time.Millisecond)
		default:
			fmt.Fprintf(os.Stderr, "unknown step %q\n", s)
			os.Exit(2)
		}
	}
}

// chain is a linear rule: states[i] --events[i]--> states[i+1]; every other cell stays put.
type chain struct {
	meta    fsm.RuleMeta
	scope   uint32
	actions []uint32
}

var (
	escape = chain{
		meta: fsm.RuleMeta{
			Name:   "container-escape",
			Scope:  "cgroup",
			States: []string{"normal", "suspicious", "escalating", "breakout_imminent", "compromised"},
			Events: []string{"runtime_socket_open", "namespace_manipulation", "host_mount", "critical_execve"},
		},
		scope:   fsm.ScopeCgroup,
		actions: []uint32{fsm.ActionObserve, fsm.ActionThrottle, fsm.ActionDeny, fsm.ActionKill},
	}
	fileless = chain{
		meta: fsm.RuleMeta{
			Name:   "fileless-exec",
			Scope:  "process",
			States: []string{"normal", "memfd_created", "compromised"},
			Events: []string{"memfd_create", "exec"},
		},
		scope:   fsm.ScopeProcess,
		actions: []uint32{fsm.ActionObserve, fsm.ActionObserve},
	}
)

const (
	ruleEscape uint32 = iota
	ruleFileless
)

func anyBinding(hook, rule, event uint32) fsm.Binding {
	return fsm.Binding{Hook: hook, Rule: rule, Event: event, PathArg: fsm.NoArg, ArgIndex: fsm.NoArg}
}

func pathBinding(hook, rule, event, arg, kind uint32, pattern string) fsm.Binding {
	b := anyBinding(hook, rule, event)
	b.PathArg, b.PathKind, b.PathLen = arg, kind, uint32(len(pattern))
	copy(b.Pattern[:], pattern)
	return b
}

// testBundle builds the container-escape and fileless-exec rules with the given window.
func testBundle(window time.Duration) *fsm.Bundle {
	b := &fsm.Bundle{}
	for _, c := range []chain{escape, fileless} {
		ns, ne := uint32(len(c.meta.States)), uint32(len(c.meta.Events))
		b.Rules = append(b.Rules, fsm.Rule{
			NumStates: ns, NumEvents: ne, TransBase: uint32(len(b.Transitions)),
			Scope: c.scope, TerminalFrom: ns - 1, WindowNs: uint64(window),
		})
		for s := uint32(0); s < ns; s++ {
			for e := uint32(0); e < ne; e++ {
				t := fsm.Transition{NextState: s}
				if e == s {
					t = fsm.Transition{NextState: s + 1, Action: c.actions[e]}
				}
				b.Transitions = append(b.Transitions, t)
			}
		}
		b.Meta.Rules = append(b.Meta.Rules, c.meta)
	}
	mount := anyBinding(fsm.HookMount, ruleEscape, 2)
	mount.ArgIndex, mount.ArgOp = 3, fsm.ArgMaskNone
	mount.ArgValue = unix.MS_SHARED | unix.MS_PRIVATE | unix.MS_SLAVE | unix.MS_UNBINDABLE
	b.Bindings = []fsm.Binding{
		pathBinding(fsm.HookOpenat, ruleEscape, 0, 1, fsm.PathPrefix, runtimeSocket),
		pathBinding(fsm.HookConnect, ruleEscape, 0, 1, fsm.PathSunPrefix, runtimeSocket),
		anyBinding(fsm.HookSetns, ruleEscape, 1),
		anyBinding(fsm.HookUnshare, ruleEscape, 1),
		mount,
		anyBinding(fsm.HookFsmount, ruleEscape, 2),
		anyBinding(fsm.HookMoveMount, ruleEscape, 2),
		anyBinding(fsm.HookExecve, ruleEscape, 3),
		anyBinding(fsm.HookMemfdCreate, ruleFileless, 0),
		anyBinding(fsm.HookExecve, ruleFileless, 1),
		anyBinding(fsm.HookExecveat, ruleFileless, 1),
	}
	return b
}

type harness struct {
	obj  *loader.Object
	maps kmap.KernelMaps
	rd   *ringbuf.Reader
	meta fsm.Meta
}

func setup(t *testing.T) *harness {
	t.Helper()
	if os.Geteuid() != 0 {
		if os.Getenv("STATEWALL_REQUIRE_OBJECT") != "" {
			t.Fatal("integration tests need root")
		}
		t.Skip("integration tests need root")
	}
	root := repoRoot(t)
	objPath := envOr("STATEWALL_OBJECT", filepath.Join(root, "bin", "statewall.bpf.o"))
	obj, err := loader.Load(objPath, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(func() { _ = obj.Close() })

	h := &harness{obj: obj, maps: kmap.KernelMaps{
		Policy:      obj.Maps.Policy,
		Rules:       obj.Maps.Rules,
		Transitions: obj.Maps.Transitions,
		Bindings:    obj.Maps.Bindings,
	}}
	h.apply(t, testBundle(30*time.Second))
	if err := obj.Attach(); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if stats, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME)); err == nil {
		t.Cleanup(func() { _ = stats.Close() })
	}
	h.rd, err = ringbuf.NewReader(obj.Maps.Audit)
	if err != nil {
		t.Fatalf("ring buffer: %v", err)
	}
	t.Cleanup(func() { _ = h.rd.Close() })
	return h
}

func (h *harness) apply(t *testing.T, b *fsm.Bundle) {
	t.Helper()
	if err := policy.Apply(h.maps, b); err != nil {
		t.Fatalf("apply bundle: %v", err)
	}
	h.meta = b.Meta
}

// run executes steps in a fresh cgroup and returns the audit events it produced.
func (h *harness) run(t *testing.T, steps ...string) []audit.Event {
	t.Helper()
	cgID, cgFD := newCgroup(t)
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), stepsEnv+"="+strings.Join(steps, ","))
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cgFD}
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() == 2 {
			t.Fatalf("child: %v", err)
		}
	}

	var events []audit.Event
	h.rd.SetDeadline(time.Now().Add(time.Second))
	for {
		rec, err := h.rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return events
		}
		if err != nil {
			t.Fatalf("read ring buffer: %v", err)
		}
		r, err := audit.Decode(rec.RawSample)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if r.CgroupID == cgID {
			events = append(events, audit.NewEvent(r, &h.meta, podmeta.Info{}))
		}
	}
}

// states returns the states rule reached, in order.
func states(events []audit.Event, rule string) []string {
	var out []string
	for _, e := range events {
		if e.Rule == rule {
			out = append(out, e.To)
		}
	}
	return out
}

func TestChain(t *testing.T) {
	h := setup(t)
	escapeName := escape.meta.Name

	t.Run("full chain reaches compromised", func(t *testing.T) {
		events := h.run(t, "socket", "setns", "mount", "execve")
		got := states(events, escapeName)
		want := []string{"suspicious", "escalating", "breakout_imminent", "compromised"}
		if !slices.Equal(got, want) {
			logRunCounts(t)
			t.Fatalf("states = %v, want %v", got, want)
		}
		if comm := events[0].Comm; comm == "" {
			t.Errorf("audit record without comm: %+v", events[0])
		}
	})

	t.Run("connect to the runtime socket starts the chain", func(t *testing.T) {
		got := states(h.run(t, "connect", "setns", "mount", "execve"), escapeName)
		if !reached(escape, got, "compromised") {
			t.Fatalf("states = %v, want compromised", got)
		}
	})

	t.Run("detected on every CPU", func(t *testing.T) {
		var set unix.CPUSet
		if err := unix.SchedGetaffinity(0, &set); err != nil {
			t.Fatalf("sched_getaffinity: %v", err)
		}
		for cpu := 0; cpu < 1024; cpu++ {
			if !set.IsSet(cpu) {
				continue
			}
			t.Setenv(cpuEnv, strconv.Itoa(cpu))
			got := states(h.run(t, "socket", "setns", "mount", "execve"), escapeName)
			if !reached(escape, got, "compromised") {
				logRunCounts(t)
				t.Errorf("cpu %d: states = %v, want compromised", cpu, got)
			}
		}
	})

	t.Run("fragments without socket stay normal", func(t *testing.T) {
		if got := h.run(t, "other-open", "setns", "mount", "execve"); len(got) != 0 {
			t.Fatalf("events = %+v, want none", got)
		}
	})

	t.Run("out of order does not escalate", func(t *testing.T) {
		got := states(h.run(t, "mount", "execve", "setns", "socket"), escapeName)
		if reached(escape, got, "escalating") {
			t.Fatalf("states = %v, want nothing past suspicious", got)
		}
	})

	t.Run("propagation-only mount is not a host mount", func(t *testing.T) {
		got := states(h.run(t, "socket", "setns", "private-mount", "execve"), escapeName)
		if !reached(escape, got, "escalating") || reached(escape, got, "breakout_imminent") {
			t.Fatalf("states = %v, want escalating and nothing past it", got)
		}
	})

	t.Run("two rules evaluate together", func(t *testing.T) {
		events := h.run(t, "memfd", "execve")
		want := []string{"memfd_created", "compromised"}
		if got := states(events, fileless.meta.Name); !slices.Equal(got, want) {
			t.Fatalf("fileless states = %v, want %v", got, want)
		}
		if got := states(events, escapeName); len(got) != 0 {
			t.Fatalf("container-escape states = %v, want none", got)
		}
	})

	t.Run("expired chain does not escalate", func(t *testing.T) {
		h.apply(t, testBundle(50*time.Millisecond))
		t.Cleanup(func() { h.apply(t, testBundle(30*time.Second)) })
		got := states(h.run(t, "socket", "sleep", "setns", "mount", "execve"), escapeName)
		if reached(escape, got, "escalating") {
			t.Fatalf("states = %v, want reset after the window", got)
		}
	})

	t.Run("hot swap keeps detection", func(t *testing.T) {
		h.apply(t, testBundle(30*time.Second))
		got := states(h.run(t, "socket", "setns", "mount", "execve"), escapeName)
		if !reached(escape, got, "compromised") {
			logRunCounts(t)
			t.Fatalf("states = %v, want compromised after re-apply", got)
		}
	})
}

// setEnforce flips Policy.enforce in the live SW_POLICY, keeping NumRules.
func (h *harness) setEnforce(t *testing.T, on uint32) {
	t.Helper()
	var p fsm.Policy
	if err := h.obj.Maps.Policy.Lookup(uint32(0), &p); err != nil {
		t.Fatalf("policy lookup: %v", err)
	}
	p.Enforce = on
	if err := h.obj.Maps.Policy.Put(uint32(0), p); err != nil {
		t.Fatalf("policy put: %v", err)
	}
}

// runEnforce runs steps in a fresh cgroup, registering it in SW_PODS when pod is true.
// It reports whether the child died from SIGKILL and the raw audit records for the cgroup.
func (h *harness) runEnforce(t *testing.T, pod bool, steps ...string) (bool, []fsm.AuditRecord) {
	t.Helper()
	cgID, cgFD := newCgroup(t)
	if pod {
		if err := h.obj.Maps.Pods.Put(cgID, uint8(1)); err != nil {
			t.Fatalf("SW_PODS put: %v", err)
		}
		t.Cleanup(func() { _ = h.obj.Maps.Pods.Delete(cgID) })
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), stepsEnv+"="+strings.Join(steps, ","))
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cgFD}

	killed := false
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("child: %v", err)
		}
		ws, ok := exitErr.Sys().(syscall.WaitStatus)
		if ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL {
			killed = true
		} else if !ok || exitErr.ExitCode() == 2 {
			t.Fatalf("child: %v", err)
		}
	}

	var records []fsm.AuditRecord
	h.rd.SetDeadline(time.Now().Add(time.Second))
	for {
		rec, err := h.rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return killed, records
		}
		if err != nil {
			t.Fatalf("read ring buffer: %v", err)
		}
		r, err := audit.Decode(rec.RawSample)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if r.CgroupID == cgID {
			records = append(records, r)
		}
	}
}

// killRecord returns the first audit record whose action is kill.
func killRecord(records []fsm.AuditRecord) (fsm.AuditRecord, bool) {
	for _, r := range records {
		if r.Action == fsm.ActionKill {
			return r, true
		}
	}
	return fsm.AuditRecord{}, false
}

// TestEnforcement covers the Phase 2 kill path: the escape chain's terminal transition
// carries action=kill, so a pod cgroup under enforcement is SIGKILLed at the execve step,
// while a dry run (enforce=0) or a non-pod cgroup is only audited.
func TestEnforcement(t *testing.T) {
	h := setup(t)
	chain := []string{"socket", "setns", "mount", "execve"}

	t.Run("enforce and pod: child killed, Enforced=1", func(t *testing.T) {
		h.setEnforce(t, 1)
		killed, records := h.runEnforce(t, true, chain...)
		if !killed {
			t.Fatalf("child was not killed by SIGKILL; records=%+v", records)
		}
		r, ok := killRecord(records)
		if !ok {
			t.Fatalf("no kill-action audit record; records=%+v", records)
		}
		if r.Enforced != 1 {
			t.Errorf("terminal record Enforced=%d, want 1 (%+v)", r.Enforced, r)
		}
	})

	t.Run("dry run (enforce=0): not killed, Enforced=0", func(t *testing.T) {
		h.setEnforce(t, 0)
		killed, records := h.runEnforce(t, true, chain...)
		if killed {
			t.Fatal("child killed with enforce=0")
		}
		r, ok := killRecord(records)
		if !ok {
			t.Fatalf("no kill-action audit record; records=%+v", records)
		}
		if r.Enforced != 0 {
			t.Errorf("terminal record Enforced=%d, want 0 (%+v)", r.Enforced, r)
		}
	})

	t.Run("non-pod cgroup: not killed, Enforced=0", func(t *testing.T) {
		h.setEnforce(t, 1)
		killed, records := h.runEnforce(t, false, chain...)
		if killed {
			t.Fatal("non-pod child killed")
		}
		r, ok := killRecord(records)
		if !ok {
			t.Fatalf("no kill-action audit record; records=%+v", records)
		}
		if r.Enforced != 0 {
			t.Errorf("terminal record Enforced=%d, want 0 (%+v)", r.Enforced, r)
		}
	})
}

// logRunCounts reports how often each statewall program ran, to tell a hook
// that never fires from one that fires without matching.
func logRunCounts(t *testing.T) {
	t.Helper()
	var id ebpf.ProgramID
	for {
		next, err := ebpf.ProgramGetNextID(id)
		if err != nil {
			return
		}
		id = next
		p, err := ebpf.NewProgramFromID(id)
		if err != nil {
			continue
		}
		info, err := p.Info()
		if err != nil || !strings.HasPrefix(info.Name, loader.ProgramPrefix) {
			_ = p.Close()
			continue
		}
		stats, err := p.Stats()
		_ = p.Close()
		if err != nil {
			t.Logf("program %s (id %d): stats: %v", info.Name, id, err)
			continue
		}
		t.Logf("program %s (id %d): runs=%d recursion_misses=%d", info.Name, id, stats.RunCount, stats.RecursionMisses)
	}
}

func newCgroup(t *testing.T) (uint64, int) {
	t.Helper()
	base := "/sys/fs/cgroup"
	if _, err := os.Stat(filepath.Join(base, "cgroup.controllers")); err != nil {
		if err := unix.Mount("cgroup2", base, "cgroup2", 0, ""); err != nil {
			t.Fatalf("mount cgroup2: %v", err)
		}
	}
	dir, err := os.MkdirTemp(base, "statewall-it-")
	if err != nil {
		t.Fatalf("create cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	var st unix.Stat_t
	if err := unix.Stat(dir, &st); err != nil {
		t.Fatalf("stat cgroup: %v", err)
	}
	fd, err := unix.Open(dir, unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open cgroup: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return st.Ino, fd
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// reached reports whether any state in states is s or later in c's chain.
func reached(c chain, states []string, s string) bool {
	min := slices.Index(c.meta.States, s)
	for _, got := range states {
		if slices.Index(c.meta.States, got) >= min {
			return true
		}
	}
	return false
}
