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
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/CosminMilica/statewall/agent/internal/audit"
	"github.com/CosminMilica/statewall/agent/internal/loader"
	"github.com/CosminMilica/statewall/agent/internal/policy"
	"github.com/CosminMilica/statewall/pkg/fsm"
)

const stepsEnv = "STATEWALL_CHAIN_STEPS"

func TestMain(m *testing.M) {
	if steps := os.Getenv(stepsEnv); steps != "" {
		runSteps(strings.Split(steps, ","))
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runSteps issues the syscalls the hooks observe. Their results do not matter:
// sys_enter_* fires before the kernel validates arguments.
func runSteps(steps []string) {
	for _, s := range steps {
		switch s {
		case "socket":
			_, _ = unix.Open("/var/run/docker.sock", unix.O_RDONLY, 0)
		case "other-open":
			_, _ = unix.Open("/etc/hostname", unix.O_RDONLY, 0)
		case "setns":
			_ = unix.Setns(-1, 0)
		case "mount":
			_ = unix.Mount("none", "/nonexistent-statewall", "statewall-none", 0, "")
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

type harness struct {
	obj  *loader.Object
	maps policy.KernelMaps
	rd   *ringbuf.Reader
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

	h := &harness{obj: obj, maps: policy.KernelMaps{
		Transitions: obj.Maps.Transitions,
		Bindings:    obj.Maps.Bindings,
		Dims:        obj.Maps.Dims,
	}}
	h.apply(t, golden(t, root))
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
}

// run executes steps in a fresh cgroup and returns the states it reached.
func (h *harness) run(t *testing.T, steps ...string) []string {
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

	var states []string
	h.rd.SetDeadline(time.Now().Add(time.Second))
	for {
		rec, err := h.rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return states
		}
		if err != nil {
			t.Fatalf("read ring buffer: %v", err)
		}
		r, err := audit.Decode(rec.RawSample)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if r.CgroupID == cgID {
			states = append(states, audit.StateName(r.ToState))
		}
	}
}

func TestChain(t *testing.T) {
	h := setup(t)

	t.Run("full chain reaches compromised", func(t *testing.T) {
		got := h.run(t, "socket", "setns", "mount", "execve")
		want := []string{"suspicious", "escalating", "breakout_imminent", "compromised"}
		if !slices.Equal(got, want) {
			logRunCounts(t)
			t.Fatalf("states = %v, want %v", got, want)
		}
	})

	t.Run("fragments without socket stay normal", func(t *testing.T) {
		if got := h.run(t, "other-open", "setns", "mount", "execve"); len(got) != 0 {
			t.Fatalf("states = %v, want none", got)
		}
	})

	t.Run("out of order does not escalate", func(t *testing.T) {
		got := h.run(t, "mount", "execve", "setns", "socket")
		if reached(got, "escalating") {
			t.Fatalf("states = %v, want nothing past suspicious", got)
		}
	})

	t.Run("expired chain does not escalate", func(t *testing.T) {
		b := golden(t, repoRoot(t))
		b.Dims.WindowNs = uint64(50 * time.Millisecond)
		h.apply(t, b)
		t.Cleanup(func() { h.apply(t, golden(t, repoRoot(t))) })
		got := h.run(t, "socket", "sleep", "setns", "mount", "execve")
		if reached(got, "escalating") {
			t.Fatalf("states = %v, want reset after the window", got)
		}
	})

	t.Run("hot swap keeps detection", func(t *testing.T) {
		h.apply(t, golden(t, repoRoot(t)))
		got := h.run(t, "socket", "setns", "mount", "execve")
		if !reached(got, "compromised") {
			logRunCounts(t)
			t.Fatalf("states = %v, want compromised after re-apply", got)
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

func golden(t *testing.T, root string) *fsm.Bundle {
	t.Helper()
	path := envOr("STATEWALL_BUNDLE", filepath.Join(root, "testdata", "golden", "container-escape.bin"))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	b, err := fsm.UnmarshalBundle(data)
	if err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	return b
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

// reached reports whether any state in states is s or more severe.
func reached(states []string, s string) bool {
	order := []string{"normal", "suspicious", "escalating", "breakout_imminent", "compromised"}
	min := slices.Index(order, s)
	for _, got := range states {
		if slices.Index(order, got) >= min {
			return true
		}
	}
	return false
}
