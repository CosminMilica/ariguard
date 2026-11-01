//go:build linux

// Command ariguard-bench measures a running ariguard agent in a VM (root plus a
// loaded agent). It has three subcommands:
//
//	latency      per-program eBPF run-time stats (overhead per hook)
//	memcurve     agent RSS and the constant BPF map budget as tracked workloads grow
//	throughput   matched-event rate under a tight syscall load
//
// The load generators are children of this same binary, re-entered through the
// ARIGUARD_BENCH_WORKER environment variable. It needs root (CAP_BPF/CAP_SYS_ADMIN)
// and a loaded agent; it cannot run on the host.
package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// runtimeSocket is the canonical container runtime socket; openat/connect on it
// matches the standard container-escape bindings, so it drives matched events.
const runtimeSocket = "/var/run/docker.sock"

// agentComm is the agent's /proc/<pid>/comm (kernel truncates to 15 bytes; this fits).
const agentComm = "ariguard-agent"

// Worker environment: a child re-enters as a load generator when envWorker is set.
const (
	envWorker        = "ARIGUARD_BENCH_WORKER"
	envWorkerPath    = "ARIGUARD_BENCH_PATH"     // openat target
	envWorkerSteps   = "ARIGUARD_BENCH_STEPS"    // openat calls per batch
	envWorkerSleepNs = "ARIGUARD_BENCH_SLEEP_NS" // nanosleep between batches (0 = tight loop)
)

func main() {
	if os.Getenv(envWorker) != "" {
		runWorker()
		return
	}
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "latency":
		err = runLatency(os.Args[2:])
	case "memcurve":
		err = runMemcurve(os.Args[2:])
	case "throughput":
		err = runThroughput(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "ariguard-bench: unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ariguard-bench: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `ariguard-bench measures a running ariguard agent (needs root + a loaded agent).

usage:
  ariguard-bench latency    [--window 10s] [--out file]
  ariguard-bench memcurve   [--sweep 1,10,100,500,1000] [--settle 3s] [--workload-steps 1] [--out file]
  ariguard-bench throughput [--workers 16] [--window 10s] [--metrics-url http://127.0.0.1:9102/metrics] [--out file]
`)
}

// runWorker is the load generator: a benign openat loop in the current cgroup.
// It blocks on a start byte from stdin so the parent can place it in a fresh
// cgroup first, then loops until the parent kills it.
func runWorker() {
	var b [1]byte
	_, _ = os.Stdin.Read(b[:])

	path := envOr(envWorkerPath, "/etc/hostname")
	steps := atoiOr(os.Getenv(envWorkerSteps), 1)
	if steps < 1 {
		steps = 1
	}
	sleepNs := atoi64Or(os.Getenv(envWorkerSleepNs), 0)
	ts := unix.Timespec{Sec: sleepNs / 1_000_000_000, Nsec: sleepNs % 1_000_000_000}

	for {
		for i := 0; i < steps; i++ {
			if fd, err := unix.Open(path, unix.O_RDONLY, 0); err == nil {
				_ = unix.Close(fd)
			}
		}
		if sleepNs > 0 {
			_ = unix.Nanosleep(&ts, nil)
		}
	}
}

// worker is a spawned load generator and, optionally, the cgroup created for it.
type worker struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	cgDir string // "" when not placed in a dedicated cgroup
}

// spawnWorker starts a load-generating child. When cgDir is non-empty the child
// is moved into that cgroup before it begins its loop, so its syscalls are
// attributed to a distinct workload.
func spawnWorker(path string, steps int, sleepNs int64, cgDir string) (*worker, error) {
	self, err := os.Executable()
	if err != nil {
		self = os.Args[0]
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(),
		envWorker+"=1",
		envWorkerPath+"="+path,
		envWorkerSteps+"="+strconv.Itoa(steps),
		envWorkerSleepNs+"="+strconv.FormatInt(sleepNs, 10),
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	w := &worker{cmd: cmd, stdin: stdin, cgDir: cgDir}
	if cgDir != "" {
		if err := moveToCgroup(cgDir, cmd.Process.Pid); err != nil {
			fmt.Fprintf(os.Stderr, "ariguard-bench: move pid %d to cgroup: %v\n", cmd.Process.Pid, err)
		}
	}
	// Release the worker into its loop now that it is in its cgroup.
	_, _ = stdin.Write([]byte{1})
	return w, nil
}

// stop kills the worker, reaps it, and removes its cgroup directory.
func (w *worker) stop() {
	_ = w.stdin.Close()
	if w.cmd.Process != nil {
		_ = w.cmd.Process.Kill()
		_ = w.cmd.Wait()
	}
	if w.cgDir != "" {
		_ = os.Remove(w.cgDir)
	}
}

const cgroupRoot = "/sys/fs/cgroup"

// newBenchCgroup creates a fresh cgroup2 directory, mounting cgroup2 first if the
// hierarchy is absent (same approach as the integration harness).
func newBenchCgroup() (string, error) {
	if _, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.controllers")); err != nil {
		if err := unix.Mount("cgroup2", cgroupRoot, "cgroup2", 0, ""); err != nil {
			return "", fmt.Errorf("mount cgroup2: %w", err)
		}
	}
	return os.MkdirTemp(cgroupRoot, "ariguard-bench-")
}

// moveToCgroup writes pid into the cgroup's cgroup.procs file.
func moveToCgroup(dir string, pid int) error {
	return os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o644)
}

// openOut returns the CSV destination and a close function; "" means stdout.
func openOut(path string) (io.Writer, func() error, error) {
	if path == "" {
		return os.Stdout, func() error { return nil }, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}

// writeCSV writes rows (header first) in CSV format.
func writeCSV(w io.Writer, rows [][]string) error {
	cw := csv.NewWriter(w)
	if err := cw.WriteAll(rows); err != nil {
		return err
	}
	cw.Flush()
	return cw.Error()
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

func atoi64Or(s string, def int64) int64 {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	return def
}
