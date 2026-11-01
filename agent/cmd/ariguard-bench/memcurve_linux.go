//go:build linux

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"

	"github.com/CosminMilica/ariguard/agent/internal/loader"
	"github.com/CosminMilica/ariguard/pkg/fsm"
)

// runMemcurve is the flat-memory experiment. For each N in --sweep it starts N
// benign workers, each in its own cgroup, lets them settle, then samples the
// agent's user-space RSS, the constant pre-allocated BPF map budget, and the live
// AG_STATE entry count. CSV: n,agent_rss_kb,bpf_map_bytes,state_entries.
func runMemcurve(args []string) error {
	fs := flag.NewFlagSet("memcurve", flag.ExitOnError)
	sweep := fs.String("sweep", "1,10,100,500,1000", "comma-separated worker counts")
	settle := fs.Duration("settle", 3*time.Second, "time to let workers run before sampling")
	steps := fs.Int("workload-steps", 1, "openat calls each worker does per batch")
	out := fs.String("out", "", `CSV output file ("" = stdout)`)
	if err := fs.Parse(args); err != nil {
		return err
	}

	ns, err := parseSweep(*sweep)
	if err != nil {
		return err
	}
	budget := bpfMapBudget()

	rows := [][]string{{"n", "agent_rss_kb", "bpf_map_bytes", "state_entries"}}
	for _, n := range ns {
		workers, err := startWorkers(n, *steps)
		if err != nil {
			stopWorkers(workers)
			return fmt.Errorf("start %d workers: %w", n, err)
		}
		time.Sleep(*settle)

		rssKB, err := agentRSSKB()
		if err != nil {
			stopWorkers(workers)
			return err
		}
		stateField := ""
		if entries, ok := countStateEntries(); ok {
			stateField = strconv.Itoa(entries)
		}

		rows = append(rows, []string{
			strconv.Itoa(n),
			strconv.FormatUint(rssKB, 10),
			strconv.FormatUint(budget, 10),
			stateField,
		})
		stopWorkers(workers)
	}

	w, closeOut, err := openOut(*out)
	if err != nil {
		return err
	}
	defer func() { _ = closeOut() }()
	return writeCSV(w, rows)
}

// startWorkers spawns n benign openat workers, each in a fresh cgroup. The 1 ms
// nanosleep keeps them lightweight while still generating steady syscall traffic.
func startWorkers(n, steps int) ([]*worker, error) {
	workers := make([]*worker, 0, n)
	for i := 0; i < n; i++ {
		cg, err := newBenchCgroup()
		if err != nil {
			return workers, err
		}
		w, err := spawnWorker("/etc/hostname", steps, 1_000_000, cg)
		if err != nil {
			_ = os.Remove(cg)
			return workers, err
		}
		workers = append(workers, w)
	}
	return workers, nil
}

func stopWorkers(workers []*worker) {
	for _, w := range workers {
		w.stop()
	}
}

func parseSweep(s string) ([]int, error) {
	var out []int
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		n, err := strconv.Atoi(f)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("bad sweep value %q", f)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty sweep")
	}
	return out, nil
}

// bpfMapBudget is the pre-allocated, constant memory budget of the AG_* contract
// maps. It does not vary with the number of tracked workloads, which is what the
// flat-memory curve demonstrates.
func bpfMapBudget() uint64 {
	return fsm.BPFMapBytes()
}

// agentRSSKB reads VmRSS (kB) of the running agent process from /proc.
func agentRSSKB() (uint64, error) {
	pid, err := findAgentPID()
	if err != nil {
		return 0, err
	}
	f, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line) // "VmRSS:", "<kB>", "kB"
		if len(fields) < 2 {
			return 0, fmt.Errorf("malformed VmRSS line %q", line)
		}
		return strconv.ParseUint(fields[1], 10, 64)
	}
	return 0, fmt.Errorf("VmRSS not found for pid %d", pid)
}

// findAgentPID returns the pid whose /proc/<pid>/comm is the agent's.
func findAgentPID() (int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) == agentComm {
			return pid, nil
		}
	}
	return 0, fmt.Errorf("agent process %q not found; is the agent running?", agentComm)
}

// countStateEntries counts the live entries in AG_STATE by locating the loaded map
// by name and iterating it. Returns (count, true) when the map is readable.
func countStateEntries() (int, bool) {
	var id ebpf.MapID
	for {
		next, err := ebpf.MapGetNextID(id)
		if err != nil {
			return 0, false // no AG_STATE found
		}
		id = next
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue
		}
		info, err := m.Info()
		if err != nil || info.Name != loader.MapState {
			_ = m.Close()
			continue
		}
		count := 0
		var k fsm.FsmKey
		var v fsm.FsmState
		it := m.Iterate()
		for it.Next(&k, &v) {
			count++
		}
		err = it.Err()
		_ = m.Close()
		if err != nil {
			return 0, false
		}
		return count, true
	}
}
