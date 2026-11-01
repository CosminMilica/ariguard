//go:build linux

package main

import (
	"flag"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/CosminMilica/ariguard/agent/internal/loader"
)

// runLatency enables BPF run-time statistics, waits a sampling window during
// which load is applied externally, then reports per-program run counts and
// per-run cost for every ariguard program. CSV: program,run_count,run_time_ns,ns_per_run.
func runLatency(args []string) error {
	fs := flag.NewFlagSet("latency", flag.ExitOnError)
	window := fs.Duration("window", 10*time.Second, "sampling window during which load is applied externally")
	out := fs.String("out", "", `CSV output file ("" = stdout)`)
	if err := fs.Parse(args); err != nil {
		return err
	}

	closer, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }()

	time.Sleep(*window)

	stats, err := ariguardProgramStats()
	if err != nil {
		return err
	}

	rows := [][]string{{"program", "run_count", "run_time_ns", "ns_per_run"}}
	for _, s := range stats {
		var nsPerRun uint64
		if s.runCount > 0 {
			nsPerRun = s.runTimeNs / s.runCount
		}
		rows = append(rows, []string{
			s.name,
			strconv.FormatUint(s.runCount, 10),
			strconv.FormatUint(s.runTimeNs, 10),
			strconv.FormatUint(nsPerRun, 10),
		})
	}

	w, closeOut, err := openOut(*out)
	if err != nil {
		return err
	}
	defer func() { _ = closeOut() }()
	return writeCSV(w, rows)
}

type progStat struct {
	name      string
	runCount  uint64
	runTimeNs uint64
}

// ariguardProgramStats enumerates loaded programs and returns, for each one whose
// name carries an ariguard prefix, its accumulated run count and run time. Results
// are sorted by name for stable output.
func ariguardProgramStats() ([]progStat, error) {
	var out []progStat
	var id ebpf.ProgramID
	for {
		next, err := ebpf.ProgramGetNextID(id)
		if err != nil {
			break // ErrNotExist: no more programs
		}
		id = next
		p, err := ebpf.NewProgramFromID(id)
		if err != nil {
			continue
		}
		info, err := p.Info()
		if err != nil || !isAriguardProgram(info.Name) {
			_ = p.Close()
			continue
		}
		st, err := p.Stats()
		_ = p.Close()
		if err != nil {
			continue
		}
		out = append(out, progStat{
			name:      info.Name,
			runCount:  st.RunCount,
			runTimeNs: uint64(st.Runtime.Nanoseconds()),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

func isAriguardProgram(name string) bool {
	return strings.HasPrefix(name, loader.ProgramPrefix) || strings.HasPrefix(name, loader.LSMProgramPrefix)
}
