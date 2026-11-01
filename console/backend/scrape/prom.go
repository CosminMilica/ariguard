// Package scrape polls agent /metrics endpoints and stores the results.
package scrape

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// Sample is one parsed Prometheus text-format sample.
type Sample struct {
	Name   string
	Labels map[string]string
	Value  float64
}

// ParseProm parses Prometheus text exposition format. Comments, blank lines and
// malformed lines are skipped; an optional trailing timestamp is ignored.
func ParseProm(r io.Reader) []Sample {
	var out []Sample
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		if s, ok := parseLine(line); ok {
			out = append(out, s)
		}
	}
	return out
}

// ProgramStat holds the lifetime counters for one eBPF program.
type ProgramStat struct {
	Runs      float64
	RunTimeNS float64
}

// PerfStats holds the per-node agent performance metrics derived from a scrape.
type PerfStats struct {
	BPFMapBytes float64
	// Programs is keyed by the `program` label (e.g. "sw_openat").
	Programs map[string]ProgramStat
}

// ExtractPerf pulls the performance metrics out of parsed samples: the single
// ariguard_bpf_map_bytes gauge and the per-program labeled counters
// ariguard_program_runs_total{program=...} / ariguard_program_run_time_ns_total{program=...}.
func ExtractPerf(samples []Sample) PerfStats {
	ps := PerfStats{Programs: map[string]ProgramStat{}}
	for _, s := range samples {
		switch s.Name {
		case "ariguard_bpf_map_bytes":
			ps.BPFMapBytes = s.Value
		case "ariguard_program_runs_total":
			if p := s.Labels["program"]; p != "" {
				st := ps.Programs[p]
				st.Runs = s.Value
				ps.Programs[p] = st
			}
		case "ariguard_program_run_time_ns_total":
			if p := s.Labels["program"]; p != "" {
				st := ps.Programs[p]
				st.RunTimeNS = s.Value
				ps.Programs[p] = st
			}
		}
	}
	return ps
}

func parseLine(line string) (Sample, bool) {
	s := Sample{Labels: map[string]string{}}
	i := strings.IndexAny(line, "{ \t")
	if i < 0 {
		return s, false
	}
	s.Name = line[:i]
	rest := line[i:]
	if rest[0] == '{' {
		end, ok := parseLabels(rest, s.Labels)
		if !ok {
			return s, false
		}
		rest = rest[end:]
	}
	fields := strings.Fields(rest)
	if len(fields) < 1 {
		return s, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return s, false
	}
	s.Value = v
	return s, s.Name != ""
}

// parseLabels parses `{k="v",...}` at the start of in and returns the index just
// past the closing brace.
func parseLabels(in string, dst map[string]string) (int, bool) {
	i := 1
	for {
		for i < len(in) && (in[i] == ' ' || in[i] == ',') {
			i++
		}
		if i >= len(in) {
			return 0, false
		}
		if in[i] == '}' {
			return i + 1, true
		}
		eq := strings.IndexByte(in[i:], '=')
		if eq < 0 {
			return 0, false
		}
		key := strings.TrimSpace(in[i : i+eq])
		i += eq + 1
		if i >= len(in) || in[i] != '"' {
			return 0, false
		}
		i++
		var val strings.Builder
		for {
			if i >= len(in) {
				return 0, false
			}
			c := in[i]
			if c == '\\' && i+1 < len(in) {
				switch in[i+1] {
				case 'n':
					val.WriteByte('\n')
				default:
					val.WriteByte(in[i+1])
				}
				i += 2
				continue
			}
			if c == '"' {
				i++
				break
			}
			val.WriteByte(c)
			i++
		}
		dst[key] = val.String()
	}
}
