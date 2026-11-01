package scrape

import (
	"strings"
	"testing"
)

func TestParseProm(t *testing.T) {
	in := `# HELP ariguard_events_total Events.
# TYPE ariguard_events_total counter
ariguard_events_total 12345
ariguard_kills_total 3 1700000000000
ariguard_workload_state{pod="web-1",namespace="default",node="n1",comm="sh",rule="r, \"x\""} 2
ariguard_workload_state{pod="db}",namespace="p"} 0

garbage line
bad_value 12abc
ariguard_inf +Inf
ariguard_denies_total 2
unterminated{a="b 1
`
	got := ParseProm(strings.NewReader(in))
	if len(got) != 6 {
		t.Fatalf("got %d samples, want 6: %+v", len(got), got)
	}
	if got[5].Name != "ariguard_denies_total" || got[5].Value != 2 {
		t.Errorf("bad denies counter: %+v", got[5])
	}
	if got[0].Name != "ariguard_events_total" || got[0].Value != 12345 {
		t.Errorf("bad counter: %+v", got[0])
	}
	if got[1].Value != 3 {
		t.Errorf("timestamp not ignored: %+v", got[1])
	}
	g := got[2]
	if g.Labels["pod"] != "web-1" || g.Labels["rule"] != `r, "x"` || g.Value != 2 {
		t.Errorf("bad gauge: %+v", g)
	}
	if got[3].Labels["pod"] != "db}" {
		t.Errorf("brace in label value: %+v", got[3])
	}
}

func TestExtractPerf(t *testing.T) {
	in := `# HELP ariguard_bpf_map_bytes BPF map budget.
# TYPE ariguard_bpf_map_bytes gauge
ariguard_bpf_map_bytes 1048576
ariguard_program_runs_total{program="sw_openat"} 400
ariguard_program_run_time_ns_total{program="sw_openat"} 20000
ariguard_program_runs_total{program="sw_connect"} 0
ariguard_program_run_time_ns_total{program="sw_connect"} 0
ariguard_events_total 99
`
	perf := ExtractPerf(ParseProm(strings.NewReader(in)))
	if perf.BPFMapBytes != 1048576 {
		t.Errorf("bpf_map_bytes: got %v", perf.BPFMapBytes)
	}
	if len(perf.Programs) != 2 {
		t.Fatalf("programs: %+v", perf.Programs)
	}
	openat := perf.Programs["sw_openat"]
	if openat.Runs != 400 || openat.RunTimeNS != 20000 {
		t.Errorf("sw_openat: %+v", openat)
	}
	connect := perf.Programs["sw_connect"]
	if connect.Runs != 0 || connect.RunTimeNS != 0 {
		t.Errorf("sw_connect: %+v", connect)
	}
}
