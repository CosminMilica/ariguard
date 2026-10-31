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
unterminated{a="b 1
`
	got := ParseProm(strings.NewReader(in))
	if len(got) != 5 {
		t.Fatalf("got %d samples, want 5: %+v", len(got), got)
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
