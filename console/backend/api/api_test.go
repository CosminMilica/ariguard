package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CosminMilica/ariguard/console/backend/api"
	"github.com/CosminMilica/ariguard/console/backend/ingest"
	"github.com/CosminMilica/ariguard/console/backend/store"
)

func TestIngestAndRead(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mux := http.NewServeMux()
	(&ingest.Handler{DB: db}).Routes(mux)
	(&api.API{DB: db}).Routes(mux)
	srv := httptest.NewServer(api.CORS(mux))
	defer srv.Close()

	post := func(path, body string) {
		t.Helper()
		resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader(body))
		if err != nil || resp.StatusCode >= 300 {
			t.Fatalf("POST %s: %v %v", path, err, resp)
		}
	}
	get := func(path string, v any) {
		t.Helper()
		resp, err := http.Get(srv.URL + path)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("GET %s: %v %v", path, err, resp)
		}
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			t.Fatal(err)
		}
	}

	post("/api/v1/register", `{"node":"n1","kernel":"6.8","enforce":true,"hooks_attached":3,"hooks_total":4,
		"audit_ring_bytes":4096,"metrics_addr":"127.0.0.1:9","bundle":{"rules":[{"name":"r1","scope":"pod","num_states":5,"window_ns":1000,"terminal_action":"kill"}]}}`)
	now := time.Now().UnixNano()
	ev := func(to, pod string) string {
		return `{"ts_ns":` + itoa(now) + `,"rule":"r1","event":"execve","from":"normal","to":"` + to + `","action":"kill","enforced":true,"namespace":"ns","pod":"` + pod + `","node":"n1","comm":"sh"}`
	}
	post("/api/v1/audit", "["+ev("suspicious", "p1")+","+ev("compromised", "p1")+","+ev("escalating", "p2")+"]")

	var wl []map[string]any
	get("/api/workloads?filter=alerting", &wl)
	if len(wl) != 2 {
		t.Fatalf("workloads: %v", wl)
	}
	var evs []map[string]any
	get("/api/events?severity=crit", &evs)
	if len(evs) != 1 || evs[0]["severity"] != "crit" {
		t.Fatalf("events: %v", evs)
	}
	var rules []map[string]any
	get("/api/rules", &rules)
	if len(rules) != 1 || rules[0]["hits"].(float64) != 3 { // 3 enforced-kill events = 3 mitigations
		t.Fatalf("rules: %v", rules)
	}
	var chain []map[string]any
	get("/api/chain?pod=p1", &chain)
	if len(chain) != 2 || chain[1]["state"] != "compromised" {
		t.Fatalf("chain: %v", chain)
	}

	post("/api/v1/audit", `[{"ts_ns":`+itoa(now)+`,"rule":"r1","event":"openat","from":"normal","to":"","action":"observe","enforced":false,"namespace":"ns","pod":"p3","node":"n1","comm":"ls"}]`)
	var all, sig []map[string]any
	get("/api/events", &all)
	get("/api/events?significant=1", &sig)
	if len(all) != 4 || len(sig) != 3 {
		t.Fatalf("significant: all=%d sig=%d", len(all), len(sig))
	}

	nowMS := time.Now().UnixMilli()
	var win []map[string]any
	get("/api/events?from="+itoa(nowMS-60000)+"&to="+itoa(nowMS+60000), &win)
	if len(win) != 4 {
		t.Fatalf("window in: %v", win)
	}
	get("/api/events?from="+itoa(nowMS-7200000)+"&to="+itoa(nowMS-3600000), &win)
	if len(win) != 0 {
		t.Fatalf("window out: %v", win)
	}
	var ovw struct {
		Kpis         map[string]float64    `json:"kpis"`
		EventsSeries []any                 `json:"events_series"`
		KillsSeries  []struct{ V float64 } `json:"kills_series"`
	}
	get("/api/overview?from="+itoa(nowMS-60000)+"&to="+itoa(nowMS+60000), &ovw)
	var sum float64
	for _, p := range ovw.KillsSeries {
		sum += p.V
	}
	if ovw.Kpis["kills"] != 3 || sum != 3 || len(ovw.EventsSeries) != 60 {
		t.Fatalf("overview window: %+v sum=%v", ovw, sum)
	}
	get("/api/overview?from="+itoa(nowMS-7200000)+"&to="+itoa(nowMS-3600000), &ovw)
	if ovw.Kpis["kills"] != 0 {
		t.Fatalf("overview out of window: %+v", ovw)
	}
	var rw []map[string]any
	get("/api/rules?from="+itoa(nowMS-7200000)+"&to="+itoa(nowMS-3600000), &rw)
	if rw[0]["hits"].(float64) != 0 {
		t.Fatalf("rules window: %v", rw)
	}

	post("/api/mutes", `{"pod":"p1"}`)
	get("/api/workloads", &wl)
	if len(wl) != 1 {
		t.Fatalf("muted workloads: %v", wl)
	}
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/mutes/p1", nil)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 204 {
		t.Fatalf("unmute: %v %v", err, resp)
	}

	var ov struct {
		Kpis          map[string]float64 `json:"kpis"`
		EventsSeries  []any              `json:"events_series"`
		StateBreakdwn map[string]int     `json:"state_breakdown"`
	}
	get("/api/overview?range=1h", &ov)
	if ov.Kpis["workloads"] != 2 || ov.Kpis["agents"] != 1 || ov.Kpis["rules"] != 1 || len(ov.EventsSeries) != 60 {
		t.Fatalf("overview: %+v", ov)
	}
	var st map[string]any
	get("/api/settings", &st)
	if st["enforce"] != true || st["kernel"] != "6.8" {
		t.Fatalf("settings: %v", st)
	}
	var nodes []map[string]any
	get("/api/nodes", &nodes)
	if len(nodes) != 1 || nodes[0]["status"] != "ready" {
		t.Fatalf("nodes: %v", nodes)
	}
}

func TestOverviewMitigationsCountsDenies(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "o.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mux := http.NewServeMux()
	(&ingest.Handler{DB: db}).Routes(mux)
	(&api.API{DB: db}).Routes(mux)
	srv := httptest.NewServer(api.CORS(mux))
	defer srv.Close()

	now := time.Now().UnixNano()
	ev := func(pod, action string, enforced bool) string {
		b, _ := json.Marshal(map[string]any{"ts_ns": now, "rule": "r1", "event": "execve", "from": "normal",
			"to": "compromised", "action": action, "enforced": enforced, "namespace": "ns", "pod": pod, "node": "n1", "comm": "sh"})
		return string(b)
	}
	body := "[" + strings.Join([]string{
		ev("kp", "kill", true),  // enforced kill
		ev("dp", "deny", true),  // enforced deny -> counts as a mitigation
		ev("dp", "deny", false), // detection-only deny -> excluded
	}, ",") + "]"
	resp, err := http.Post(srv.URL+"/api/v1/audit", "application/json", strings.NewReader(body))
	if err != nil || resp.StatusCode >= 300 {
		t.Fatalf("audit: %v %v", err, resp)
	}

	var ovw struct {
		Kpis        map[string]float64    `json:"kpis"`
		KillsSeries []struct{ V float64 } `json:"kills_series"`
	}
	nowMS := time.Now().UnixMilli()
	resp, err = http.Get(srv.URL + "/api/overview?from=" + itoa(nowMS-60000) + "&to=" + itoa(nowMS+60000))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("overview: %v %v", err, resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(&ovw); err != nil {
		t.Fatal(err)
	}
	var sum float64
	for _, p := range ovw.KillsSeries {
		sum += p.V
	}
	if ovw.Kpis["kills"] != 2 || sum != 2 {
		t.Fatalf("mitigations KPI/series: kills=%v sum=%v", ovw.Kpis["kills"], sum)
	}
}

func TestRulesDetail(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "rd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mux := http.NewServeMux()
	(&ingest.Handler{DB: db}).Routes(mux)
	(&api.API{DB: db}).Routes(mux)
	srv := httptest.NewServer(api.CORS(mux))
	defer srv.Close()

	// Register the same rule from two nodes; the detail (state machine) is shared.
	reg := `{"node":"%s","kernel":"6.8","bundle":{"rules":[{"name":"r1","scope":"pod","num_states":3,
		"window_ns":1000,"terminal_action":"kill","states":["normal","suspicious","compromised"],
		"events":["execve","openat"],"terminal_from":2,
		"transitions":[{"from":"normal","event":"execve","to":"suspicious","action":"observe"},
		{"from":"suspicious","event":"openat","to":"compromised","action":"kill","syscalls":["ptrace arg0 == 16"]}]}]}}`
	for _, node := range []string{"n1", "n2"} {
		resp, err := http.Post(srv.URL+"/api/v1/register", "application/json",
			strings.NewReader(strings.Replace(reg, "%s", node, 1)))
		if err != nil || resp.StatusCode >= 300 {
			t.Fatalf("register %s: %v %v", node, err, resp)
		}
	}

	var rules []struct {
		Name         string   `json:"name"`
		States       []string `json:"states"`
		Events       []string `json:"events"`
		TerminalFrom int      `json:"terminal_from"`
		Transitions  []struct {
			From, Event, To, Action string
			Syscalls                []string `json:"syscalls"`
		} `json:"transitions"`
	}
	resp, err := http.Get(srv.URL + "/api/rules")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("GET /api/rules: %v %v", err, resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(&rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("rules: %+v", rules)
	}
	r := rules[0]
	if r.Name != "r1" || len(r.States) != 3 || r.States[2] != "compromised" {
		t.Fatalf("states: %+v", r)
	}
	if len(r.Events) != 2 || r.Events[1] != "openat" || r.TerminalFrom != 2 {
		t.Fatalf("events/terminal_from: %+v", r)
	}
	if len(r.Transitions) != 2 || r.Transitions[1].From != "suspicious" ||
		r.Transitions[1].Event != "openat" || r.Transitions[1].To != "compromised" ||
		r.Transitions[1].Action != "kill" {
		t.Fatalf("transitions: %+v", r.Transitions)
	}
	if len(r.Transitions[1].Syscalls) != 1 || r.Transitions[1].Syscalls[0] != "ptrace arg0 == 16" {
		t.Fatalf("syscalls: %+v", r.Transitions)
	}
}

func TestAnalysisFields(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mux := http.NewServeMux()
	(&ingest.Handler{DB: db}).Routes(mux)
	(&api.API{DB: db}).Routes(mux)
	srv := httptest.NewServer(api.CORS(mux))
	defer srv.Close()

	now := time.Now().UnixNano()
	ev := func(ts int64, to, action string, pid int, comm, hook string) string {
		b, _ := json.Marshal(map[string]any{"ts_ns": ts, "cgroup_id": 42, "pid": pid, "comm": comm, "hook": hook,
			"rule": "r1", "event": "execve", "from": "normal", "to": to, "action": action, "enforced": true,
			"namespace": "ns", "pod": "p1", "node": "n1"})
		return string(b)
	}
	body := "[" + strings.Join([]string{
		ev(now-2000, "suspicious", "observe", 1234, "nginx", "connect"),
		ev(now-1000, "compromised", "kill", 1234, "sh", "execve"),
	}, ",") + "]"
	resp, err := http.Post(srv.URL+"/api/v1/audit", "application/json", strings.NewReader(body))
	if err != nil || resp.StatusCode >= 300 {
		t.Fatalf("audit: %v %v", err, resp)
	}

	type rec struct {
		Comm string `json:"comm"`
		Pid  int    `json:"pid"`
		Hook string `json:"hook"`
	}
	get := func(path string, v any) {
		t.Helper()
		resp, err := http.Get(srv.URL + path)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("GET %s: %v %v", path, err, resp)
		}
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			t.Fatal(err)
		}
	}

	// /api/events returns newest first; the kill step carries sh/1234/execve.
	var evs []rec
	get("/api/events", &evs)
	if len(evs) != 2 {
		t.Fatalf("events: %+v", evs)
	}
	if evs[0].Comm != "sh" || evs[0].Pid != 1234 || evs[0].Hook != "execve" {
		t.Fatalf("event analysis fields: %+v", evs[0])
	}
	if evs[1].Comm != "nginx" || evs[1].Pid != 1234 || evs[1].Hook != "connect" {
		t.Fatalf("event analysis fields: %+v", evs[1])
	}

	// /api/chain is ordered oldest first.
	var chain []rec
	get("/api/chain?pod=p1", &chain)
	if len(chain) != 2 {
		t.Fatalf("chain: %+v", chain)
	}
	if chain[0].Comm != "nginx" || chain[0].Pid != 1234 || chain[0].Hook != "connect" {
		t.Fatalf("chain analysis fields: %+v", chain[0])
	}
	if chain[1].Comm != "sh" || chain[1].Pid != 1234 || chain[1].Hook != "execve" {
		t.Fatalf("chain analysis fields: %+v", chain[1])
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestPerf(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "perf.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mux := http.NewServeMux()
	(&api.API{DB: db}).Routes(mux)
	srv := httptest.NewServer(api.CORS(mux))
	defer srv.Close()

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	// Two nodes share the same constant BPF map budget; per-program counters
	// are summed across nodes (sw_openat totals 400 runs / 20000 ns).
	exec(`INSERT INTO nodes(node,metrics_addr,bpf_map_bytes,last_seen) VALUES('n1','a',1048576,?)`, time.Now().UnixMilli())
	exec(`INSERT INTO nodes(node,metrics_addr,bpf_map_bytes,last_seen) VALUES('n2','b',1048576,?)`, time.Now().UnixMilli())
	exec(`INSERT INTO program_stats(node,program,runs,run_time_ns,updated) VALUES('n1','sw_openat',300,15000,0)`)
	exec(`INSERT INTO program_stats(node,program,runs,run_time_ns,updated) VALUES('n2','sw_openat',100,5000,0)`)
	exec(`INSERT INTO program_stats(node,program,runs,run_time_ns,updated) VALUES('n1','sw_connect',0,0,0)`)
	// Two samples on n1 give events_per_sec = (110-100)/1s = 10 and audit_dropped = 7.
	now := time.Now().UnixMilli()
	exec(`INSERT INTO metric_samples(ts,node,events,kills,denies,audit_dropped) VALUES(?,'n1',100,0,0,0)`, now-1000)
	exec(`INSERT INTO metric_samples(ts,node,events,kills,denies,audit_dropped) VALUES(?,'n1',110,0,0,7)`, now)

	var got struct {
		BPFMapBytes  int64   `json:"bpf_map_bytes"`
		EventsPerSec float64 `json:"events_per_sec"`
		AuditDropped int64   `json:"audit_dropped"`
		Programs     []struct {
			Program  string  `json:"program"`
			Runs     int64   `json:"runs"`
			NsPerRun float64 `json:"ns_per_run"`
		} `json:"programs"`
	}
	resp, err := http.Get(srv.URL + "/api/perf")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("GET /api/perf: %v %v", err, resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.BPFMapBytes != 1048576 {
		t.Errorf("bpf_map_bytes: %d", got.BPFMapBytes)
	}
	if got.EventsPerSec != 10 {
		t.Errorf("events_per_sec: %v", got.EventsPerSec)
	}
	if got.AuditDropped != 7 {
		t.Errorf("audit_dropped: %d", got.AuditDropped)
	}
	if len(got.Programs) != 2 {
		t.Fatalf("programs: %+v", got.Programs)
	}
	// Sorted by name: sw_connect (runs=0 -> ns_per_run=0), then sw_openat.
	if got.Programs[0].Program != "sw_connect" || got.Programs[0].Runs != 0 || got.Programs[0].NsPerRun != 0 {
		t.Errorf("sw_connect: %+v", got.Programs[0])
	}
	if got.Programs[1].Program != "sw_openat" || got.Programs[1].Runs != 400 || got.Programs[1].NsPerRun != 50 {
		t.Errorf("sw_openat: %+v", got.Programs[1])
	}
}

func TestIncidents(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "i.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mux := http.NewServeMux()
	(&ingest.Handler{DB: db}).Routes(mux)
	(&api.API{DB: db}).Routes(mux)
	srv := httptest.NewServer(api.CORS(mux))
	defer srv.Close()

	now := time.Now().UnixNano()
	old := now - int64(2*time.Hour)
	ev := func(ts int64, pod, rule, from, to, action string, enforced bool) string {
		b, _ := json.Marshal(map[string]any{"ts_ns": ts, "rule": rule, "event": "execve", "from": from, "to": to,
			"action": action, "enforced": enforced, "namespace": "ns", "pod": pod, "node": "n1", "comm": "sh"})
		return string(b)
	}
	body := "[" + strings.Join([]string{
		ev(now-3000, "killed-pod", "r1", "normal", "suspicious", "observe", false),
		ev(now-2000, "killed-pod", "r1", "suspicious", "compromised", "kill", true),
		ev(now-1000, "killed-pod", "r1", "compromised", "compromised", "observe", false),
		ev(now-900, "deny-pod", "r1", "normal", "escalating", "deny", false),
		ev(now-800, "deny-pod", "r1", "escalating", "escalating", "deny", true),
		ev(now-500, "esc-pod", "r1", "normal", "escalating", "observe", false),
		ev(now-400, "benign-pod", "r1", "normal", "normal", "observe", false),
		ev(old, "old-pod", "r1", "normal", "compromised", "kill", true),
		ev(old, "esc-pod", "r1", "normal", "compromised", "kill", true),
	}, ",") + "]"
	resp, err := http.Post(srv.URL+"/api/v1/audit", "application/json", strings.NewReader(body))
	if err != nil || resp.StatusCode >= 300 {
		t.Fatalf("audit: %v %v", err, resp)
	}

	type inc struct {
		Pod, Namespace, Node, Rule string
		StartedNS                  int64  `json:"started_ts_ns"`
		EndedNS                    int64  `json:"ended_ts_ns"`
		MaxState                   string `json:"max_state"`
		Outcome                    string
		Steps                      int
	}
	get := func(path string) []inc {
		t.Helper()
		resp, err := http.Get(srv.URL + path)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("GET %s: %v %v", path, err, resp)
		}
		var v []inc
		if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	got := get("/api/incidents?range=1h")
	if len(got) != 3 {
		t.Fatalf("incidents: %+v", got)
	}
	esc, deny, killed := got[0], got[1], got[2]
	if esc.Pod != "esc-pod" || esc.Outcome != "detected" || esc.MaxState != "escalating" || esc.Steps != 1 {
		t.Fatalf("escalating incident: %+v", esc)
	}
	if deny.Pod != "deny-pod" || deny.Outcome != "blocked" || deny.MaxState != "escalating" || deny.Steps != 2 {
		t.Fatalf("deny incident: %+v", deny)
	}
	if killed.Pod != "killed-pod" || killed.Outcome != "killed" || killed.MaxState != "compromised" || killed.Steps != 3 ||
		killed.StartedNS != now-3000 || killed.EndedNS != now-1000 || killed.Node != "n1" || killed.Namespace != "ns" || killed.Rule != "r1" {
		t.Fatalf("killed incident: %+v", killed)
	}

	nowMS := time.Now().UnixMilli()
	if out := get("/api/incidents?from=" + itoa(nowMS-7300000) + "&to=" + itoa(nowMS-7000000)); len(out) != 2 {
		t.Fatalf("old window: %+v", out)
	}
	if out := get("/api/incidents?from=" + itoa(nowMS-20000000) + "&to=" + itoa(nowMS-10000000)); len(out) != 0 {
		t.Fatalf("empty window: %+v", out)
	}
}
