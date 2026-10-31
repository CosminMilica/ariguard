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
	if len(rules) != 1 || rules[0]["hits"].(float64) != 1 {
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

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
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
	if len(got) != 2 {
		t.Fatalf("incidents: %+v", got)
	}
	esc, killed := got[0], got[1]
	if esc.Pod != "esc-pod" || esc.Outcome != "detected" || esc.MaxState != "escalating" || esc.Steps != 1 {
		t.Fatalf("escalating incident: %+v", esc)
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
