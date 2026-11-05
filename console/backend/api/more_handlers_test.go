package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// evJSON builds one audit event body field.
func evJSON(ts int64, pod, rule, from, to, action string, enforced bool, extra map[string]any) string {
	m := map[string]any{
		"ts_ns": ts, "rule": rule, "event": "execve", "from": from, "to": to, "action": action,
		"enforced": enforced, "namespace": "ns", "pod": pod, "node": "n1", "comm": "sh", "hook": "execve",
	}
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func TestIncidentsHandler(t *testing.T) {
	srv := newServer(t)
	now := time.Now().UnixNano()
	body := "[" + strings.Join([]string{
		evJSON(now-2000, "p1", "reverse-shell", "normal", "suspicious", "observe", false, nil),
		evJSON(now-1000, "p1", "reverse-shell", "suspicious", "compromised", "kill", true,
			map[string]any{"owner": "Deployment/app"}),
	}, ",") + "]"
	mustPost(t, srv, "/api/v1/audit", body)

	var raw []map[string]any
	mustGet(t, srv, "/api/incidents?range=1h", &raw)
	if len(raw) != 1 {
		t.Fatalf("incidents=%d", len(raw))
	}
	i := raw[0]
	if i["pod"] != "p1" || i["outcome"] != "killed" || i["max_state"] != "compromised" || i["owner"] != "Deployment/app" {
		t.Fatalf("incident=%+v", i)
	}
}

func TestChainHandler(t *testing.T) {
	srv := newServer(t)
	now := time.Now().UnixNano()
	body := "[" + strings.Join([]string{
		evJSON(now-2000, "p1", "reverse-shell", "normal", "connected", "observe", false, nil),
		evJSON(now-1000, "p1", "reverse-shell", "connected", "compromised", "kill", true, nil),
	}, ",") + "]"
	mustPost(t, srv, "/api/v1/audit", body)

	var steps []map[string]any
	mustGet(t, srv, "/api/chain?pod=p1&range=1h", &steps)
	if len(steps) != 2 || steps[0]["state"] != "connected" || steps[1]["state"] != "compromised" {
		t.Fatalf("chain=%+v", steps)
	}
}

func TestOverviewHandler(t *testing.T) {
	srv := newServer(t)
	now := time.Now().UnixNano()
	mustPost(t, srv, "/api/v1/audit", "["+evJSON(now-1000, "p1", "r", "normal", "compromised", "kill", true, nil)+"]")
	var ov map[string]any
	mustGet(t, srv, "/api/overview?range=1h", &ov)
	if ov == nil {
		t.Fatal("overview empty")
	}
}

func TestNodesHandler(t *testing.T) {
	srv := newServer(t)
	mustPost(t, srv, "/api/v1/register",
		`{"node":"n1","kernel":"6.8","enforce":true,"hooks_attached":16,"hooks_total":16}`)
	var nodes []map[string]any
	mustGet(t, srv, "/api/nodes", &nodes)
	if len(nodes) != 1 || nodes[0]["node"] != "n1" || nodes[0]["kernel"] != "6.8" {
		t.Fatalf("nodes=%+v", nodes)
	}
}

func TestRulesHandler(t *testing.T) {
	srv := newServer(t)
	mustPost(t, srv, "/api/v1/register", `{"node":"n1","bundle":{"rules":[
		{"name":"reverse-shell","scope":"process","num_states":4,"terminal_action":"kill",
		 "states":["normal"],"events":["e"],"transitions":[{"from":"normal","event":"e","to":"normal","action":"observe","syscalls":["execve"]}]}]}}`)
	// a hit for that rule
	now := time.Now().UnixNano()
	mustPost(t, srv, "/api/v1/audit", "["+evJSON(now-500, "p1", "reverse-shell", "normal", "compromised", "kill", true, nil)+"]")
	var rules []map[string]any
	mustGet(t, srv, "/api/rules", &rules)
	if len(rules) != 1 || rules[0]["name"] != "reverse-shell" {
		t.Fatalf("rules=%+v", rules)
	}
}

func TestPerfHandler(t *testing.T) {
	srv := newServer(t)
	// no scraper data yet — the handler must still return a valid, empty-ish shape (SQL smoke).
	var perf struct {
		BPFMapBytes  int64 `json:"bpf_map_bytes"`
		AuditDropped int64 `json:"audit_dropped"`
		Programs     []any `json:"programs"`
	}
	mustGet(t, srv, "/api/perf", &perf)
	if perf.Programs == nil {
		// programs should be an empty array, not null, for the frontend
		t.Fatalf("perf programs is null")
	}
}

func TestMuteRoundTrip(t *testing.T) {
	srv := newServer(t)
	mustPost(t, srv, "/api/mutes", `{"pod":"p1"}`)
	var muted []string
	mustGet(t, srv, "/api/v1/mutes", &muted)
	if len(muted) != 1 || muted[0] != "p1" {
		t.Fatalf("muted=%+v", muted)
	}
	// empty pod is rejected
	resp, _ := http.Post(srv.URL+"/api/mutes", "application/json", strings.NewReader(`{"pod":""}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty mute: status=%d", resp.StatusCode)
	}
	// unmute
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/mutes/p1", nil)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unmute: status=%d", resp.StatusCode)
	}
	mustGet(t, srv, "/api/v1/mutes", &muted)
	if len(muted) != 0 {
		t.Fatalf("still muted: %+v", muted)
	}
}

func TestObserveNamespaceRoundTrip(t *testing.T) {
	srv := newServer(t)
	mustPost(t, srv, "/api/observe-namespaces", `{"namespace":"ariguard-honeypot"}`)
	// the frontend reads /api/observe-namespaces; the agent polls /api/v1/observe-namespaces
	var ui, agent []string
	mustGet(t, srv, "/api/observe-namespaces", &ui)
	mustGet(t, srv, "/api/v1/observe-namespaces", &agent)
	if len(ui) != 1 || ui[0] != "ariguard-honeypot" || len(agent) != 1 || agent[0] != "ariguard-honeypot" {
		t.Fatalf("ui=%+v agent=%+v", ui, agent)
	}
	// empty namespace is rejected
	resp, _ := http.Post(srv.URL+"/api/observe-namespaces", "application/json", strings.NewReader(`{"namespace":""}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty observe: status=%d", resp.StatusCode)
	}
	// remove it
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/observe-namespaces/ariguard-honeypot", nil)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unobserve: status=%d", resp.StatusCode)
	}
	mustGet(t, srv, "/api/v1/observe-namespaces", &agent)
	if len(agent) != 0 {
		t.Fatalf("still observed: %+v", agent)
	}
}
