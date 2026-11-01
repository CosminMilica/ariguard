package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestExport(t *testing.T) {
	srv := newServer(t)
	mustPost(t, srv, "/api/v1/register", `{"node":"n1","kernel":"6.8","enforce":true,"hooks_attached":3,"hooks_total":4,
		"bundle":{"rules":[{"name":"r1","scope":"pod","num_states":3,"window_ns":1000,"terminal_action":"kill"}]}}`)
	now := time.Now().UnixNano()
	ev := func(ts int64, from, to, action string, enforced bool, comm string, pid int, hook string) string {
		b, _ := json.Marshal(map[string]any{"ts_ns": ts, "rule": "r1", "event": "execve", "from": from, "to": to,
			"action": action, "enforced": enforced, "namespace": "ns", "pod": "p1", "node": "n1", "comm": comm, "pid": pid, "hook": hook})
		return string(b)
	}
	body := "[" + strings.Join([]string{
		ev(now-2000, "normal", "suspicious", "observe", false, "nginx", 100, "connect"),
		ev(now-1000, "suspicious", "compromised", "kill", true, "sh", 200, "execve"),
	}, ",") + "]"
	mustPost(t, srv, "/api/v1/audit", body)

	// missing pod -> 400
	if resp, err := http.Get(srv.URL + "/api/export"); err != nil || resp.StatusCode != 400 {
		t.Fatalf("missing pod: %v %v", err, resp)
	}

	resp, err := http.Get(srv.URL + "/api/export?pod=p1")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("export: %v %v", err, resp)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd != `attachment; filename="ariguard-incident-p1.json"` {
		t.Fatalf("content-disposition: %q", cd)
	}
	var got struct {
		GeneratedAtNS int64 `json:"generated_at_ns"`
		Incident      struct {
			Pod, Namespace, Node, Rule, Outcome string
			MaxState                            string `json:"max_state"`
			StartedNS                           int64  `json:"started_ts_ns"`
			EndedNS                             int64  `json:"ended_ts_ns"`
			Steps                               int
		}
		Chain []struct {
			TsNS                      int64 `json:"ts_ns"`
			Comm, Hook, Event, Action string
			FromState                 string `json:"from_state"`
			ToState                   string `json:"to_state"`
			Pid                       int
			Enforced                  bool
		}
		Rules []struct {
			Name, Scope    string
			TerminalAction string `json:"terminal_action"`
			NumStates      int    `json:"num_states"`
			WindowNS       int64  `json:"window_ns"`
		}
		Node struct {
			Node, Kernel  string
			Enforce       bool
			HooksAttached int `json:"hooks_attached"`
			HooksTotal    int `json:"hooks_total"`
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.GeneratedAtNS == 0 {
		t.Fatalf("generated_at_ns empty")
	}
	i := got.Incident
	if i.Pod != "p1" || i.Namespace != "ns" || i.Node != "n1" || i.Rule != "r1" || i.MaxState != "compromised" ||
		i.Outcome != "killed" || i.Steps != 2 || i.StartedNS != now-2000 || i.EndedNS != now-1000 {
		t.Fatalf("incident: %+v", i)
	}
	if len(got.Chain) != 2 {
		t.Fatalf("chain len: %+v", got.Chain)
	}
	c0, c1 := got.Chain[0], got.Chain[1]
	if c0.Comm != "nginx" || c0.Pid != 100 || c0.Hook != "connect" || c0.FromState != "normal" || c0.ToState != "suspicious" {
		t.Fatalf("chain[0]: %+v", c0)
	}
	if c1.Comm != "sh" || c1.Pid != 200 || c1.Action != "kill" || !c1.Enforced || c1.FromState != "suspicious" || c1.ToState != "compromised" {
		t.Fatalf("chain[1]: %+v", c1)
	}
	if len(got.Rules) != 1 || got.Rules[0].Name != "r1" || got.Rules[0].Scope != "pod" || got.Rules[0].NumStates != 3 ||
		got.Rules[0].WindowNS != 1000 || got.Rules[0].TerminalAction != "kill" {
		t.Fatalf("rules: %+v", got.Rules)
	}
	if got.Node.Node != "n1" || got.Node.Kernel != "6.8" || !got.Node.Enforce ||
		got.Node.HooksAttached != 3 || got.Node.HooksTotal != 4 {
		t.Fatalf("node: %+v", got.Node)
	}
}
