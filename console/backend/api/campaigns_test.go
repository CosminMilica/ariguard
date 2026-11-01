package api_test

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestCampaigns(t *testing.T) {
	srv := newServer(t)
	now := time.Now().UnixNano()
	ev := func(ts int64, pod, ns, rule, to, action string, enforced bool) string {
		b, _ := json.Marshal(map[string]any{"ts_ns": ts, "rule": rule, "event": "execve", "from": "normal", "to": to,
			"action": action, "enforced": enforced, "namespace": ns, "pod": pod, "node": "n1", "comm": "sh"})
		return string(b)
	}
	body := "[" + strings.Join([]string{
		ev(now-3000, "p1", "ns-a", "r1", "compromised", "kill", true),    // r1/ns-a killed
		ev(now-2000, "p2", "ns-b", "r1", "escalating", "observe", false), // r1/ns-b detected
		ev(now-1000, "p3", "ns-a", "r2", "escalating", "deny", true),     // r2/ns-a blocked
	}, ",") + "]"
	mustPost(t, srv, "/api/v1/audit", body)

	type ruleC struct {
		Rule                               string
		Incidents, Pods, Namespaces, Nodes int
		Killed, Blocked, Detected          int
		AffectedNS                         []string `json:"affected_namespaces"`
		AffectedNodes                      []string `json:"affected_nodes"`
	}
	type nsC struct {
		Namespace                     string
		Incidents, Pods, Rules, Nodes int
		Killed, Blocked, Detected     int
		AffectedRules                 []string `json:"affected_rules"`
	}
	var got struct {
		ByRule []ruleC `json:"by_rule"`
		ByNS   []nsC   `json:"by_namespace"`
	}
	mustGet(t, srv, "/api/campaigns?range=1h", &got)

	if len(got.ByRule) != 2 {
		t.Fatalf("by_rule: %+v", got.ByRule)
	}
	r1 := got.ByRule[0]
	if r1.Rule != "r1" || r1.Incidents != 2 || r1.Pods != 2 || r1.Namespaces != 2 || r1.Nodes != 1 ||
		r1.Killed != 1 || r1.Blocked != 0 || r1.Detected != 1 {
		t.Fatalf("r1: %+v", r1)
	}
	sort.Strings(r1.AffectedNS)
	if strings.Join(r1.AffectedNS, ",") != "ns-a,ns-b" || strings.Join(r1.AffectedNodes, ",") != "n1" {
		t.Fatalf("r1 affected: %+v", r1)
	}
	r2 := got.ByRule[1]
	if r2.Rule != "r2" || r2.Incidents != 1 || r2.Blocked != 1 || r2.Killed != 0 || r2.Detected != 0 {
		t.Fatalf("r2: %+v", r2)
	}

	if len(got.ByNS) != 2 {
		t.Fatalf("by_namespace: %+v", got.ByNS)
	}
	nsa := got.ByNS[0]
	if nsa.Namespace != "ns-a" || nsa.Incidents != 2 || nsa.Pods != 2 || nsa.Rules != 2 ||
		nsa.Killed != 1 || nsa.Blocked != 1 || nsa.Detected != 0 {
		t.Fatalf("ns-a: %+v", nsa)
	}
	sort.Strings(nsa.AffectedRules)
	if strings.Join(nsa.AffectedRules, ",") != "r1,r2" {
		t.Fatalf("ns-a rules: %+v", nsa)
	}
	if got.ByNS[1].Namespace != "ns-b" || got.ByNS[1].Detected != 1 {
		t.Fatalf("ns-b: %+v", got.ByNS[1])
	}
}
