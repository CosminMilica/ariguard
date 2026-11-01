package api_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEventsFilters(t *testing.T) {
	srv := newServer(t)
	now := time.Now().UnixNano()
	ev := func(pod, ns, node, rule string) string {
		b, _ := json.Marshal(map[string]any{"ts_ns": now, "rule": rule, "event": "execve", "from": "normal",
			"to": "suspicious", "action": "observe", "enforced": false, "namespace": ns, "pod": pod, "node": node, "comm": "sh"})
		return string(b)
	}
	body := "[" + strings.Join([]string{
		ev("p1", "ns-a", "n1", "r1"),
		ev("p2", "ns-b", "n1", "r2"),
		ev("p3", "ns-a", "n2", "r1"),
	}, ",") + "]"
	mustPost(t, srv, "/api/v1/audit", body)

	var all []map[string]any
	mustGet(t, srv, "/api/events", &all)
	if len(all) != 3 {
		t.Fatalf("all: %d", len(all))
	}

	type rec struct{ Rule, Namespace, Node string }
	var byRule []rec
	mustGet(t, srv, "/api/events?rule=r1", &byRule)
	if len(byRule) != 2 {
		t.Fatalf("rule filter: %+v", byRule)
	}
	var byNS []rec
	mustGet(t, srv, "/api/events?namespace=ns-a", &byNS)
	if len(byNS) != 2 {
		t.Fatalf("namespace filter: %+v", byNS)
	}
	var byNode []rec
	mustGet(t, srv, "/api/events?node=n2", &byNode)
	if len(byNode) != 1 || byNode[0].Node != "n2" {
		t.Fatalf("node filter: %+v", byNode)
	}
	// Composable with existing q filter and with each other.
	var composed []rec
	mustGet(t, srv, "/api/events?rule=r1&namespace=ns-a&node=n1", &composed)
	if len(composed) != 1 || composed[0].Rule != "r1" || composed[0].Namespace != "ns-a" || composed[0].Node != "n1" {
		t.Fatalf("composed: %+v", composed)
	}
}
