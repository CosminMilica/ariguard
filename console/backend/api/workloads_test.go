package api_test

import (
	"encoding/json"
	"testing"
	"time"
)

// A bare outbound connect (reverse-shell `connected` state) is benign — every pod makes
// connections — so it must not count as alerting. Only real threat states do.
func TestAlertingExcludesConnected(t *testing.T) {
	srv := newServer(t)
	now := time.Now().UnixNano()
	ev := func(to, pod, rule, event string) string {
		b, _ := json.Marshal(map[string]any{
			"ts_ns": now, "rule": rule, "event": event, "from": "normal", "to": to,
			"action": "observe", "enforced": false, "namespace": "ns", "pod": pod, "node": "n1", "comm": "x",
		})
		return string(b)
	}
	mustPost(t, srv, "/api/v1/audit", "["+
		ev("connected", "benign-client", "reverse-shell", "connect")+","+
		ev("escalating", "attacker", "container-escape", "setns")+"]")

	var alerting []map[string]any
	mustGet(t, srv, "/api/workloads?filter=alerting", &alerting)
	if len(alerting) != 1 || alerting[0]["pod"] != "attacker" {
		t.Fatalf("alerting must contain only the escalating pod, got %v", alerting)
	}

	var quiet []map[string]any
	mustGet(t, srv, "/api/workloads?filter=quiet", &quiet)
	found := false
	for _, w := range quiet {
		if w["pod"] == "benign-client" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a connected (benign) pod must be quiet, got %v", quiet)
	}
}
