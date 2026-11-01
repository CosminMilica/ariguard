package api_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestContainment(t *testing.T) {
	srv := newServer(t)
	now := time.Now().UnixNano()
	ev := func(ts int64, pod, rule, to, action string, enforced bool) string {
		b, _ := json.Marshal(map[string]any{"ts_ns": ts, "rule": rule, "event": "execve", "from": "normal", "to": to,
			"action": action, "enforced": enforced, "namespace": "ns", "pod": pod, "node": "n1", "comm": "sh"})
		return string(b)
	}
	body := "[" + strings.Join([]string{
		ev(now-5000, "p1", "r1", "suspicious", "observe", false),  // killed group, observe raw
		ev(now-4000, "p1", "r1", "compromised", "kill", true),     // killed group, kill raw
		ev(now-3000, "p2", "r2", "escalating", "deny", true),      // blocked group, deny raw
		ev(now-2000, "p3", "r1", "escalating", "observe", false),  // observed-only group, observe raw
		ev(now-1000, "p4", "r3", "escalating", "throttle", false), // observed-only group, throttle raw
	}, ",") + "]"
	mustPost(t, srv, "/api/v1/audit", body)

	var got struct {
		Total, Killed, Blocked int
		ObservedOnly           int                                         `json:"observed_only"`
		ByAction               struct{ Kill, Deny, Throttle, Observe int } `json:"by_action"`
		Gaps                   []struct {
			Rule         string
			ObservedOnly int `json:"observed_only"`
		}
	}
	mustGet(t, srv, "/api/containment?range=1h", &got)

	if got.Total != 4 || got.Killed != 1 || got.Blocked != 1 || got.ObservedOnly != 2 {
		t.Fatalf("rollup: %+v", got)
	}
	if got.ByAction.Kill != 1 || got.ByAction.Deny != 1 || got.ByAction.Throttle != 1 || got.ByAction.Observe != 2 {
		t.Fatalf("by_action: %+v", got.ByAction)
	}
	if len(got.Gaps) != 2 {
		t.Fatalf("gaps: %+v", got.Gaps)
	}
	if got.Gaps[0].Rule != "r1" || got.Gaps[0].ObservedOnly != 1 || got.Gaps[1].Rule != "r3" || got.Gaps[1].ObservedOnly != 1 {
		t.Fatalf("gaps content: %+v", got.Gaps)
	}
}
