package api_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestTriage(t *testing.T) {
	srv := newServer(t)
	now := time.Now().UnixNano()
	ev := func(ts int64, pod, from, to, action string, enforced bool) string {
		b, _ := json.Marshal(map[string]any{"ts_ns": ts, "rule": "r1", "event": "execve", "from": from, "to": to,
			"action": action, "enforced": enforced, "namespace": "ns", "pod": pod, "node": "n1", "comm": "sh"})
		return string(b)
	}
	body := "[" + strings.Join([]string{
		ev(now-3000, "killed-pod", "normal", "suspicious", "observe", false),
		ev(now-2000, "killed-pod", "suspicious", "compromised", "kill", true),
		ev(now-1500, "esc-pod", "normal", "suspicious", "observe", false),
		ev(now-1000, "esc-pod", "suspicious", "escalating", "observe", false),
		ev(now-500, "benign-pod", "normal", "normal", "observe", false),
	}, ",") + "]"
	mustPost(t, srv, "/api/v1/audit", body)

	type item struct {
		Pod, Rule, Outcome string
		MaxState           string `json:"max_state"`
		MaxAction          string `json:"max_action"`
		StartedNS          int64  `json:"started_ts_ns"`
		LastNS             int64  `json:"last_ts_ns"`
		Steps              int
		Active             bool
	}
	var got []item
	mustGet(t, srv, "/api/triage?range=1h", &got)
	if len(got) != 2 {
		t.Fatalf("triage: %+v", got)
	}
	// Ordered by max state rank: compromised first.
	k, e := got[0], got[1]
	if k.Pod != "killed-pod" || k.MaxState != "compromised" || k.MaxAction != "kill" || k.Outcome != "killed" ||
		k.Steps != 2 || k.Active || k.StartedNS != now-3000 || k.LastNS != now-2000 {
		t.Fatalf("killed: %+v", k)
	}
	if e.Pod != "esc-pod" || e.MaxState != "escalating" || e.MaxAction != "observe" || e.Outcome != "detected" ||
		e.Steps != 2 || !e.Active {
		t.Fatalf("escalating: %+v", e)
	}
}
