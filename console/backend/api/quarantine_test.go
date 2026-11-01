package api_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestQuarantine(t *testing.T) {
	srv := newServer(t)
	now := time.Now().UnixNano()

	// Agent isolates a pod, then re-posts with a newer ts to confirm the upsert.
	q := func(ts int64, rule, mode string) string {
		b, _ := json.Marshal(map[string]any{
			"node": "n1", "namespace": "ns", "pod": "iso-pod", "rule": rule, "mode": mode, "ts_ns": ts})
		return string(b)
	}
	mustPost(t, srv, "/api/v1/quarantine", q(now-2000, "r1", "dryrun"))
	mustPost(t, srv, "/api/v1/quarantine", q(now-1000, "r1", "on"))

	var rows []struct {
		Node, Namespace, Pod, Rule, Mode string
		TsNS                             int64 `json:"ts_ns"`
	}
	mustGet(t, srv, "/api/quarantine?range=1h", &rows)
	if len(rows) != 1 {
		t.Fatalf("quarantine rows: %+v", rows)
	}
	r := rows[0]
	if r.Node != "n1" || r.Namespace != "ns" || r.Pod != "iso-pod" || r.Rule != "r1" || r.Mode != "on" || r.TsNS != now-1000 {
		t.Fatalf("quarantine row: %+v", r)
	}

	// A triage row for the same pod must be flagged quarantined.
	ev := func(ts int64, from, to, action string, enforced bool) string {
		b, _ := json.Marshal(map[string]any{"ts_ns": ts, "rule": "r1", "event": "execve", "from": from, "to": to,
			"action": action, "enforced": enforced, "namespace": "ns", "pod": "iso-pod", "node": "n1", "comm": "sh"})
		return string(b)
	}
	body := "[" + strings.Join([]string{
		ev(now-3000, "normal", "suspicious", "observe", false),
		ev(now-2500, "suspicious", "escalating", "observe", false),
	}, ",") + "]"
	mustPost(t, srv, "/api/v1/audit", body)

	var triage []struct {
		Pod         string
		Quarantined bool
	}
	mustGet(t, srv, "/api/triage?range=1h", &triage)
	if len(triage) != 1 || triage[0].Pod != "iso-pod" || !triage[0].Quarantined {
		t.Fatalf("triage quarantined flag: %+v", triage)
	}
}
