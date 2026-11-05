package api_test

import (
	"testing"
	"time"
)

func TestAutonomyView(t *testing.T) {
	srv := newServer(t)
	// a curated enforcing rule and an auto shadow rule, both reported by the agent
	mustPost(t, srv, "/api/v1/register", `{"node":"n1","bundle":{"rules":[
		{"name":"reverse-shell","scope":"process","terminal_action":"kill","num_states":4,
		 "states":["normal"],"events":["e"],"transitions":[{"from":"normal","event":"e","to":"normal","action":"observe"}]},
		{"name":"auto-unshare-mount-bpf","scope":"process","terminal_action":"observe","num_states":4,
		 "states":["normal"],"events":["e"],"transitions":[{"from":"normal","event":"e","to":"normal","action":"observe"}]}]}}`)

	now := time.Now().UnixNano()
	// the shadow rule hit a real threat state on a normal pod (attack hit)
	mustPost(t, srv, "/api/v1/audit",
		`[`+evJSON(now-1000, "p1", "auto-unshare-mount-bpf", "normal", "compromised", "observe", false, nil)+`]`)

	var a struct {
		Rules []struct {
			Name, Mode, Source, Status string
			Hits                       int64
			BenignFires                int64 `json:"benign_fires"`
		}
		MinDays float64 `json:"min_days"`
	}
	mustGet(t, srv, "/api/autonomy", &a)

	byName := map[string]int{}
	for i, r := range a.Rules {
		byName[r.Name] = i
	}
	rs, ok := byName["reverse-shell"]
	au, ok2 := byName["auto-unshare-mount-bpf"]
	if !ok || !ok2 {
		t.Fatalf("missing rules: %+v", a.Rules)
	}
	if a.Rules[rs].Mode != "enforce" || a.Rules[rs].Source != "curated" || a.Rules[rs].Status != "enforcing" {
		t.Fatalf("curated rule wrong: %+v", a.Rules[rs])
	}
	auto := a.Rules[au]
	if auto.Mode != "shadow" || auto.Source != "auto" || auto.Hits != 1 || auto.Status != "observing" {
		t.Fatalf("auto rule wrong: %+v", auto)
	}
	if a.MinDays != 7 {
		t.Fatalf("min_days=%v", a.MinDays)
	}
}

func TestAutonomyRetireOnBenignFire(t *testing.T) {
	srv := newServer(t)
	mustPost(t, srv, "/api/v1/register", `{"node":"n1","bundle":{"rules":[
		{"name":"auto-x","scope":"process","terminal_action":"observe","num_states":2,
		 "states":["normal"],"events":["e"],"transitions":[{"from":"normal","event":"e","to":"normal","action":"observe"}]}]}}`)
	mustPost(t, srv, "/api/mutes", `{"pod":"known-good"}`)
	now := time.Now().UnixNano()
	mustPost(t, srv, "/api/v1/audit",
		`[`+evJSON(now-1000, "known-good", "auto-x", "normal", "compromised", "observe", false, nil)+`]`)

	var a struct {
		Rules []struct {
			Name, Status string
			BenignFires  int64 `json:"benign_fires"`
		}
	}
	mustGet(t, srv, "/api/autonomy", &a)
	if len(a.Rules) != 1 || a.Rules[0].BenignFires != 1 || a.Rules[0].Status != "retire" {
		t.Fatalf("expected retire on a benign fire: %+v", a.Rules)
	}
}
