package api

import (
	"net/http"
	"time"
)

const actionRank = `CASE action WHEN 'kill' THEN 4 WHEN 'deny' THEN 3 WHEN 'throttle' THEN 2 ELSE 1 END`

var maxActionOf = map[int]string{4: "kill", 3: "deny", 2: "throttle", 1: "observe"}

type triageItem struct {
	Pod       string `json:"pod"`
	Namespace string `json:"namespace"`
	Node      string `json:"node"`
	Rule      string `json:"rule"`
	StartedNS int64  `json:"started_ts_ns"`
	LastNS    int64  `json:"last_ts_ns"`
	MaxState  string `json:"max_state"`
	MaxAction string `json:"max_action"`
	Outcome   string `json:"outcome"`
	Steps     int64  `json:"steps"`
	Active    bool   `json:"active"`
}

// triage lists in-progress attacks, most advanced first (max state, then most recent).
func (a *API) triage(w http.ResponseWriter, r *http.Request) {
	win := windowOf(r)
	rows, err := a.DB.Query(`SELECT pod, namespace, node, rule, MIN(ts_ns), MAX(ts_ns),
			MAX(`+stateRank+`), MAX(`+actionRank+`),
			MAX(enforced = 1 AND action = 'kill'), MAX(enforced = 1 AND action = 'deny'), COUNT(*)
		FROM audit_events
		WHERE ts_ns >= ? AND ts_ns <= ? AND pod != ''
		GROUP BY pod, namespace, node, rule
		HAVING MAX(to_state IN ('compromised','breakout_imminent','escalating') OR action != 'observe') = 1
		ORDER BY MAX(`+stateRank+`) DESC, MAX(ts_ns) DESC, pod, rule`, win.fromNS(), win.toNS())
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()
	now := time.Now().UnixNano()
	out := []triageItem{}
	for rows.Next() {
		var t triageItem
		var srank, arank, killed, blocked int
		if err := rows.Scan(&t.Pod, &t.Namespace, &t.Node, &t.Rule, &t.StartedNS, &t.LastNS, &srank, &arank, &killed, &blocked, &t.Steps); err != nil {
			fail(w, err)
			return
		}
		t.MaxState = maxStateOf[srank]
		t.MaxAction = maxActionOf[arank]
		switch {
		case killed != 0:
			t.Outcome = "killed"
		case blocked != 0:
			t.Outcome = "blocked"
		default:
			t.Outcome = "detected"
		}
		t.Active = t.LastNS >= now-10_000_000_000 && killed == 0 && blocked == 0 && t.MaxState != "compromised"
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, out)
}
