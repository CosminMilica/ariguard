package api

import (
	"net/http"
)

type chainStep struct {
	TsNS     int64  `json:"ts_ns"`
	State    string `json:"state"`
	Event    string `json:"event"`
	Action   string `json:"action"`
	Enforced bool   `json:"enforced"`
}

func (a *API) chain(w http.ResponseWriter, r *http.Request) {
	pod := r.URL.Query().Get("pod")
	win := windowOf(r)
	rows, err := a.DB.Query(`SELECT ts_ns,to_state,event,action,enforced FROM audit_events
		WHERE pod=? AND ts_ns >= ? AND ts_ns <= ? ORDER BY ts_ns, id`, pod, win.fromNS(), win.toNS())
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()
	out := []chainStep{}
	for rows.Next() {
		var s chainStep
		var enforced int
		if err := rows.Scan(&s.TsNS, &s.State, &s.Event, &s.Action, &enforced); err != nil {
			fail(w, err)
			return
		}
		s.Enforced = enforced != 0
		out = append(out, s)
	}
	writeJSON(w, out)
}
