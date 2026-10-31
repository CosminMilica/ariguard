package api

import (
	"net/http"
)

const eventLimit = 500

type event struct {
	TsNS      int64  `json:"ts_ns"`
	Severity  string `json:"severity"`
	Pod       string `json:"pod"`
	Namespace string `json:"namespace"`
	Rule      string `json:"rule"`
	Event     string `json:"event"`
	Node      string `json:"node"`
	Action    string `json:"action"`
	Enforced  bool   `json:"enforced"`
}

func (a *API) events(w http.ResponseWriter, r *http.Request) {
	win := windowOf(r)
	query := `SELECT ts_ns,to_state,pod,namespace,rule,event,node,action,enforced FROM audit_events WHERE ts_ns >= ? AND ts_ns <= ?`
	args := []any{win.fromNS(), win.toNS()}
	switch r.URL.Query().Get("severity") {
	case "crit":
		query += ` AND to_state IN ('compromised','breakout_imminent')`
	case "mid":
		query += ` AND to_state = 'escalating'`
	case "warn":
		query += ` AND to_state = 'suspicious'`
	}
	if r.URL.Query().Get("significant") == "1" {
		query += ` AND (to_state IN ('compromised','breakout_imminent','escalating','suspicious') OR action != 'observe')`
	}
	if q := r.URL.Query().Get("q"); q != "" {
		query += ` AND (pod LIKE ? OR namespace LIKE ? OR rule LIKE ? OR event LIKE ? OR node LIKE ?)`
		l := like(q)
		args = append(args, l, l, l, l, l)
	}
	query += ` ORDER BY ts_ns DESC, id DESC LIMIT ?`
	args = append(args, eventLimit)

	rows, err := a.DB.Query(query, args...)
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()
	out := []event{}
	for rows.Next() {
		var e event
		var to string
		var enforced int
		if err := rows.Scan(&e.TsNS, &to, &e.Pod, &e.Namespace, &e.Rule, &e.Event, &e.Node, &e.Action, &enforced); err != nil {
			fail(w, err)
			return
		}
		e.Severity = stateSeverity[to]
		e.Enforced = enforced != 0
		out = append(out, e)
	}
	writeJSON(w, out)
}
