package api

import (
	"net/http"
)

type rule struct {
	Name           string `json:"name"`
	Scope          string `json:"scope"`
	NumStates      int    `json:"num_states"`
	WindowNS       int64  `json:"window_ns"`
	TerminalAction string `json:"terminal_action"`
	Hits           int64  `json:"hits"`
}

func (a *API) rules(w http.ResponseWriter, r *http.Request) {
	win := windowOf(r)
	hits := map[string]int64{}
	hr, err := a.DB.Query(`SELECT rule, COUNT(*) FROM audit_events WHERE ts_ns >= ? AND ts_ns <= ? AND to_state = 'compromised' GROUP BY rule`, win.fromNS(), win.toNS())
	if err != nil {
		fail(w, err)
		return
	}
	for hr.Next() {
		var name string
		var n int64
		if err := hr.Scan(&name, &n); err != nil {
			hr.Close()
			fail(w, err)
			return
		}
		hits[name] = n
	}
	hr.Close()

	rows, err := a.DB.Query(`SELECT name, MIN(scope), MAX(num_states), MAX(window_ns), MIN(terminal_action)
		FROM rules GROUP BY name ORDER BY name`)
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()
	out := []rule{}
	for rows.Next() {
		var x rule
		if err := rows.Scan(&x.Name, &x.Scope, &x.NumStates, &x.WindowNS, &x.TerminalAction); err != nil {
			fail(w, err)
			return
		}
		x.Hits = hits[x.Name]
		out = append(out, x)
	}
	writeJSON(w, out)
}
