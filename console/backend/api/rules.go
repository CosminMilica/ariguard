package api

import (
	"encoding/json"
	"net/http"
)

type ruleTransition struct {
	From     string   `json:"from"`
	Event    string   `json:"event"`
	To       string   `json:"to"`
	Action   string   `json:"action"`
	Syscalls []string `json:"syscalls"`
}

type rule struct {
	Name           string           `json:"name"`
	Scope          string           `json:"scope"`
	NumStates      int              `json:"num_states"`
	WindowNS       int64            `json:"window_ns"`
	TerminalAction string           `json:"terminal_action"`
	Hits           int64            `json:"hits"`
	States         []string         `json:"states"`
	Events         []string         `json:"events"`
	TerminalFrom   int              `json:"terminal_from"`
	Transitions    []ruleTransition `json:"transitions"`
}

func (a *API) rules(w http.ResponseWriter, r *http.Request) {
	win := windowOf(r)
	hits := map[string]int64{}
	// Hits = enforced mitigations in the window: a kill at the terminal, or an -EPERM deny
	// (a denied chain never reaches 'compromised', so counting that alone misses it).
	hr, err := a.DB.Query(`SELECT rule, COUNT(*) FROM audit_events WHERE ts_ns >= ? AND ts_ns <= ? AND enforced = 1 AND action IN ('kill','deny') GROUP BY rule`, win.fromNS(), win.toNS())
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

	rows, err := a.DB.Query(`SELECT name, MIN(scope), MAX(num_states), MAX(window_ns), MIN(terminal_action), MAX(detail)
		FROM rules GROUP BY name ORDER BY name`)
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()
	out := []rule{}
	for rows.Next() {
		var x rule
		var detail string
		if err := rows.Scan(&x.Name, &x.Scope, &x.NumStates, &x.WindowNS, &x.TerminalAction, &detail); err != nil {
			fail(w, err)
			return
		}
		x.Hits = hits[x.Name]
		var d struct {
			States       []string         `json:"states"`
			Events       []string         `json:"events"`
			TerminalFrom int              `json:"terminal_from"`
			Transitions  []ruleTransition `json:"transitions"`
		}
		if detail != "" {
			if err := json.Unmarshal([]byte(detail), &d); err != nil {
				fail(w, err)
				return
			}
		}
		x.States = d.States
		x.Events = d.Events
		x.TerminalFrom = d.TerminalFrom
		x.Transitions = d.Transitions
		out = append(out, x)
	}
	writeJSON(w, out)
}
