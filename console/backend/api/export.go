package api

import (
	"database/sql"
	"errors"
	"net/http"
	"time"
)

type exportChainStep struct {
	TsNS      int64  `json:"ts_ns"`
	Comm      string `json:"comm"`
	Pid       int    `json:"pid"`
	Ppid      int    `json:"ppid"`
	Hook      string `json:"hook"`
	Event     string `json:"event"`
	FromState string `json:"from_state"`
	ToState   string `json:"to_state"`
	Action    string `json:"action"`
	Enforced  bool   `json:"enforced"`
	Image     string `json:"image"`
	ImageID   string `json:"image_id"`
}

type exportRule struct {
	Name           string `json:"name"`
	Scope          string `json:"scope"`
	NumStates      int    `json:"num_states"`
	WindowNS       int64  `json:"window_ns"`
	TerminalAction string `json:"terminal_action"`
}

type exportNode struct {
	Node          string `json:"node"`
	Kernel        string `json:"kernel"`
	Enforce       bool   `json:"enforce"`
	HooksAttached int    `json:"hooks_attached"`
	HooksTotal    int    `json:"hooks_total"`
}

type exportOut struct {
	GeneratedAtNS int64             `json:"generated_at_ns"`
	Incident      incident          `json:"incident"`
	Chain         []exportChainStep `json:"chain"`
	Rules         []exportRule      `json:"rules"`
	Node          exportNode        `json:"node"`
}

// export builds a self-contained evidence bundle for a single pod.
func (a *API) export(w http.ResponseWriter, r *http.Request) {
	pod := r.URL.Query().Get("pod")
	if pod == "" {
		http.Error(w, "pod is required", http.StatusBadRequest)
		return
	}
	out := exportOut{GeneratedAtNS: time.Now().UnixNano(), Chain: []exportChainStep{}, Rules: []exportRule{}}

	// incident: the pod's most-advanced rule group (highest state, then most recent).
	var rank, killed, blocked int
	err := a.DB.QueryRow(`SELECT pod, namespace, node, rule, MIN(ts_ns), MAX(ts_ns), MAX(`+stateRank+`),
			MAX(enforced = 1 AND action = 'kill'), MAX(enforced = 1 AND action = 'deny'), COUNT(*)
		FROM audit_events WHERE pod = ?
		GROUP BY pod, namespace, node, rule
		ORDER BY MAX(`+stateRank+`) DESC, MAX(ts_ns) DESC LIMIT 1`, pod).
		Scan(&out.Incident.Pod, &out.Incident.Namespace, &out.Incident.Node, &out.Incident.Rule,
			&out.Incident.StartedNS, &out.Incident.EndedNS, &rank, &killed, &blocked, &out.Incident.Steps)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "pod not found", http.StatusNotFound)
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	out.Incident.MaxState = maxStateOf[rank]
	switch {
	case killed != 0:
		out.Incident.Outcome = "killed"
	case blocked != 0:
		out.Incident.Outcome = "blocked"
	default:
		out.Incident.Outcome = "detected"
	}

	chain, err := a.DB.Query(`SELECT ts_ns, comm, pid, ppid, hook, event, from_state, to_state, action, enforced, image, image_id
		FROM audit_events WHERE pod = ? ORDER BY ts_ns, id`, pod)
	if err != nil {
		fail(w, err)
		return
	}
	for chain.Next() {
		var s exportChainStep
		var enforced int
		if err := chain.Scan(&s.TsNS, &s.Comm, &s.Pid, &s.Ppid, &s.Hook, &s.Event, &s.FromState, &s.ToState, &s.Action, &enforced, &s.Image, &s.ImageID); err != nil {
			chain.Close()
			fail(w, err)
			return
		}
		s.Enforced = enforced != 0
		out.Chain = append(out.Chain, s)
	}
	chain.Close()
	if err := chain.Err(); err != nil {
		fail(w, err)
		return
	}

	rules, err := a.DB.Query(`SELECT name, MIN(scope), MAX(num_states), MAX(window_ns), MIN(terminal_action)
		FROM rules WHERE name IN (SELECT DISTINCT rule FROM audit_events WHERE pod = ?)
		GROUP BY name ORDER BY name`, pod)
	if err != nil {
		fail(w, err)
		return
	}
	for rules.Next() {
		var x exportRule
		if err := rules.Scan(&x.Name, &x.Scope, &x.NumStates, &x.WindowNS, &x.TerminalAction); err != nil {
			rules.Close()
			fail(w, err)
			return
		}
		out.Rules = append(out.Rules, x)
	}
	rules.Close()
	if err := rules.Err(); err != nil {
		fail(w, err)
		return
	}

	var enforce int
	err = a.DB.QueryRow(`SELECT node, kernel, enforce, hooks_attached, hooks_total FROM nodes WHERE node = ?`, out.Incident.Node).
		Scan(&out.Node.Node, &out.Node.Kernel, &enforce, &out.Node.HooksAttached, &out.Node.HooksTotal)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		fail(w, err)
		return
	}
	out.Node.Enforce = enforce != 0

	w.Header().Set("Content-Disposition", `attachment; filename="ariguard-incident-`+pod+`.json"`)
	writeJSON(w, out)
}
