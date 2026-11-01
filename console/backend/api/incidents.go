package api

import "net/http"

type incident struct {
	Pod         string `json:"pod"`
	Namespace   string `json:"namespace"`
	Node        string `json:"node"`
	Rule        string `json:"rule"`
	StartedNS   int64  `json:"started_ts_ns"`
	EndedNS     int64  `json:"ended_ts_ns"`
	MaxState    string `json:"max_state"`
	Outcome     string `json:"outcome"`
	Steps       int64  `json:"steps"`
	Quarantined bool   `json:"quarantined"`
}

// maxStateOf maps a stateRank to its name; action-only groups (rank <= 1) report "suspicious".
var maxStateOf = map[int]string{5: "compromised", 4: "breakout_imminent", 3: "escalating", 2: "suspicious", 1: "suspicious", 0: "suspicious"}

const stateRank = `CASE to_state WHEN 'compromised' THEN 5 WHEN 'breakout_imminent' THEN 4 WHEN 'escalating' THEN 3 WHEN 'suspicious' THEN 2 ELSE 1 END`

// incidentGroupsSQL materializes one row per incident group (pod,namespace,node,rule)
// with its enforced-kill/deny flags and ts bounds; reused as a subquery by campaigns
// and containment. Takes two bind params: window from/to in ns.
const incidentGroupsSQL = `SELECT pod, namespace, node, rule,
		MAX(enforced = 1 AND action = 'kill') AS killed,
		MAX(enforced = 1 AND action = 'deny') AS blocked,
		MIN(ts_ns) AS first_ns, MAX(ts_ns) AS last_ns,
		MAX(image_id) AS image_id, MAX(image) AS image, MAX(comm) AS comm
	FROM audit_events
	WHERE ts_ns >= ? AND ts_ns <= ? AND pod != ''
	GROUP BY pod, namespace, node, rule
	HAVING MAX(to_state IN ('compromised','breakout_imminent','escalating') OR action != 'observe') = 1`

// incidents aggregates audit events per (pod, namespace, node, rule) within the window.
func (a *API) incidents(w http.ResponseWriter, r *http.Request) {
	win := windowOf(r)
	qset, err := a.quarantinedKeys()
	if err != nil {
		fail(w, err)
		return
	}
	rows, err := a.DB.Query(`SELECT pod, namespace, node, rule, MIN(ts_ns), MAX(ts_ns), MAX(`+stateRank+`),
			MAX(enforced = 1 AND action = 'kill'), MAX(enforced = 1 AND action = 'deny'), COUNT(*)
		FROM audit_events
		WHERE ts_ns >= ? AND ts_ns <= ? AND pod != ''
		GROUP BY pod, namespace, node, rule
		HAVING MAX(to_state IN ('compromised','breakout_imminent','escalating') OR action != 'observe') = 1
		ORDER BY MAX(ts_ns) DESC, pod, rule`, win.fromNS(), win.toNS())
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()
	out := []incident{}
	for rows.Next() {
		var i incident
		var rank, killed, blocked int
		if err := rows.Scan(&i.Pod, &i.Namespace, &i.Node, &i.Rule, &i.StartedNS, &i.EndedNS, &rank, &killed, &blocked, &i.Steps); err != nil {
			fail(w, err)
			return
		}
		i.MaxState = maxStateOf[rank]
		switch {
		case killed != 0:
			i.Outcome = "killed"
		case blocked != 0:
			i.Outcome = "blocked"
		default:
			i.Outcome = "detected"
		}
		i.Quarantined = qset[i.Namespace+"\x00"+i.Pod]
		out = append(out, i)
	}
	if err := rows.Err(); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, out)
}
