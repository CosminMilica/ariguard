package api

import "net/http"

type quarantineRow struct {
	Node      string `json:"node"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Rule      string `json:"rule"`
	Mode      string `json:"mode"`
	TsNS      int64  `json:"ts_ns"`
}

// quarantine lists autonomous workload isolations within the window, newest first.
func (a *API) quarantine(w http.ResponseWriter, r *http.Request) {
	win := windowOf(r)
	rows, err := a.DB.Query(`SELECT node, namespace, pod, rule, mode, ts_ns FROM quarantine
		WHERE ts_ns >= ? AND ts_ns <= ? ORDER BY ts_ns DESC, pod`, win.fromNS(), win.toNS())
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()
	out := []quarantineRow{}
	for rows.Next() {
		var q quarantineRow
		if err := rows.Scan(&q.Node, &q.Namespace, &q.Pod, &q.Rule, &q.Mode, &q.TsNS); err != nil {
			fail(w, err)
			return
		}
		out = append(out, q)
	}
	if err := rows.Err(); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, out)
}

// quarantinedKeys returns the set of "namespace\x00pod" keys currently quarantined,
// used to flag triage/incident rows. One query, intersected in Go.
func (a *API) quarantinedKeys() (map[string]bool, error) {
	rows, err := a.DB.Query(`SELECT namespace, pod FROM quarantine`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	set := map[string]bool{}
	for rows.Next() {
		var ns, pod string
		if err := rows.Scan(&ns, &pod); err != nil {
			return nil, err
		}
		set[ns+"\x00"+pod] = true
	}
	return set, rows.Err()
}
