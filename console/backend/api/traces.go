package api

import "net/http"

// TraceStat is the count of stored traces for one (kind, label) pair. kind is the trace's origin —
// "learn" for F11 learn-mode production traffic, "honeypot" otherwise — derived from the source.
type TraceStat struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

// traceStats summarises the mining corpus for the frontend: how many traces came from learn-mode
// vs the honeypot, split by attack/benign. Lets an operator see the production benign baseline
// (learn/benign) growing next to the attack traces that seed discovery.
func (a *API) traceStats(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.Query(`
		SELECT CASE WHEN source LIKE 'learn:%' THEN 'learn' ELSE 'honeypot' END AS kind,
		       label, COUNT(*)
		FROM honeypot_traces
		GROUP BY kind, label
		ORDER BY kind, label`)
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()
	out := []TraceStat{}
	for rows.Next() {
		var s TraceStat
		if err := rows.Scan(&s.Kind, &s.Label, &s.Count); err != nil {
			fail(w, err)
			return
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, out)
}
