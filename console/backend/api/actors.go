package api

import (
	"database/sql"
	"net/http"
)

type actor struct {
	ImageID            string   `json:"image_id"`
	Image              string   `json:"image"`
	Incidents          int64    `json:"incidents"`
	Pods               int64    `json:"pods"`
	Namespaces         int64    `json:"namespaces"`
	Nodes              int64    `json:"nodes"`
	Killed             int64    `json:"killed"`
	Blocked            int64    `json:"blocked"`
	Detected           int64    `json:"detected"`
	FirstNS            int64    `json:"first_ts_ns"`
	LastNS             int64    `json:"last_ts_ns"`
	Rules              []string `json:"rules"`
	Comms              []string `json:"comms"`
	AffectedNamespaces []string `json:"affected_namespaces"`
}

// actors clusters incident groups by container image digest: the same compromised image seen
// across many pods/namespaces is treated as one actor (a campaign by payload, not by rule).
// Widest spread (most pods) first, since that is the most likely fleet-wide compromise.
func (a *API) actors(w http.ResponseWriter, r *http.Request) {
	win := windowOf(r)
	out := []actor{}
	rows, err := a.DB.Query(`SELECT image_id, MAX(image), COUNT(*), COUNT(DISTINCT pod),
			COUNT(DISTINCT namespace), COUNT(DISTINCT node),
			SUM(killed), SUM(killed = 0 AND blocked = 1), SUM(killed = 0 AND blocked = 0),
			MIN(first_ns), MAX(last_ns),
			GROUP_CONCAT(DISTINCT rule), GROUP_CONCAT(DISTINCT comm), GROUP_CONCAT(DISTINCT namespace)
		FROM (`+incidentGroupsSQL+`)
		WHERE image_id != ''
		GROUP BY image_id
		ORDER BY COUNT(DISTINCT pod) DESC, COUNT(*) DESC`, win.fromNS(), win.toNS())
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var ac actor
		var rules, comms, ns sql.NullString
		if err := rows.Scan(&ac.ImageID, &ac.Image, &ac.Incidents, &ac.Pods, &ac.Namespaces, &ac.Nodes,
			&ac.Killed, &ac.Blocked, &ac.Detected, &ac.FirstNS, &ac.LastNS, &rules, &comms, &ns); err != nil {
			fail(w, err)
			return
		}
		ac.Rules = splitConcat(rules)
		ac.Comms = splitConcat(comms)
		ac.AffectedNamespaces = splitConcat(ns)
		out = append(out, ac)
	}
	if err := rows.Err(); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, out)
}
