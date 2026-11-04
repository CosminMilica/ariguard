package api

import (
	"database/sql"
	"net/http"
	"sort"
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
	DstIPs             []string `json:"dst_ips"`       // observed outbound C2 destinations (B3/F4)
	Owners             []string `json:"owners"`        // controlling workloads (e.g. Deployment/frontend)
	Apps               []string `json:"apps"`          // app labels
	AffectedPods       []string `json:"affected_pods"` // pods this actor ran in (drill-down to chains)
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
			GROUP_CONCAT(DISTINCT rule), GROUP_CONCAT(DISTINCT comm), GROUP_CONCAT(DISTINCT namespace),
			GROUP_CONCAT(dst_ips),
			GROUP_CONCAT(DISTINCT owner), GROUP_CONCAT(DISTINCT app), GROUP_CONCAT(DISTINCT pod)
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
		var rules, comms, ns, dstIPs, owners, apps, pods sql.NullString
		if err := rows.Scan(&ac.ImageID, &ac.Image, &ac.Incidents, &ac.Pods, &ac.Namespaces, &ac.Nodes,
			&ac.Killed, &ac.Blocked, &ac.Detected, &ac.FirstNS, &ac.LastNS, &rules, &comms, &ns, &dstIPs,
			&owners, &apps, &pods); err != nil {
			fail(w, err)
			return
		}
		ac.Rules = splitConcat(rules)
		ac.Comms = splitConcat(comms)
		ac.AffectedNamespaces = splitConcat(ns)
		// dst_ips arrives as per-group concats joined again; dedup across groups.
		ac.DstIPs = uniqueSorted(splitConcat(dstIPs))
		ac.Owners = uniqueSorted(splitConcat(owners))
		ac.Apps = uniqueSorted(splitConcat(apps))
		ac.AffectedPods = uniqueSorted(splitConcat(pods))
		out = append(out, ac)
	}
	if err := rows.Err(); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, out)
}

// uniqueSorted dedups and sorts a list, dropping empty entries.
func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
