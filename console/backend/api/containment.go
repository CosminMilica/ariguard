package api

import "net/http"

type byAction struct {
	Kill     int64 `json:"kill"`
	Deny     int64 `json:"deny"`
	Throttle int64 `json:"throttle"`
	Observe  int64 `json:"observe"`
}

type containmentGap struct {
	Rule         string `json:"rule"`
	ObservedOnly int64  `json:"observed_only"`
}

type containmentOut struct {
	Total        int64            `json:"total"`
	Killed       int64            `json:"killed"`
	Blocked      int64            `json:"blocked"`
	ObservedOnly int64            `json:"observed_only"`
	ByAction     byAction         `json:"by_action"`
	Gaps         []containmentGap `json:"gaps"`
}

// containment rolls up enforcement outcomes over incident groups plus raw action counts.
func (a *API) containment(w http.ResponseWriter, r *http.Request) {
	win := windowOf(r)
	out := containmentOut{Gaps: []containmentGap{}}

	err := a.DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(killed),0),
			COALESCE(SUM(killed = 0 AND blocked = 1),0), COALESCE(SUM(killed = 0 AND blocked = 0),0)
		FROM (`+incidentGroupsSQL+`)`, win.fromNS(), win.toNS()).
		Scan(&out.Total, &out.Killed, &out.Blocked, &out.ObservedOnly)
	if err != nil {
		fail(w, err)
		return
	}

	acts, err := a.DB.Query(`SELECT action, COUNT(*) FROM audit_events WHERE ts_ns >= ? AND ts_ns <= ? GROUP BY action`, win.fromNS(), win.toNS())
	if err != nil {
		fail(w, err)
		return
	}
	for acts.Next() {
		var action string
		var n int64
		if err := acts.Scan(&action, &n); err != nil {
			acts.Close()
			fail(w, err)
			return
		}
		switch action {
		case "kill":
			out.ByAction.Kill = n
		case "deny":
			out.ByAction.Deny = n
		case "throttle":
			out.ByAction.Throttle = n
		case "observe":
			out.ByAction.Observe = n
		}
	}
	acts.Close()
	if err := acts.Err(); err != nil {
		fail(w, err)
		return
	}

	gaps, err := a.DB.Query(`SELECT rule, SUM(killed = 0 AND blocked = 0) AS oo
		FROM (`+incidentGroupsSQL+`) GROUP BY rule HAVING oo > 0 ORDER BY oo DESC, rule`, win.fromNS(), win.toNS())
	if err != nil {
		fail(w, err)
		return
	}
	defer gaps.Close()
	for gaps.Next() {
		var g containmentGap
		if err := gaps.Scan(&g.Rule, &g.ObservedOnly); err != nil {
			fail(w, err)
			return
		}
		out.Gaps = append(out.Gaps, g)
	}
	if err := gaps.Err(); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, out)
}
