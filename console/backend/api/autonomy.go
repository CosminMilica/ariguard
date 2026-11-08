package api

import (
	"net/http"
	"strings"
)

const nsPerDay = int64(86_400) * 1_000_000_000

// autoRule is one rule as the autonomous loop sees it: its deploy mode, provenance, and the measured
// behavior that drives shadow->enforce promotion.
type autoRule struct {
	Name         string  `json:"name"`
	Scope        string  `json:"scope"`
	Mode         string  `json:"mode"`   // shadow (observe terminal) | enforce (kill terminal)
	Source       string  `json:"source"` // auto (mined/honeypot) | curated
	Hits         int64   `json:"hits"`
	DistinctPod  int64   `json:"distinct_pods"`
	BenignFires  int64   `json:"benign_fires"`
	DaysObserved float64 `json:"days_observed"`
	Status       string  `json:"status"` // enforcing | ready | observing | retire
}

type autonomy struct {
	Rules         []autoRule `json:"rules"`
	PolicyVersion string     `json:"policy_version"`
	PolicyUpdated int64      `json:"policy_updated_ns"`
	// promotion thresholds (mirror compiler decide_mode) so the UI can show progress honestly.
	MinDays float64 `json:"min_days"`
	MinHits int64   `json:"min_hits"`
}

// autonomyView reports the autonomous rule-generation state: every rule's mode (shadow vs enforce),
// provenance, and the telemetry that decides promotion — plus the current control-plane policy.
func (a *API) autonomyView(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.Query(`SELECT r.name, MIN(r.scope), MIN(r.terminal_action),
			COALESCE(t.hits,0), COALESCE(t.pods,0), COALESCE(t.benign,0), COALESCE(t.first_ns,0), COALESCE(t.last_ns,0)
		FROM rules r
		LEFT JOIN (
			SELECT a.rule AS rule, COUNT(*) AS hits, COUNT(DISTINCT a.pod) AS pods,
			       COALESCE(SUM(CASE WHEN m.pod IS NOT NULL THEN 1 ELSE 0 END),0) AS benign,
			       MIN(a.ts_ns) AS first_ns, MAX(a.ts_ns) AS last_ns
			FROM audit_events a LEFT JOIN mutes m ON m.pod = a.namespace || '/' || a.pod
			WHERE a.rule != '' AND a.to_state IN ` + threatStatesSQL + `
			GROUP BY a.rule
		) t ON t.rule = r.name
		GROUP BY r.name ORDER BY r.name`)
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()

	out := autonomy{Rules: []autoRule{}, MinDays: 7, MinHits: 1}
	for rows.Next() {
		var ar autoRule
		var terminal string
		var first, last int64
		if err := rows.Scan(&ar.Name, &ar.Scope, &terminal, &ar.Hits, &ar.DistinctPod, &ar.BenignFires, &first, &last); err != nil {
			fail(w, err)
			return
		}
		ar.Mode = "enforce"
		if terminal == "observe" {
			ar.Mode = "shadow"
		}
		ar.Source = "curated"
		if strings.HasPrefix(ar.Name, "auto-") {
			ar.Source = "auto"
		}
		if last > first {
			ar.DaysObserved = float64(last-first) / float64(nsPerDay)
		}
		ar.Status = statusOf(ar, out.MinDays, out.MinHits)
		out.Rules = append(out.Rules, ar)
	}
	if err := rows.Err(); err != nil {
		fail(w, err)
		return
	}

	var ver string
	var updated int64
	if err := a.DB.QueryRow(`SELECT version, ts_ns FROM policy WHERE id=1`).Scan(&ver, &updated); err == nil {
		out.PolicyVersion, out.PolicyUpdated = ver, updated
	}
	writeJSON(w, out)
}

// statusOf mirrors the compiler's decide_mode: a benign fire retires a shadow rule; enough hits over
// enough days promote it; otherwise it keeps observing. An enforcing rule is already promoted.
func statusOf(ar autoRule, minDays float64, minHits int64) string {
	if ar.Mode == "enforce" {
		return "enforcing"
	}
	if ar.BenignFires > 0 {
		return "retire"
	}
	if ar.DaysObserved >= minDays && ar.Hits >= minHits {
		return "ready"
	}
	return "observing"
}
