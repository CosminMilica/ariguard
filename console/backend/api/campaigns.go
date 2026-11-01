package api

import (
	"database/sql"
	"net/http"
	"strings"
)

type ruleCampaign struct {
	Rule          string   `json:"rule"`
	Incidents     int64    `json:"incidents"`
	Pods          int64    `json:"pods"`
	Namespaces    int64    `json:"namespaces"`
	Nodes         int64    `json:"nodes"`
	Killed        int64    `json:"killed"`
	Blocked       int64    `json:"blocked"`
	Detected      int64    `json:"detected"`
	FirstNS       int64    `json:"first_ts_ns"`
	LastNS        int64    `json:"last_ts_ns"`
	AffectedNS    []string `json:"affected_namespaces"`
	AffectedNodes []string `json:"affected_nodes"`
}

type nsCampaign struct {
	Namespace     string   `json:"namespace"`
	Incidents     int64    `json:"incidents"`
	Pods          int64    `json:"pods"`
	Rules         int64    `json:"rules"`
	Nodes         int64    `json:"nodes"`
	Killed        int64    `json:"killed"`
	Blocked       int64    `json:"blocked"`
	Detected      int64    `json:"detected"`
	FirstNS       int64    `json:"first_ts_ns"`
	LastNS        int64    `json:"last_ts_ns"`
	AffectedRules []string `json:"affected_rules"`
}

type campaignsOut struct {
	ByRule []ruleCampaign `json:"by_rule"`
	ByNS   []nsCampaign   `json:"by_namespace"`
}

// splitConcat turns a GROUP_CONCAT(DISTINCT ...) result into a non-nil slice.
func splitConcat(s sql.NullString) []string {
	if !s.Valid || s.String == "" {
		return []string{}
	}
	return strings.Split(s.String, ",")
}

// campaigns aggregates incident groups into blast-radius rollups by rule and namespace.
func (a *API) campaigns(w http.ResponseWriter, r *http.Request) {
	win := windowOf(r)
	out := campaignsOut{ByRule: []ruleCampaign{}, ByNS: []nsCampaign{}}

	byRule, err := a.DB.Query(`SELECT rule, COUNT(*), COUNT(DISTINCT pod), COUNT(DISTINCT namespace), COUNT(DISTINCT node),
			SUM(killed), SUM(killed = 0 AND blocked = 1), SUM(killed = 0 AND blocked = 0),
			MIN(first_ns), MAX(last_ns),
			GROUP_CONCAT(DISTINCT namespace), GROUP_CONCAT(DISTINCT node)
		FROM (`+incidentGroupsSQL+`) GROUP BY rule ORDER BY COUNT(*) DESC, rule`, win.fromNS(), win.toNS())
	if err != nil {
		fail(w, err)
		return
	}
	for byRule.Next() {
		var c ruleCampaign
		var ns, nodes sql.NullString
		if err := byRule.Scan(&c.Rule, &c.Incidents, &c.Pods, &c.Namespaces, &c.Nodes,
			&c.Killed, &c.Blocked, &c.Detected, &c.FirstNS, &c.LastNS, &ns, &nodes); err != nil {
			byRule.Close()
			fail(w, err)
			return
		}
		c.AffectedNS = splitConcat(ns)
		c.AffectedNodes = splitConcat(nodes)
		out.ByRule = append(out.ByRule, c)
	}
	byRule.Close()
	if err := byRule.Err(); err != nil {
		fail(w, err)
		return
	}

	byNS, err := a.DB.Query(`SELECT namespace, COUNT(*), COUNT(DISTINCT pod), COUNT(DISTINCT rule), COUNT(DISTINCT node),
			SUM(killed), SUM(killed = 0 AND blocked = 1), SUM(killed = 0 AND blocked = 0),
			MIN(first_ns), MAX(last_ns), GROUP_CONCAT(DISTINCT rule)
		FROM (`+incidentGroupsSQL+`) GROUP BY namespace ORDER BY COUNT(*) DESC, namespace`, win.fromNS(), win.toNS())
	if err != nil {
		fail(w, err)
		return
	}
	defer byNS.Close()
	for byNS.Next() {
		var c nsCampaign
		var rules sql.NullString
		if err := byNS.Scan(&c.Namespace, &c.Incidents, &c.Pods, &c.Rules, &c.Nodes,
			&c.Killed, &c.Blocked, &c.Detected, &c.FirstNS, &c.LastNS, &rules); err != nil {
			fail(w, err)
			return
		}
		c.AffectedRules = splitConcat(rules)
		out.ByNS = append(out.ByNS, c)
	}
	if err := byNS.Err(); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, out)
}
