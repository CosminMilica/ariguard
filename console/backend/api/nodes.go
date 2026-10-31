package api

import (
	"database/sql"
	"errors"
	"net/http"
	"time"
)

type nodeOut struct {
	Node          string  `json:"node"`
	Kernel        string  `json:"kernel"`
	HooksAttached int     `json:"hooks_attached"`
	HooksTotal    int     `json:"hooks_total"`
	Status        string  `json:"status"`
	EventsPerSec  float64 `json:"events_per_sec"`
}

func (a *API) nodes(w http.ResponseWriter, r *http.Request) {
	stats, err := a.latestStats()
	if err != nil {
		fail(w, err)
		return
	}
	rows, err := a.DB.Query(`SELECT node,kernel,hooks_attached,hooks_total,last_seen FROM nodes ORDER BY node`)
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()
	cutoff := time.Now().UnixMilli() - freshMS
	out := []nodeOut{}
	for rows.Next() {
		var n nodeOut
		var seen int64
		if err := rows.Scan(&n.Node, &n.Kernel, &n.HooksAttached, &n.HooksTotal, &seen); err != nil {
			fail(w, err)
			return
		}
		n.Status = "stale"
		if seen >= cutoff {
			n.Status = "ready"
		}
		n.EventsPerSec = stats[n.Node].eventsPerSec
		out = append(out, n)
	}
	writeJSON(w, out)
}

type bundleRule struct {
	Name           string `json:"name"`
	Scope          string `json:"scope"`
	NumStates      int    `json:"num_states"`
	WindowNS       int64  `json:"window_ns"`
	TerminalAction string `json:"terminal_action"`
}

type settingsOut struct {
	Enforce        bool   `json:"enforce"`
	MetricsAddr    string `json:"metrics_addr"`
	Bundle         bundle `json:"bundle"`
	AuditRingBytes int64  `json:"audit_ring_bytes"`
	Kernel         string `json:"kernel"`
}

type bundle struct {
	Rules []bundleRule `json:"rules"`
}

// settings reports the configuration of the most recently seen node.
func (a *API) settings(w http.ResponseWriter, r *http.Request) {
	out := settingsOut{Bundle: bundle{Rules: []bundleRule{}}}
	var node string
	var enforce int
	err := a.DB.QueryRow(`SELECT node,kernel,enforce,audit_ring_bytes,metrics_addr FROM nodes ORDER BY last_seen DESC, node LIMIT 1`).
		Scan(&node, &out.Kernel, &enforce, &out.AuditRingBytes, &out.MetricsAddr)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, out)
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	out.Enforce = enforce != 0
	rows, err := a.DB.Query(`SELECT name,scope,num_states,window_ns,terminal_action FROM rules WHERE node=? ORDER BY name`, node)
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var x bundleRule
		if err := rows.Scan(&x.Name, &x.Scope, &x.NumStates, &x.WindowNS, &x.TerminalAction); err != nil {
			fail(w, err)
			return
		}
		out.Bundle.Rules = append(out.Bundle.Rules, x)
	}
	writeJSON(w, out)
}
