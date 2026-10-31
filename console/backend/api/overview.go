package api

import (
	"net/http"
	"time"
)

type point struct {
	T int64   `json:"t"` // bucket start, unix ms
	V float64 `json:"v"`
}

const seriesBuckets = 60

func (a *API) overview(w http.ResponseWriter, r *http.Request) {
	win := windowOf(r)
	now := time.Now()

	stats, err := a.latestStats()
	if err != nil {
		fail(w, err)
		return
	}
	var eps float64
	var killsTotal, dropped int64
	for _, s := range stats {
		eps += s.eventsPerSec
		killsTotal += s.kills + s.denies
		dropped += s.dropped
	}

	states := map[string]int{"normal": 0, "suspicious": 0, "escalating": 0, "breakout_imminent": 0, "compromised": 0}
	rows, err := a.DB.Query(`SELECT state, COUNT(*) FROM workloads WHERE pod NOT IN (SELECT pod FROM mutes) GROUP BY state`)
	if err != nil {
		fail(w, err)
		return
	}
	workloads := 0
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			rows.Close()
			fail(w, err)
			return
		}
		if _, ok := states[st]; ok {
			states[st] = n
		}
		workloads += n
	}
	rows.Close()

	var nrules, nagents int
	if err := a.DB.QueryRow(`SELECT COUNT(DISTINCT name) FROM rules`).Scan(&nrules); err != nil {
		fail(w, err)
		return
	}
	if err := a.DB.QueryRow(`SELECT COUNT(*) FROM nodes WHERE last_seen >= ?`, now.UnixMilli()-freshMS).Scan(&nagents); err != nil {
		fail(w, err)
		return
	}

	var kills int64
	if err := a.DB.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE enforced != 0 AND action IN ('kill','deny') AND ts_ns >= ? AND ts_ns <= ?`,
		win.fromNS(), win.toNS()).Scan(&kills); err != nil {
		fail(w, err)
		return
	}

	evSeries, killSeries, err := a.series(win)
	if err != nil {
		fail(w, err)
		return
	}

	writeJSON(w, map[string]any{
		"kpis": map[string]any{
			"workloads":      workloads,
			"events_per_sec": eps,
			"kills":          kills,
			"kills_total":    killsTotal,
			"audit_dropped":  dropped,
			"rules":          nrules,
			"agents":         nagents,
		},
		"events_series":   evSeries,
		"kills_series":    killSeries,
		"state_breakdown": states,
	})
}

// series buckets the window into seriesBuckets slots. Events are a per-second rate
// derived from per-node counter deltas; kills are the enforced mitigation audit
// events (kill and deny) per bucket.
func (a *API) series(win window) (ev, kills []point, err error) {
	span := win.To - win.From
	width := span / seriesBuckets
	if width < 1 {
		width = 1
	}
	start := win.From
	idx := func(ts int64) int {
		b := int((ts - start) / width)
		if b >= seriesBuckets {
			b = seriesBuckets - 1
		}
		return b
	}
	ev = make([]point, seriesBuckets)
	kills = make([]point, seriesBuckets)
	for i := range ev {
		t := start + int64(i)*width
		ev[i], kills[i] = point{T: t}, point{T: t}
	}

	rows, err := a.DB.Query(`SELECT node, ts, events FROM metric_samples WHERE ts >= ? AND ts <= ? ORDER BY node, ts`, start, win.To)
	if err != nil {
		return nil, nil, err
	}
	var lastNode string
	var lastEv int64
	have := false
	for rows.Next() {
		var node string
		var ts, e int64
		if err := rows.Scan(&node, &ts, &e); err != nil {
			rows.Close()
			return nil, nil, err
		}
		if have && node == lastNode {
			if b := idx(ts); b >= 0 {
				if d := e - lastEv; d > 0 {
					ev[b].V += float64(d)
				}
			}
		}
		lastNode, lastEv, have = node, e, true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, err
	}
	rows.Close()
	for i := range ev {
		ev[i].V /= float64(width) / 1000
	}

	kr, err := a.DB.Query(`SELECT ts_ns FROM audit_events WHERE enforced != 0 AND action IN ('kill','deny') AND ts_ns >= ? AND ts_ns <= ?`,
		win.fromNS(), win.toNS())
	if err != nil {
		return nil, nil, err
	}
	defer kr.Close()
	for kr.Next() {
		var ns int64
		if err := kr.Scan(&ns); err != nil {
			return nil, nil, err
		}
		if b := idx(ns / 1_000_000); b >= 0 {
			kills[b].V++
		}
	}
	return ev, kills, kr.Err()
}
