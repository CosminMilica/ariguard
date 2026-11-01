package api

import "net/http"

type progPerf struct {
	Program  string  `json:"program"`
	Runs     int64   `json:"runs"`
	NsPerRun float64 `json:"ns_per_run"`
}

// perf serves agent performance metrics: the pre-allocated BPF map budget, the
// current events/sec and dropped-audit counters, and per eBPF program lifetime
// run counts with the average time per run.
func (a *API) perf(w http.ResponseWriter, r *http.Request) {
	stats, err := a.latestStats()
	if err != nil {
		fail(w, err)
		return
	}
	var eps float64
	var dropped int64
	for _, s := range stats {
		eps += s.eventsPerSec
		dropped += s.dropped
	}

	// bpf_map_bytes is a per-node constant budget; report a single value.
	var bpf int64
	if err := a.DB.QueryRow(`SELECT COALESCE(MAX(bpf_map_bytes),0) FROM nodes`).Scan(&bpf); err != nil {
		fail(w, err)
		return
	}

	// Aggregate per-program counters across nodes.
	rows, err := a.DB.Query(`SELECT program, SUM(runs), SUM(run_time_ns) FROM program_stats GROUP BY program ORDER BY program`)
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()
	programs := []progPerf{}
	for rows.Next() {
		var p progPerf
		var runTimeNS int64
		if err := rows.Scan(&p.Program, &p.Runs, &runTimeNS); err != nil {
			fail(w, err)
			return
		}
		if p.Runs > 0 {
			p.NsPerRun = float64(runTimeNS) / float64(p.Runs)
		}
		programs = append(programs, p)
	}
	if err := rows.Err(); err != nil {
		fail(w, err)
		return
	}

	writeJSON(w, map[string]any{
		"bpf_map_bytes":  bpf,
		"events_per_sec": eps,
		"audit_dropped":  dropped,
		"programs":       programs,
	})
}
