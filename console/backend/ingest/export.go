package ingest

import (
	"encoding/json"
	"net/http"
	"strconv"
)

const (
	exportDefaultLimit = 20_000
	exportMaxLimit     = 50_000
)

// threatStatesSQL mirrors api.threatStatesSQL: the FSM states that denote real threat progression.
// A rule "hit" for telemetry is reaching one of these (not a bare `connected`/`normal`).
const threatStatesSQL = `('suspicious','memfd_created','stdio_redirected','escalating','breakout_imminent','compromised')`

// exportRow is one raw audit event, with the field names the compiler's trace.from_audit expects
// (cgroup_id, pid, ts_ns, hook, dst_ip) plus enough context for provenance. The `id` is the paging
// cursor: the caller pulls again with ?since=<max id seen>.
type exportRow struct {
	ID        int64  `json:"id"`
	TsNS      int64  `json:"ts_ns"`
	Node      string `json:"node"`
	Pod       string `json:"pod"`
	Namespace string `json:"namespace"`
	Comm      string `json:"comm"`
	Rule      string `json:"rule"`
	Event     string `json:"event"`
	From      string `json:"from"`
	To        string `json:"to"`
	Action    string `json:"action"`
	CgroupID  int64  `json:"cgroup_id"`
	PID       int64  `json:"pid"`
	Ppid      int64  `json:"ppid"`
	Hook      string `json:"hook"`
	DstIP     string `json:"dst_ip"`
	DstPort   int64  `json:"dst_port"`
}

// AuditExport streams raw audit events as JSONL for the autonomous rule-generation loop (F11) to
// mine. Rows are returned oldest-first with id > ?since, capped at ?limit, so a miner pages the
// whole history deterministically by the last id it saw.
func (h *Handler) AuditExport(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	limit := exportDefaultLimit
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = v
	}
	if limit > exportMaxLimit {
		limit = exportMaxLimit
	}

	rows, err := h.DB.Query(`SELECT id,ts_ns,node,pod,namespace,comm,rule,event,from_state,to_state,action,cgroup_id,pid,ppid,hook,dst_ip,dst_port
		FROM audit_events WHERE id > ? ORDER BY id ASC LIMIT ?`, since, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "application/x-ndjson")
	enc := json.NewEncoder(w)
	for rows.Next() {
		var e exportRow
		if err := rows.Scan(&e.ID, &e.TsNS, &e.Node, &e.Pod, &e.Namespace, &e.Comm, &e.Rule, &e.Event,
			&e.From, &e.To, &e.Action, &e.CgroupID, &e.PID, &e.Ppid, &e.Hook, &e.DstIP, &e.DstPort); err != nil {
			return // best-effort stream; a mid-stream error just ends the batch
		}
		_ = enc.Encode(&e) // one JSON object per line
	}
}

// telemetryRow is a rule's measured behavior, the input to the loop's shadow->enforce decision.
type telemetryRow struct {
	Rule        string `json:"rule"`
	Hits        int64  `json:"hits"`
	DistinctPod int64  `json:"distinct_pods"`
	BenignFires int64  `json:"benign_fires"`
	FirstSeenNS int64  `json:"first_seen_ns"`
	LastSeenNS  int64  `json:"last_seen_ns"`
}

// RuleTelemetry reports, per rule, how often it reached a terminal/threat state, over how many
// distinct pods and how long, and how many of those fires were on a muted (operator-declared
// known-good) pod -- the benign-fire signal that retires a rule. The loop reads this to promote a
// proven shadow rule to enforce, hold it, or retire one that fired on benign traffic.
func (h *Handler) RuleTelemetry(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Query(`SELECT a.rule,
		  COUNT(*),
		  COUNT(DISTINCT a.pod),
		  COALESCE(SUM(CASE WHEN m.pod IS NOT NULL THEN 1 ELSE 0 END),0),
		  MIN(a.ts_ns), MAX(a.ts_ns)
		FROM audit_events a
		LEFT JOIN mutes m ON m.pod = a.pod
		WHERE a.rule != '' AND a.to_state IN ` + threatStatesSQL + `
		GROUP BY a.rule ORDER BY a.rule`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	out := []telemetryRow{}
	for rows.Next() {
		var t telemetryRow
		if err := rows.Scan(&t.Rule, &t.Hits, &t.DistinctPod, &t.BenignFires, &t.FirstSeenNS, &t.LastSeenNS); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out = append(out, t)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
