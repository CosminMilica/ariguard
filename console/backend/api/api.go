// Package api serves the read API used by the console frontend.
package api

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const freshMS = 30_000 // a node is "ready" if seen within this window

type API struct{ DB *sql.DB }

// Routes registers all read endpoints and the mute actions on mux.
func (a *API) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/overview", a.overview)
	mux.HandleFunc("GET /api/workloads", a.workloads)
	mux.HandleFunc("GET /api/events", a.events)
	mux.HandleFunc("GET /api/rules", a.rules)
	mux.HandleFunc("GET /api/nodes", a.nodes)
	mux.HandleFunc("GET /api/settings", a.settings)
	mux.HandleFunc("GET /api/chain", a.chain)
	mux.HandleFunc("GET /api/incidents", a.incidents)
	mux.HandleFunc("GET /api/triage", a.triage)
	mux.HandleFunc("GET /api/quarantine", a.quarantine)
	mux.HandleFunc("GET /api/campaigns", a.campaigns)
	mux.HandleFunc("GET /api/fleet", a.fleet)
	mux.HandleFunc("GET /api/actors", a.actors)
	mux.HandleFunc("GET /api/lateral", a.lateral)
	mux.HandleFunc("GET /api/edges", a.edges)
	mux.HandleFunc("GET /api/policy", a.policy)
	mux.HandleFunc("GET /api/autonomy", a.autonomyView)
	mux.HandleFunc("GET /api/containment", a.containment)
	mux.HandleFunc("GET /api/coverage", a.coverage)
	mux.HandleFunc("GET /api/export", a.export)
	mux.HandleFunc("GET /api/perf", a.perf)
	mux.HandleFunc("POST /api/mutes", a.mute)
	mux.HandleFunc("DELETE /api/mutes/{pod}", a.unmute)
	mux.HandleFunc("GET /api/observe-namespaces", a.observeNamespaces)
	mux.HandleFunc("POST /api/observe-namespaces", a.observeNamespace)
	mux.HandleFunc("DELETE /api/observe-namespaces/{ns}", a.unobserveNamespace)
	mux.HandleFunc("GET /api/learn-namespaces", a.learnNamespaces)
	mux.HandleFunc("POST /api/learn-namespaces", a.learnNamespace)
	mux.HandleFunc("DELETE /api/learn-namespaces/{ns}", a.unlearnNamespace)
	mux.HandleFunc("GET /api/traces/stats", a.traceStats)
	mux.HandleFunc("GET /api/mode", a.mode)
	mux.HandleFunc("POST /api/mode", a.setMode)
}

// CORS allows any origin to call the API (used by the Vite dev server).
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("api: encode: %v", err)
	}
}

// fail logs the real error server-side and returns a generic message to the client so internal
// detail (SQL text, schema, paths) is not leaked. 4xx validation errors are written directly by
// handlers and keep their specific messages. (Tier 4)
func fail(w http.ResponseWriter, err error) {
	log.Printf("api: %v", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// window is a resolved [From, To] time window in unix milliseconds.
type window struct{ From, To int64 }

func (w window) fromNS() int64 { return w.From * 1_000_000 }

// toNS covers the whole `to` millisecond (+999_999ns) so ns-precision events recorded
// within the same millisecond as `to` (e.g. just-ingested events at ~now) are included.
func (w window) toNS() int64 { return w.To*1_000_000 + 999_999 }

// maxWindowMs caps the explicit query span so an unauthenticated caller cannot force a full-table
// aggregation (e.g. ?from=0&to=now) that holds the single DB connection for seconds and stalls
// ingest. It also keeps toNS() well clear of int64 overflow. (M1)
const maxWindowMs int64 = 31 * 24 * 60 * 60 * 1000 // 31 days

// windowOf resolves the query window: an explicit ?from=&to= (unix millis, from < to)
// wins; otherwise ?range=15m|1h|24h (default 15m) ending now. An over-long explicit span is clamped
// to the most recent maxWindowMs.
func windowOf(r *http.Request) window {
	q := r.URL.Query()
	if f, t := q.Get("from"), q.Get("to"); f != "" && t != "" {
		from, e1 := strconv.ParseInt(f, 10, 64)
		to, e2 := strconv.ParseInt(t, 10, 64)
		if e1 == nil && e2 == nil && from >= 0 && to > from {
			if to-from > maxWindowMs {
				from = to - maxWindowMs
			}
			return window{from, to}
		}
	}
	d := 15 * time.Minute
	switch q.Get("range") {
	case "1h":
		d = time.Hour
	case "24h":
		d = 24 * time.Hour
	}
	now := time.Now().UnixMilli()
	return window{now - d.Milliseconds(), now}
}

// likeEscaper escapes the LIKE metacharacters %, _ and the escape character itself so that
// caller-supplied search text matches literally rather than as wildcards.
var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// like wraps q as a case-insensitive substring LIKE pattern with its metacharacters escaped. Every
// LIKE clause fed by like() must append ESCAPE '\' so the escapes are honored. (Tier 4)
func like(q string) string { return "%" + likeEscaper.Replace(q) + "%" }

var stateSeverity = map[string]string{
	"compromised":       "crit",
	"breakout_imminent": "crit",
	"escalating":        "mid",
	"suspicious":        "warn",
	"memfd_created":     "warn", // fileless-exec staging — rare, worth surfacing
	"stdio_redirected":  "warn", // reverse-shell stdio→socket — rare, worth surfacing
}

// threatStatesSQL lists the FSM states that denote real threat progression. A workload is
// "alerting" when it reaches one of these. `normal` and reverse-shell's `connected` (a bare
// outbound connect, which every pod makes) are benign and excluded — connecting out is not itself
// an attack, so it must not flag kube-apiserver/agent/etc. as threats.
const threatStatesSQL = `('suspicious','memfd_created','stdio_redirected','escalating','breakout_imminent','compromised')`

// nodeStats holds the latest counters and the rate between the last two samples.
type nodeStats struct {
	eventsPerSec float64
	kills        int64
	denies       int64
	dropped      int64
}

// latestStats returns per-node stats derived from the two newest metric samples.
func (a *API) latestStats() (map[string]nodeStats, error) {
	rows, err := a.DB.Query(`SELECT node, ts, events, kills, denies, audit_dropped FROM (
		SELECT *, ROW_NUMBER() OVER (PARTITION BY node ORDER BY ts DESC) rn FROM metric_samples
	) WHERE rn <= 2 ORDER BY node, ts DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]nodeStats{}
	prev := map[string]struct{ ts, events int64 }{}
	for rows.Next() {
		var node string
		var ts, ev, k, dn, d int64
		if err := rows.Scan(&node, &ts, &ev, &k, &dn, &d); err != nil {
			return nil, err
		}
		st, seen := out[node]
		if !seen {
			out[node] = nodeStats{kills: k, denies: dn, dropped: d}
			prev[node] = struct{ ts, events int64 }{ts, ev}
			continue
		}
		p := prev[node]
		if dt := p.ts - ts; dt > 0 && p.events >= ev {
			st.eventsPerSec = float64(p.events-ev) / (float64(dt) / 1000)
		}
		out[node] = st
	}
	return out, rows.Err()
}
