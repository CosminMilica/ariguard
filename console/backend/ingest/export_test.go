package ingest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CosminMilica/ariguard/console/backend/store"
)

func testDB(t *testing.T) *Handler {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return &Handler{DB: db}
}

func insertAudit(t *testing.T, h *Handler, rule, pod, to string, tsNS int64) {
	t.Helper()
	_, err := h.DB.Exec(`INSERT INTO audit_events(ts_ns,node,pod,rule,event,to_state,action,cgroup_id,pid,hook,dst_ip)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`, tsNS, "n1", pod, rule, "e0", to, "observe", 42, 7, "execve", "")
	if err != nil {
		t.Fatalf("insert audit: %v", err)
	}
}

func TestAuditExportPagesByID(t *testing.T) {
	h := testDB(t)
	for i := range 5 {
		insertAudit(t, h, "reverse-shell", "p1", "compromised", int64(1_700_000_000_000_000_000+i))
	}

	// first page, limit 3
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/export?since=0&limit=3", nil)
	rec := httptest.NewRecorder()
	h.AuditExport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Fatalf("content-type = %q", ct)
	}
	rows := parseJSONL(t, rec.Body.String())
	if len(rows) != 3 {
		t.Fatalf("page 1 = %d rows, want 3", len(rows))
	}
	// oldest-first, ascending ids, and the fields the miner needs are present
	if rows[0]["hook"] != "execve" || rows[0]["cgroup_id"].(float64) != 42 {
		t.Fatalf("row shape wrong: %+v", rows[0])
	}
	lastID := int64(rows[2]["id"].(float64))

	// next page from the cursor returns the remaining 2
	req = httptest.NewRequest(http.MethodGet, "/api/v1/audit/export?since="+itoa(lastID), nil)
	rec = httptest.NewRecorder()
	h.AuditExport(rec, req)
	rows = parseJSONL(t, rec.Body.String())
	if len(rows) != 2 {
		t.Fatalf("page 2 = %d rows, want 2", len(rows))
	}
}

func TestRuleTelemetryCountsHitsAndBenignFires(t *testing.T) {
	h := testDB(t)
	base := int64(1_700_000_000_000_000_000)
	day := int64(86_400 * 1_000_000_000)
	// a proven rule: 3 terminal hits across 2 pods over 8 days, none muted
	insertAudit(t, h, "auto-a", "podA", "compromised", base)
	insertAudit(t, h, "auto-a", "podA", "compromised", base+day)
	insertAudit(t, h, "auto-a", "podB", "compromised", base+8*day)
	// a rule that fired on a muted (known-good) pod => benign fire
	insertAudit(t, h, "auto-b", "podMuted", "compromised", base)
	// a non-threat state must NOT count as a hit
	insertAudit(t, h, "auto-a", "podC", "connected", base+2*day)
	if _, err := h.DB.Exec(`INSERT INTO mutes(pod) VALUES('/podMuted')`); err != nil {
		t.Fatalf("mute: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/telemetry", nil)
	rec := httptest.NewRecorder()
	h.RuleTelemetry(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var out []telemetryRow
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byRule := map[string]telemetryRow{}
	for _, r := range out {
		byRule[r.Rule] = r
	}
	a, b := byRule["auto-a"], byRule["auto-b"]
	if a.Hits != 3 || a.DistinctPod != 2 || a.BenignFires != 0 {
		t.Fatalf("auto-a = %+v, want hits=3 pods=2 benign=0 (connected excluded)", a)
	}
	if got := a.LastSeenNS - a.FirstSeenNS; got != 8*day {
		t.Fatalf("auto-a span = %d, want %d", got, 8*day)
	}
	if b.Hits != 1 || b.BenignFires != 1 {
		t.Fatalf("auto-b = %+v, want hits=1 benign=1", b)
	}
}

func parseJSONL(t *testing.T, body string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad jsonl line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func itoa(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}
