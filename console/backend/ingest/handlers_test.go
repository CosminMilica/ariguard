package ingest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func do(t *testing.T, h *Handler, fn http.HandlerFunc, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	rec := httptest.NewRecorder()
	fn(rec, req)
	return rec
}

func countRows(t *testing.T, h *Handler, q string) int {
	t.Helper()
	var n int
	if err := h.DB.QueryRow(q).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// --- Register -------------------------------------------------------------------------------

func TestRegisterStoresNodeAndRules(t *testing.T) {
	h := testDB(t)
	body := `{"node":"n1","kernel":"6.8","enforce":true,"hooks_attached":16,"hooks_total":16,
		"bundle":{"rules":[{"name":"container-escape","scope":"cgroup","num_states":5,"terminal_action":"kill",
		"states":["normal"],"events":["e"],"transitions":[{"from":"normal","event":"e","to":"normal","action":"observe"}]}]}}`
	if rec := do(t, h, h.Register, http.MethodPost, "/api/v1/register", body); rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if n := countRows(t, h, `SELECT COUNT(*) FROM nodes WHERE node='n1'`); n != 1 {
		t.Fatalf("nodes=%d", n)
	}
	if n := countRows(t, h, `SELECT COUNT(*) FROM rules WHERE node='n1'`); n != 1 {
		t.Fatalf("rules=%d", n)
	}
	// re-register replaces the rule set (no duplicates)
	do(t, h, h.Register, http.MethodPost, "/api/v1/register", body)
	if n := countRows(t, h, `SELECT COUNT(*) FROM rules WHERE node='n1'`); n != 1 {
		t.Fatalf("rules after re-register=%d, want 1", n)
	}
}

func TestRegisterRejectsBadInput(t *testing.T) {
	h := testDB(t)
	if rec := do(t, h, h.Register, http.MethodPost, "/api/v1/register", `{"node":""}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty node: status=%d", rec.Code)
	}
	if rec := do(t, h, h.Register, http.MethodPost, "/api/v1/register", `{ not json`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json: status=%d", rec.Code)
	}
}

// --- Audit ----------------------------------------------------------------------------------

func TestAuditStoresEventsAndRefreshesWorkloads(t *testing.T) {
	h := testDB(t)
	batch := `[{"ts_ns":1700000000000000000,"node":"n1","pod":"p1","namespace":"ns","comm":"sh","rule":"reverse-shell",
		"event":"shell_exec","from":"connected","to":"compromised","action":"kill","enforced":true,"hook":"execve",
		"owner":"Deployment/app","dst_ip":"1.2.3.4","dst_port":4444}]`
	if rec := do(t, h, h.Audit, http.MethodPost, "/api/v1/audit", batch); rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if n := countRows(t, h, `SELECT COUNT(*) FROM audit_events WHERE pod='p1'`); n != 1 {
		t.Fatalf("audit_events=%d", n)
	}
	if n := countRows(t, h, `SELECT COUNT(*) FROM workloads WHERE pod='p1' AND state='compromised'`); n != 1 {
		t.Fatalf("workloads not refreshed")
	}
	var owner string
	_ = h.DB.QueryRow(`SELECT owner FROM audit_events WHERE pod='p1'`).Scan(&owner)
	if owner != "Deployment/app" {
		t.Fatalf("owner=%q", owner)
	}
}

func TestAuditReplacesMonotonicTimestamp(t *testing.T) {
	h := testDB(t)
	// a ts below the wall-clock floor is treated as monotonic and replaced by receive time.
	do(t, h, h.Audit, http.MethodPost, "/api/v1/audit", `[{"ts_ns":123,"node":"n","pod":"p","rule":"r","to":"suspicious"}]`)
	var ts int64
	_ = h.DB.QueryRow(`SELECT ts_ns FROM audit_events WHERE pod='p'`).Scan(&ts)
	if ts < minWallNS {
		t.Fatalf("monotonic ts not replaced: %d", ts)
	}
}

func TestAuditRejectsBadJSON(t *testing.T) {
	h := testDB(t)
	if rec := do(t, h, h.Audit, http.MethodPost, "/api/v1/audit", `[{"ts_ns":`); rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
}

// --- Policy (F7 control plane) --------------------------------------------------------------

func TestPolicyRoundTrip(t *testing.T) {
	h := testDB(t)
	// nothing stored yet -> 204, agent keeps its baked-in bundle
	if rec := do(t, h, h.GetPolicy, http.MethodGet, "/api/v1/policy", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("empty get: status=%d", rec.Code)
	}
	// empty PUT rejected
	if rec := do(t, h, h.SetPolicy, http.MethodPut, "/api/v1/policy", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty put: status=%d", rec.Code)
	}
	// store a bundle
	rec := do(t, h, h.SetPolicy, http.MethodPut, "/api/v1/policy", "BUNDLE-BYTES")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("put: status=%d", rec.Code)
	}
	ver := rec.Header().Get("X-Policy-Version")
	if ver == "" {
		t.Fatal("no version header")
	}
	// GET returns the bytes + version
	rec = do(t, h, h.GetPolicy, http.MethodGet, "/api/v1/policy", "")
	if rec.Code != http.StatusOK || rec.Body.String() != "BUNDLE-BYTES" {
		t.Fatalf("get: status=%d body=%q", rec.Code, rec.Body.String())
	}
	// conditional GET with the current version -> 304
	rec = do(t, h, h.GetPolicy, http.MethodGet, "/api/v1/policy?have="+ver, "")
	if rec.Code != http.StatusNotModified {
		t.Fatalf("conditional get: status=%d", rec.Code)
	}
	// an unchanged re-push yields the same version (fleet-wide no-op)
	rec2 := do(t, h, h.SetPolicy, http.MethodPut, "/api/v1/policy", "BUNDLE-BYTES")
	if rec2.Header().Get("X-Policy-Version") != ver {
		t.Fatalf("version changed on identical push")
	}
}

// TestGetPolicyDBErrorIs500 verifies a real DB error no longer masquerades as 204 "no policy";
// only sql.ErrNoRows gives 204. (Tier 3)
func TestGetPolicyDBErrorIs500(t *testing.T) {
	h := testDB(t)
	if _, err := h.DB.Exec(`DROP TABLE policy`); err != nil {
		t.Fatalf("drop policy: %v", err)
	}
	rec := do(t, h, h.GetPolicy, http.MethodGet, "/api/v1/policy", "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("GetPolicy with a broken table: status=%d, want 500", rec.Code)
	}
}

// --- Mutes + Quarantine ---------------------------------------------------------------------

func TestMutesListsMutedPods(t *testing.T) {
	h := testDB(t)
	if _, err := h.DB.Exec(`INSERT INTO mutes(pod) VALUES('a'),('b')`); err != nil {
		t.Fatal(err)
	}
	rec := do(t, h, h.Mutes, http.MethodGet, "/api/v1/mutes", "")
	body, _ := io.ReadAll(rec.Result().Body)
	if rec.Code != http.StatusOK || !strings.Contains(string(body), `"a"`) || !strings.Contains(string(body), `"b"`) {
		t.Fatalf("status=%d body=%s", rec.Code, body)
	}
}

func TestQuarantineStoresEvent(t *testing.T) {
	h := testDB(t)
	body := `{"node":"n1","namespace":"ns","pod":"p1","rule":"container-escape","mode":"on","ts_ns":1700000000000000000}`
	if rec := do(t, h, h.Quarantine, http.MethodPost, "/api/v1/quarantine", body); rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if n := countRows(t, h, `SELECT COUNT(*) FROM quarantine WHERE pod='p1'`); n != 1 {
		t.Fatalf("quarantine rows=%d", n)
	}
}
