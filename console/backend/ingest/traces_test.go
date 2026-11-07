package ingest

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func postTraces(t *testing.T, h *Handler, body string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/traces", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.Traces(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("POST status = %d", rec.Code)
	}
	return rec.Code
}

func TestTracesStoreDedupAndExport(t *testing.T) {
	h := testDB(t)
	line1 := `{"label":"attack","source":"honeypot","events":[{"hook":"execve","path":"/bin/sh"},{"hook":"openat","path":"/etc/cron.d/x"}]}`
	line2 := `{"label":"attack","source":"honeypot","events":[{"hook":"connect","inet":true},{"hook":"dup2"},{"hook":"execve"}]}`

	postTraces(t, h, line1+"\n"+line2+"\n")
	// re-posting the same batch is deduped by content hash
	postTraces(t, h, line1+"\n"+line2+"\n")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/traces/export", nil)
	rec := httptest.NewRecorder()
	h.TracesExport(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("export status=%d ct=%q", rec.Code, rec.Header().Get("Content-Type"))
	}
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("export returned %d traces, want 2 (deduped)", len(lines))
	}
	if !strings.Contains(lines[0], `"hook":"execve"`) {
		t.Fatalf("export line not the stored trace: %q", lines[0])
	}
}

// TestTracesAcceptedCountsNewRowsOnly verifies X-Traces-Accepted reports actually-inserted rows,
// not every submitted line (INSERT OR IGNORE dedups duplicates by content hash). (Tier 4)
func TestTracesAcceptedCountsNewRowsOnly(t *testing.T) {
	h := testDB(t)
	line1 := `{"label":"attack","source":"honeypot","events":[{"hook":"execve"}]}`
	line2 := `{"label":"attack","source":"honeypot","events":[{"hook":"connect"}]}`
	line3 := `{"label":"attack","source":"honeypot","events":[{"hook":"dup2"}]}`

	accepted := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/traces", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.Traces(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status=%d", rec.Code)
		}
		n, _ := strconv.Atoi(rec.Header().Get("X-Traces-Accepted"))
		return n
	}

	if n := accepted(line1 + "\n" + line2 + "\n"); n != 2 {
		t.Fatalf("first post X-Traces-Accepted=%d, want 2", n)
	}
	// line1 is a duplicate (ignored); line3 is new → only 1 newly inserted
	if n := accepted(line1 + "\n" + line3 + "\n"); n != 1 {
		t.Fatalf("second post X-Traces-Accepted=%d, want 1 (one duplicate ignored)", n)
	}
}

func TestTracesSkipsMalformedLines(t *testing.T) {
	h := testDB(t)
	postTraces(t, h, "not json\n"+`{"label":"attack","source":"h","events":[{"hook":"bpf"}]}`+"\n")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/traces/export", nil)
	rec := httptest.NewRecorder()
	h.TracesExport(rec, req)
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d traces, want 1 (malformed line skipped)", len(lines))
	}
}
