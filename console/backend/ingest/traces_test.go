package ingest

import (
	"net/http"
	"net/http/httptest"
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
