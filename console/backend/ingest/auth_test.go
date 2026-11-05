package ingest

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func authProbe(t *testing.T, token, path, authHeader string) int {
	t.Helper()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	Auth(token, ok).ServeHTTP(rec, req)
	return rec.Code
}

func TestAuthGuardsControlPlane(t *testing.T) {
	const tok = "s3cr3t"
	// control-plane path: needs the right bearer token
	if c := authProbe(t, tok, "/api/v1/policy", ""); c != http.StatusUnauthorized {
		t.Fatalf("no token -> %d, want 401", c)
	}
	if c := authProbe(t, tok, "/api/v1/policy", "Bearer wrong"); c != http.StatusUnauthorized {
		t.Fatalf("wrong token -> %d, want 401", c)
	}
	if c := authProbe(t, tok, "/api/v1/policy", "Bearer "+tok); c != http.StatusOK {
		t.Fatalf("right token -> %d, want 200", c)
	}
}

func TestAuthLeavesReadAPIOpen(t *testing.T) {
	// the browser read API (/api/...) is not under /api/v1 and needs no token
	if c := authProbe(t, "s3cr3t", "/api/overview", ""); c != http.StatusOK {
		t.Fatalf("read api -> %d, want 200", c)
	}
}

func TestAuthDisabledWhenNoToken(t *testing.T) {
	// an empty token disables the check (dev / backward-compat)
	if c := authProbe(t, "", "/api/v1/policy", ""); c != http.StatusOK {
		t.Fatalf("empty token -> %d, want 200 (disabled)", c)
	}
}
