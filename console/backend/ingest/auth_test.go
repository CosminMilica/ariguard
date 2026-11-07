package ingest

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func authProbe(t *testing.T, token, path, authHeader string) int {
	return authProbeM(t, http.MethodGet, token, path, authHeader)
}

func authProbeM(t *testing.T, method, token, path, authHeader string) int {
	t.Helper()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	req := httptest.NewRequest(method, path, nil)
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

func TestAuthGuardsOperatorWrites(t *testing.T) {
	const tok = "s3cr3t"
	for _, p := range []string{"/api/mode", "/api/mutes", "/api/mutes/web", "/api/observe-namespaces", "/api/learn-namespaces", "/api/learn-namespaces/ns"} {
		for _, m := range []string{http.MethodPost, http.MethodDelete} {
			// an unauthenticated write to an operator path is rejected
			if c := authProbeM(t, m, tok, p, ""); c != http.StatusUnauthorized {
				t.Fatalf("%s %s no token -> %d, want 401", m, p, c)
			}
			// with the token it passes
			if c := authProbeM(t, m, tok, p, "Bearer "+tok); c != http.StatusOK {
				t.Fatalf("%s %s with token -> %d, want 200", m, p, c)
			}
		}
		// GET stays open (the frontend lists these without a token)
		if c := authProbeM(t, http.MethodGet, tok, p, ""); c != http.StatusOK {
			t.Fatalf("GET %s -> %d, want 200 (open)", p, c)
		}
	}
	// an unrelated read-API write is NOT gated (only the operator-write paths are)
	if c := authProbeM(t, http.MethodPost, tok, "/api/something-else", ""); c != http.StatusOK {
		t.Fatalf("non-operator POST -> %d, want 200", c)
	}
}
