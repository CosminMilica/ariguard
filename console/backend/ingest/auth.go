package ingest

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// AuthPrefix guards the agent/control-plane endpoints: the fleet-facing /api/v1/... routes —
// register, audit, quarantine, traces and above all the policy PUT that every agent hot-swaps.
const AuthPrefix = "/api/v1/"

// apiPrefix is the whole API surface. When a token is configured, EVERY /api/ request requires it
// (M5): the read API otherwise leaks the full rule set, detection coverage and per-pod attack chains
// to any in-cluster pod, letting an attacker map coverage and craft a bypass. The frontend attaches
// the operator token (set in Settings) to all requests, so the browser UI keeps working. Static
// assets are served outside /api/ and stay open so the operator can reach the Settings page to set
// the token. An empty token (dev) disables the check.
const apiPrefix = "/api/"

// needsAuth reports whether r must carry the token: any request under /api/ (which includes the
// fleet-facing /api/v1/ control plane and the browser read/operator API).
func needsAuth(r *http.Request) bool {
	return strings.HasPrefix(r.URL.Path, apiPrefix)
}

// Auth wraps next so protected requests (see needsAuth) must carry "Authorization: Bearer <token>".
// An empty token disables the check (dev / backward-compat); the caller logs a warning in that case.
// The token is compared in constant time.
func Auth(token string, next http.Handler) http.Handler {
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" && needsAuth(r) {
			got := []byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			if subtle.ConstantTimeCompare(got, want) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
