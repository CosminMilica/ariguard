package ingest

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// AuthPrefix guards the agent/control-plane endpoints. The read API the browser uses (/api/...) is
// left open; only the fleet-facing /api/v1/... routes — register, audit, quarantine, traces and
// above all the policy PUT that every agent hot-swaps — require the shared token.
const AuthPrefix = "/api/v1/"

// Auth wraps next so requests to AuthPrefix must carry "Authorization: Bearer <token>". An empty
// token disables the check (dev / backward-compat); the caller logs a warning in that case. The
// token is compared in constant time.
func Auth(token string, next http.Handler) http.Handler {
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" && strings.HasPrefix(r.URL.Path, AuthPrefix) {
			got := []byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			if subtle.ConstantTimeCompare(got, want) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
