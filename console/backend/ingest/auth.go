package ingest

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// AuthPrefix guards the agent/control-plane endpoints: the fleet-facing /api/v1/... routes —
// register, audit, quarantine, traces and above all the policy PUT that every agent hot-swaps.
const AuthPrefix = "/api/v1/"

// operatorWritePrefixes are the read-API paths whose POST/DELETE change fleet behaviour (the
// detect/enforce mode, the mute allowlist, the observe-only and learn-mode namespace sets). They live
// on the browser-facing /api/ surface, but the *writes* must be token-gated: otherwise any in-cluster
// pod could flip the whole fleet to detect-only or mute the pod it is about to compromise. GET on
// these paths stays open (the frontend lists them without a token); only mutations require it.
var operatorWritePrefixes = []string{
	"/api/mode",
	"/api/mutes",
	"/api/observe-namespaces",
	"/api/learn-namespaces",
}

// needsAuth reports whether r must carry the token: every /api/v1/ request, plus any POST/DELETE to
// an operator-write path.
func needsAuth(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, AuthPrefix) {
		return true
	}
	if r.Method == http.MethodPost || r.Method == http.MethodDelete {
		for _, p := range operatorWritePrefixes {
			if strings.HasPrefix(r.URL.Path, p) {
				return true
			}
		}
	}
	return false
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
