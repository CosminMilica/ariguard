package ingest

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"time"
)

const maxBundleBytes = 4 << 20 // a policy bundle is small; cap the upload defensively

// SetPolicy stores the control plane's current policy bundle (F7). The rule pipeline (autogen /
// CI) PUTs the compiled bundle bytes here; agents poll GetPolicy and hot-swap a new version
// without an image rebuild. The version is the bundle's SHA-256, so an unchanged push is a no-op
// for every agent.
func (h *Handler) SetPolicy(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBundleBytes))
	if err != nil {
		http.Error(w, "read bundle: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(body) == 0 {
		http.Error(w, "empty bundle", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256(body)
	version := hex.EncodeToString(sum[:])[:16]
	_, err = h.DB.Exec(`INSERT INTO policy(id,version,bundle,ts_ns) VALUES(1,?,?,?)
		ON CONFLICT(id) DO UPDATE SET version=excluded.version, bundle=excluded.bundle, ts_ns=excluded.ts_ns`,
		version, body, time.Now().UnixNano())
	if err != nil {
		serverError(w, err)
		return
	}
	w.Header().Set("X-Policy-Version", version)
	w.WriteHeader(http.StatusNoContent)
}

// GetPolicy serves the current bundle to a polling agent. With a matching ?have=<version> it
// answers 304 (nothing to do); with no policy stored it answers 204 (the agent keeps its baked-in
// bundle). Otherwise it returns the raw bytes and the version header.
func (h *Handler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	var version string
	var bundle []byte
	err := h.DB.QueryRow(`SELECT version, bundle FROM policy WHERE id=1`).Scan(&version, &bundle)
	if errors.Is(err, sql.ErrNoRows) { // no policy stored: the agent keeps its baked-in bundle
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil { // a real DB error must not masquerade as "no policy"; surface it as a 500 (Tier 3)
		serverError(w, err)
		return
	}
	w.Header().Set("X-Policy-Version", version)
	if r.URL.Query().Get("have") == version {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(bundle)
}
