package api

import (
	"encoding/json"
	"net/http"
)

// observeNamespaces lists the observe-only namespaces for the frontend.
func (a *API) observeNamespaces(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.Query(`SELECT namespace FROM observe_namespaces ORDER BY namespace`)
	if err != nil {
		fail(w, err)
		return
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var ns string
		if err := rows.Scan(&ns); err != nil {
			fail(w, err)
			return
		}
		out = append(out, ns)
	}
	if err := rows.Err(); err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, out)
}

// observeNamespace marks a namespace observe-only (detect, never kill/quarantine; traffic still
// counts as attack). Agents pick it up on their next poll.
func (a *API) observeNamespace(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Namespace string `json:"namespace"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil || body.Namespace == "" {
		http.Error(w, "namespace is required", http.StatusBadRequest)
		return
	}
	if _, err := a.DB.Exec(`INSERT OR IGNORE INTO observe_namespaces(namespace) VALUES(?)`, body.Namespace); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// unobserveNamespace returns a namespace to the fleet's enforcement mode.
func (a *API) unobserveNamespace(w http.ResponseWriter, r *http.Request) {
	if _, err := a.DB.Exec(`DELETE FROM observe_namespaces WHERE namespace=?`, r.PathValue("ns")); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
