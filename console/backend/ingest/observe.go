package ingest

import (
	"encoding/json"
	"net/http"
)

// ObserveNamespaces returns the observe-only namespaces as a JSON array. Agents poll this so their
// kill-gate and responder skip pods in these namespaces (detect, never kill or quarantine) while
// still emitting their events. The frontend manages the list via the read API's POST/DELETE
// /api/observe-namespaces.
func (h *Handler) ObserveNamespaces(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Query(`SELECT namespace FROM observe_namespaces ORDER BY namespace`)
	if err != nil {
		serverError(w, err)
		return
	}
	defer rows.Close()
	namespaces := []string{}
	for rows.Next() {
		var ns string
		if err := rows.Scan(&ns); err != nil {
			serverError(w, err)
			return
		}
		namespaces = append(namespaces, ns)
	}
	if err := rows.Err(); err != nil {
		serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(namespaces)
}
