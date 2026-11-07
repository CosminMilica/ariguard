package ingest

import (
	"encoding/json"
	"net/http"
)

// LearnNamespaces returns the learn-mode namespaces as a JSON array (F11). Agents poll this so their
// learn emit is gated to pods in these namespaces (opt-in; empty = no emit). The frontend manages the
// list via the read API's POST/DELETE /api/learn-namespaces.
func (h *Handler) LearnNamespaces(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Query(`SELECT namespace FROM learn_namespaces ORDER BY namespace`)
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
