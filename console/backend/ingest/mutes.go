package ingest

import (
	"encoding/json"
	"net/http"
)

// Mutes returns the muted pod names as a JSON array. Agents poll this so their responder and
// kill-gating honor the operator's allowlist (F5). The frontend manages the list via the
// read API's POST/DELETE /api/mutes.
func (h *Handler) Mutes(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Query(`SELECT pod FROM mutes ORDER BY pod`)
	if err != nil {
		serverError(w, err)
		return
	}
	defer rows.Close()
	pods := []string{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			serverError(w, err)
			return
		}
		pods = append(pods, p)
	}
	if err := rows.Err(); err != nil {
		serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(pods)
}
