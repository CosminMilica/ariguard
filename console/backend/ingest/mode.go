package ingest

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

// modeResp is the fleet enforcement mode: enforce true = kill at terminal states, false = detect
// only. set=false means the operator has not chosen a mode, so agents keep their launch-flag default.
type modeResp struct {
	Enforce bool `json:"enforce"`
	Set     bool `json:"set"`
}

// Mode returns the desired fleet enforcement mode. Agents poll this and hot-swap the current bundle
// under the new mode without a restart. The frontend sets it via the read API's POST /api/mode.
func (h *Handler) Mode(w http.ResponseWriter, r *http.Request) {
	var v string
	err := h.DB.QueryRow(`SELECT value FROM config WHERE key='enforce_mode'`).Scan(&v)
	resp := modeResp{}
	switch {
	case err == sql.ErrNoRows:
		// unset: agents keep their own mode
	case err != nil:
		serverError(w, err)
		return
	default:
		resp = modeResp{Enforce: v == "enforce", Set: true}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
