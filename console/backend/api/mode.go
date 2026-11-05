package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
)

type modeBody struct {
	Enforce bool `json:"enforce"`
	Set     bool `json:"set"`
}

// mode reports the operator's desired fleet enforcement mode for the frontend toggle.
func (a *API) mode(w http.ResponseWriter, r *http.Request) {
	var v string
	err := a.DB.QueryRow(`SELECT value FROM config WHERE key='enforce_mode'`).Scan(&v)
	switch {
	case err == sql.ErrNoRows:
		writeJSON(w, modeBody{})
	case err != nil:
		fail(w, err)
	default:
		writeJSON(w, modeBody{Enforce: v == "enforce", Set: true})
	}
}

// setMode records the desired fleet enforcement mode. Agents pick it up on their next poll and
// hot-swap the current bundle under the new mode (no restart).
func (a *API) setMode(w http.ResponseWriter, r *http.Request) {
	var body modeBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	v := "detect"
	if body.Enforce {
		v = "enforce"
	}
	if _, err := a.DB.Exec(
		`INSERT INTO config(key,value) VALUES('enforce_mode',?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, v); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
