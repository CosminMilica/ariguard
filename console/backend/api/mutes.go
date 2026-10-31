package api

import (
	"encoding/json"
	"net/http"
)

func (a *API) mute(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Pod string `json:"pod"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil || body.Pod == "" {
		http.Error(w, "pod is required", http.StatusBadRequest)
		return
	}
	if _, err := a.DB.Exec(`INSERT OR IGNORE INTO mutes(pod) VALUES(?)`, body.Pod); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) unmute(w http.ResponseWriter, r *http.Request) {
	if _, err := a.DB.Exec(`DELETE FROM mutes WHERE pod=?`, r.PathValue("pod")); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
