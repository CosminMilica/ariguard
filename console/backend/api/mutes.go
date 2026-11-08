package api

import (
	"encoding/json"
	"net/http"
)

// Mutes are keyed by "namespace/pod" (C4): two pods with the same name in different namespaces must
// mute independently. The value lives in the existing mutes.pod column (no schema change); agents and
// the telemetry join use the same composite key.
func muteKey(namespace, pod string) string { return namespace + "/" + pod }

func (a *API) mute(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Namespace string `json:"namespace"`
		Pod       string `json:"pod"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil || body.Namespace == "" || body.Pod == "" {
		http.Error(w, "namespace and pod are required", http.StatusBadRequest)
		return
	}
	if _, err := a.DB.Exec(`INSERT OR IGNORE INTO mutes(pod) VALUES(?)`, muteKey(body.Namespace, body.Pod)); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) unmute(w http.ResponseWriter, r *http.Request) {
	if _, err := a.DB.Exec(`DELETE FROM mutes WHERE pod=?`, muteKey(r.PathValue("namespace"), r.PathValue("pod"))); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
