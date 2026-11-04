package api

import "net/http"

type policyRow struct {
	Version string `json:"version"`
	Bytes   int    `json:"bytes"`
	TsNS    int64  `json:"ts_ns"`
	Present bool   `json:"present"`
}

// policy reports the control plane's current pushed bundle (F7): its version, size and push time,
// for the console to show what the fleet is converging on. Present is false when none is pushed.
func (a *API) policy(w http.ResponseWriter, r *http.Request) {
	var out policyRow
	var bundle []byte
	err := a.DB.QueryRow(`SELECT version, bundle, ts_ns FROM policy WHERE id=1`).Scan(&out.Version, &bundle, &out.TsNS)
	if err == nil {
		out.Present = true
		out.Bytes = len(bundle)
	}
	writeJSON(w, out)
}
