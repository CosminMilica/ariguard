package api

import (
	"encoding/json"
	"net/http"
)

// learnNamespaces lists the learn-mode namespaces for the frontend.
func (a *API) learnNamespaces(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.Query(`SELECT namespace FROM learn_namespaces ORDER BY namespace`)
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

// learnNamespace opts a namespace into learn-mode: the agent emits full-syscall traces from its pods
// for novel-chain mining (F11). Agents pick it up on their next poll.
func (a *API) learnNamespace(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Namespace string `json:"namespace"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil || body.Namespace == "" {
		http.Error(w, "namespace is required", http.StatusBadRequest)
		return
	}
	if _, err := a.DB.Exec(`INSERT OR IGNORE INTO learn_namespaces(namespace) VALUES(?)`, body.Namespace); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// unlearnNamespace opts a namespace out of learn-mode (its pods stop emitting traces).
func (a *API) unlearnNamespace(w http.ResponseWriter, r *http.Request) {
	if _, err := a.DB.Exec(`DELETE FROM learn_namespaces WHERE namespace=?`, r.PathValue("ns")); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
