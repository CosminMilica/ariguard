package ingest

import (
	"net/http"
	"time"
)

type quarantineEvent struct {
	Node      string `json:"node"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Rule      string `json:"rule"`
	Mode      string `json:"mode"`
	TsNS      int64  `json:"ts_ns"`
}

// Quarantine records that the agent isolated a workload, keeping the latest
// quarantine per (node, namespace, pod).
func (h *Handler) Quarantine(w http.ResponseWriter, r *http.Request) {
	var e quarantineEvent
	if !decode(w, r, &e) {
		return
	}
	if e.Node == "" || e.Pod == "" {
		http.Error(w, "node and pod are required", http.StatusBadRequest)
		return
	}
	if e.TsNS < minWallNS {
		e.TsNS = time.Now().UnixNano()
	}
	_, err := h.DB.Exec(`INSERT INTO quarantine(node,namespace,pod,rule,mode,ts_ns)
		VALUES(?,?,?,?,?,?)
		ON CONFLICT(node,namespace,pod) DO UPDATE SET rule=excluded.rule, mode=excluded.mode, ts_ns=excluded.ts_ns`,
		e.Node, e.Namespace, e.Pod, e.Rule, e.Mode, e.TsNS)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
