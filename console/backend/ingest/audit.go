package ingest

import (
	"net/http"
	"time"
)

type auditEvent struct {
	TsNS      int64  `json:"ts_ns"`
	CgroupID  int64  `json:"cgroup_id"`
	PID       int64  `json:"pid"`
	Ppid      int64  `json:"ppid"`
	Comm      string `json:"comm"`
	Hook      string `json:"hook"`
	Rule      string `json:"rule"`
	Event     string `json:"event"`
	From      string `json:"from"`
	To        string `json:"to"`
	Action    string `json:"action"`
	Enforced  bool   `json:"enforced"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
	Image     string `json:"image"`
	ImageID   string `json:"image_id"`
	Node      string `json:"node"`
}

// minWallNS is the earliest plausible wall-clock timestamp (2001-09-09). Agent
// timestamps below it are treated as monotonic and replaced by the receive time.
const minWallNS = 1_000_000_000_000_000_000

// Audit stores a batch of audit events and refreshes the current workload state.
func (h *Handler) Audit(w http.ResponseWriter, r *http.Request) {
	var events []auditEvent
	if !decode(w, r, &events) {
		return
	}
	tx, err := h.DB.Begin()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	nowNS := time.Now().UnixNano()
	nowMS := time.Now().UnixMilli()
	for _, e := range events {
		if e.TsNS < minWallNS {
			e.TsNS = nowNS
		}
		enforced := 0
		if e.Enforced {
			enforced = 1
		}
		if _, err = tx.Exec(`INSERT INTO audit_events(ts_ns,node,pod,namespace,comm,rule,event,from_state,to_state,action,enforced,cgroup_id,pid,ppid,hook,image,image_id)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			e.TsNS, e.Node, e.Pod, e.Namespace, e.Comm, e.Rule, e.Event, e.From, e.To, e.Action, enforced, e.CgroupID, e.PID, e.Ppid, e.Hook, e.Image, e.ImageID); err != nil {
			break
		}
		if e.Pod == "" || e.Rule == "" || e.To == "" {
			continue
		}
		if _, err = tx.Exec(`INSERT INTO workloads(node,pod,namespace,comm,rule,state,action,updated)
			VALUES(?,?,?,?,?,?,?,?)
			ON CONFLICT(node,pod,rule) DO UPDATE SET namespace=excluded.namespace, comm=excluded.comm,
			  state=excluded.state, action=excluded.action, updated=excluded.updated`,
			e.Node, e.Pod, e.Namespace, e.Comm, e.Rule, e.To, e.Action, nowMS); err != nil {
			break
		}
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
