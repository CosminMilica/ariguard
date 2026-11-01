// Package ingest implements the endpoints agents push data to.
package ingest

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"
)

type Handler struct{ DB *sql.DB }

// Routes registers the ingest endpoints on mux.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/register", h.Register)
	mux.HandleFunc("POST /api/v1/audit", h.Audit)
}

type registerReq struct {
	Node           string `json:"node"`
	Kernel         string `json:"kernel"`
	Enforce        bool   `json:"enforce"`
	HooksAttached  int    `json:"hooks_attached"`
	HooksTotal     int    `json:"hooks_total"`
	AuditRingBytes int64  `json:"audit_ring_bytes"`
	MetricsAddr    string `json:"metrics_addr"`
	Bundle         struct {
		Rules []struct {
			Name           string           `json:"name"`
			Scope          string           `json:"scope"`
			NumStates      int              `json:"num_states"`
			WindowNS       int64            `json:"window_ns"`
			TerminalAction string           `json:"terminal_action"`
			States         []string         `json:"states"`
			Events         []string         `json:"events"`
			TerminalFrom   int              `json:"terminal_from"`
			Transitions    []ruleTransition `json:"transitions"`
		} `json:"rules"`
	} `json:"bundle"`
	TsNS int64 `json:"ts_ns"`
}

// ruleTransition is one edge of a rule's state machine.
type ruleTransition struct {
	From     string   `json:"from"`
	Event    string   `json:"event"`
	To       string   `json:"to"`
	Action   string   `json:"action"`
	Syscalls []string `json:"syscalls"`
}

// ruleDetail is the full state machine stored as a JSON blob in rules.detail.
type ruleDetail struct {
	States       []string         `json:"states"`
	Events       []string         `json:"events"`
	TerminalFrom int              `json:"terminal_from"`
	Transitions  []ruleTransition `json:"transitions"`
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// Register upserts the node and replaces its rule set.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerReq
	if !decode(w, r, &req) {
		return
	}
	if req.Node == "" {
		http.Error(w, "node is required", http.StatusBadRequest)
		return
	}
	tx, err := h.DB.Begin()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	enforce := 0
	if req.Enforce {
		enforce = 1
	}
	_, err = tx.Exec(`INSERT INTO nodes(node,kernel,enforce,hooks_attached,hooks_total,audit_ring_bytes,metrics_addr,last_seen)
		VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(node) DO UPDATE SET kernel=excluded.kernel, enforce=excluded.enforce,
		  hooks_attached=excluded.hooks_attached, hooks_total=excluded.hooks_total,
		  audit_ring_bytes=excluded.audit_ring_bytes, metrics_addr=excluded.metrics_addr,
		  last_seen=excluded.last_seen`,
		req.Node, req.Kernel, enforce, req.HooksAttached, req.HooksTotal, req.AuditRingBytes,
		req.MetricsAddr, time.Now().UnixMilli())
	if err == nil {
		_, err = tx.Exec(`DELETE FROM rules WHERE node=?`, req.Node)
	}
	for _, ru := range req.Bundle.Rules {
		if err != nil {
			break
		}
		var detail []byte
		detail, err = json.Marshal(ruleDetail{
			States:       ru.States,
			Events:       ru.Events,
			TerminalFrom: ru.TerminalFrom,
			Transitions:  ru.Transitions,
		})
		if err != nil {
			break
		}
		_, err = tx.Exec(`INSERT OR REPLACE INTO rules(node,name,scope,num_states,window_ns,terminal_action,detail) VALUES(?,?,?,?,?,?,?)`,
			req.Node, ru.Name, ru.Scope, ru.NumStates, ru.WindowNS, ru.TerminalAction, string(detail))
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
