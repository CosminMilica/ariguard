package ingest

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	maxTraceBytes      = 8 << 20
	traceExportDefault = 20_000
	traceExportMax     = 50_000
)

// Traces stores honeypot-captured syscall traces (F11 discovery). A honeypot runs its workload under
// strace; a sidecar parses each process into an attack-labeled trace (JSONL) and POSTs the batch
// here. The rule-generation loop pulls them (TracesExport) as a full-syscall corpus to mine new
// chains from — what the rule-matched-only audit stream cannot provide. Each line is deduped by a
// content hash so a sidecar restart re-posting is harmless.
func (h *Handler) Traces(w http.ResponseWriter, r *http.Request) {
	body := http.MaxBytesReader(w, r.Body, maxTraceBytes)
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	tx, err := h.DB.Begin()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	now := time.Now().UnixNano()
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var probe struct {
			Label  string `json:"label"`
			Source string `json:"source"`
		}
		if json.Unmarshal([]byte(line), &probe) != nil {
			continue // skip a malformed line, don't fail the batch
		}
		label := probe.Label
		if label == "" {
			label = "attack"
		}
		sum := sha256.Sum256([]byte(line))
		hash := hex.EncodeToString(sum[:])
		if _, err = tx.Exec(`INSERT OR IGNORE INTO honeypot_traces(ts_ns,label,source,hash,events) VALUES(?,?,?,?,?)`,
			now, label, probe.Source, hash, line); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		n++
	}
	if err = sc.Err(); err != nil {
		http.Error(w, "read: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err = tx.Commit(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("X-Traces-Accepted", strconv.Itoa(n))
	w.WriteHeader(http.StatusNoContent)
}

// TracesExport streams stored honeypot traces as JSONL (each row's original trace object) for the
// rule-generation loop to mine. Rows with id > ?since, oldest first, capped at ?limit.
func (h *Handler) TracesExport(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	limit := traceExportDefault
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = v
	}
	if limit > traceExportMax {
		limit = traceExportMax
	}
	rows, err := h.DB.Query(`SELECT events FROM honeypot_traces WHERE id > ? ORDER BY id ASC LIMIT ?`, since, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	w.Header().Set("Content-Type", "application/x-ndjson")
	for rows.Next() {
		var events string
		if err := rows.Scan(&events); err != nil {
			return
		}
		_, _ = w.Write([]byte(events + "\n"))
	}
}
