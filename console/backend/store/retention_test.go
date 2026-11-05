package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func count(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestPruneDropsOldHistoryKeepsRecentAndState(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now()
	oldNS := now.Add(-48 * time.Hour).UnixNano()
	newNS := now.Add(-1 * time.Hour).UnixNano()
	oldMS := now.Add(-48 * time.Hour).UnixMilli()
	newMS := now.Add(-1 * time.Hour).UnixMilli()

	mustExec(t, db, `INSERT INTO audit_events(ts_ns,pod,rule,to_state) VALUES(?,?,?,?)`, oldNS, "p", "r", "compromised")
	mustExec(t, db, `INSERT INTO audit_events(ts_ns,pod,rule,to_state) VALUES(?,?,?,?)`, newNS, "p", "r", "compromised")
	mustExec(t, db, `INSERT INTO honeypot_traces(ts_ns,hash,events) VALUES(?,?,?)`, oldNS, "h1", "[]")
	mustExec(t, db, `INSERT INTO honeypot_traces(ts_ns,hash,events) VALUES(?,?,?)`, newNS, "h2", "[]")
	mustExec(t, db, `INSERT INTO metric_samples(ts,node) VALUES(?,?)`, oldMS, "n")
	mustExec(t, db, `INSERT INTO metric_samples(ts,node) VALUES(?,?)`, newMS, "n")
	// operational state must survive pruning regardless of age
	mustExec(t, db, `INSERT INTO mutes(pod) VALUES('keep')`)
	mustExec(t, db, `INSERT INTO nodes(node) VALUES('n1')`)

	n, err := Prune(db, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("pruned %d rows, want 3 (one old per time-series table)", n)
	}
	for _, c := range []struct {
		table string
		want  int
	}{
		{"audit_events", 1}, {"honeypot_traces", 1}, {"metric_samples", 1}, {"mutes", 1}, {"nodes", 1},
	} {
		if got := count(t, db, c.table); got != c.want {
			t.Fatalf("%s has %d rows, want %d", c.table, got, c.want)
		}
	}
}
