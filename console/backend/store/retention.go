package store

import (
	"context"
	"database/sql"
	"log"
	"time"
)

// Prune deletes time-series rows older than maxAge so the SQLite database does not grow without
// bound on a long-running console. It touches only append-only history (audit events, metric
// samples, honeypot traces); operational state — nodes, rules, mutes, quarantine, current workload
// states and the policy bundle — is kept regardless of age.
func Prune(db *sql.DB, maxAge time.Duration) (int64, error) {
	now := time.Now()
	cutoffNS := now.Add(-maxAge).UnixNano()
	cutoffMS := now.Add(-maxAge).UnixMilli()
	jobs := []struct {
		query string
		arg   int64
	}{
		{"DELETE FROM audit_events WHERE ts_ns < ?", cutoffNS},
		{"DELETE FROM honeypot_traces WHERE ts_ns < ?", cutoffNS},
		{"DELETE FROM metric_samples WHERE ts < ?", cutoffMS},
	}
	var total int64
	for _, j := range jobs {
		res, err := db.Exec(j.query, j.arg)
		if err != nil {
			return total, err
		}
		if n, err := res.RowsAffected(); err == nil {
			total += n
		}
	}
	return total, nil
}

// RunRetention prunes once on start and then every interval until ctx is cancelled. A maxAge of 0
// disables it (the caller should not start the loop in that case).
func RunRetention(ctx context.Context, db *sql.DB, interval, maxAge time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if n, err := Prune(db, maxAge); err != nil {
			log.Printf("retention: prune: %v", err)
		} else if n > 0 {
			log.Printf("retention: pruned %d rows older than %s", n, maxAge)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
