package scrape

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/CosminMilica/ariguard/console/backend/store"
)

// TestScraperPruneHonorsRetention verifies the scraper's history prune honors the configured
// --retention instead of the old hardcoded 26h, while still flooring at the 24h UI window. (Tier 4)
func TestScraperPruneHonorsRetention(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now()
	ins := func(ageHours int) {
		ts := now.Add(-time.Duration(ageHours) * time.Hour).UnixMilli()
		if _, err := db.Exec(`INSERT INTO metric_samples(ts,node,events,kills,denies,audit_dropped) VALUES(?,?,0,0,0,0)`, ts, "n1"); err != nil {
			t.Fatal(err)
		}
	}
	ins(40) // 40h old: beyond the old 26h hardcode, within a 48h retention
	ins(1)  // recent

	count := func() int {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM metric_samples`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	s := New(db)
	s.Retention = 48 * time.Hour
	s.scrapeAll(context.Background())
	if n := count(); n != 2 {
		t.Fatalf("after 48h retention: %d rows, want 2 (40h row kept — retention honored, not 26h)", n)
	}

	// A retention below the 26h floor is clamped to the floor, which still prunes the 40h row.
	s.Retention = time.Hour
	s.scrapeAll(context.Background())
	if n := count(); n != 1 {
		t.Fatalf("after floored prune: %d rows, want 1 (only the recent row kept)", n)
	}
}
