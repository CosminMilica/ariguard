package store

import (
	"path/filepath"
	"testing"
)

func TestBackupSnapshotsAndPrunes(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	mustExec(t, db, `INSERT INTO mutes(pod) VALUES('p1')`)

	dir := t.TempDir()
	path, err := Backup(db, dir, 7)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}

	// the snapshot is a valid, complete database (the row is present)
	snap, err := Open(path)
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	defer snap.Close()
	if n := count(t, snap, "mutes"); n != 1 {
		t.Fatalf("snapshot mutes = %d, want 1", n)
	}

	// keep=2 retains only the two newest of several snapshots
	for i := 0; i < 4; i++ {
		if _, err := Backup(db, dir, 2); err != nil {
			t.Fatalf("backup %d: %v", i, err)
		}
	}
	matches, _ := filepath.Glob(filepath.Join(dir, backupGlob))
	if len(matches) != 2 {
		t.Fatalf("after keep=2, found %d snapshots, want 2: %v", len(matches), matches)
	}
}
