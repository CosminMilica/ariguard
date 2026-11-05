package store

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// backupGlob matches the snapshot files Backup writes, for pruning.
const backupGlob = "ariguard-console-*.db"

// Backup writes a consistent snapshot of the database into dir via SQLite's VACUUM INTO (safe while
// the console is serving), then keeps only the newest `keep` snapshots. Returns the snapshot path.
func Backup(db *sql.DB, dir string, keep int) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("backup dir: %w", err)
	}
	// microsecond precision so rapid successive snapshots get distinct, time-ordered names (VACUUM
	// INTO refuses to overwrite an existing file).
	path := filepath.Join(dir, fmt.Sprintf("ariguard-console-%s.db", time.Now().UTC().Format("20060102T150405.000000Z")))
	// VACUUM INTO refuses to overwrite, so the timestamped name must not already exist.
	if _, err := db.Exec(`VACUUM INTO ?`, path); err != nil {
		return "", fmt.Errorf("vacuum into %s: %w", path, err)
	}
	if err := pruneBackups(dir, keep); err != nil {
		log.Printf("backup: prune old snapshots: %v", err)
	}
	return path, nil
}

// pruneBackups keeps the newest `keep` snapshots in dir (by filename, which is time-ordered), and
// deletes the rest. keep <= 0 keeps everything.
func pruneBackups(dir string, keep int) error {
	if keep <= 0 {
		return nil
	}
	matches, err := filepath.Glob(filepath.Join(dir, backupGlob))
	if err != nil {
		return err
	}
	if len(matches) <= keep {
		return nil
	}
	sort.Strings(matches) // timestamped names sort oldest-first
	for _, old := range matches[:len(matches)-keep] {
		if err := os.Remove(old); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// RunBackup snapshots the database every interval until ctx is done, keeping the newest `keep`.
func RunBackup(ctx context.Context, db *sql.DB, dir string, interval time.Duration, keep int) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if path, err := Backup(db, dir, keep); err != nil {
			log.Printf("backup: %v", err)
		} else {
			log.Printf("backup: wrote %s", path)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
