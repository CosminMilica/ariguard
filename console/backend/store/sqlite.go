// Package store opens the SQLite database and applies the schema.
package store

import (
	"database/sql"
	_ "embed"
	"fmt"
	"net/url"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

// migrations add columns to tables that may already exist with data. Each runs
// after the schema is applied; "duplicate column" errors are ignored so existing
// databases migrate in place without dropping rows.
var migrations = []string{
	`ALTER TABLE audit_events ADD COLUMN image TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE audit_events ADD COLUMN image_id TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE audit_events ADD COLUMN ppid INTEGER NOT NULL DEFAULT 0`,
}

// Open opens (creating if needed) the SQLite file at path and applies the schema.
func Open(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", url.PathEscape(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// A single connection avoids SQLITE_BUSY between the scraper, ingest and API.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			db.Close()
			return nil, fmt.Errorf("apply migration %q: %w", m, err)
		}
	}
	return db, nil
}
