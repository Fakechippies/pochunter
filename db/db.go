// Package db provides a local SQLite-backed store for CVE and POC data
// gathered from heterogeneous sources, plus normalization helpers that clean
// up badly formatted records before they are stored. Raw values are kept
// alongside normalized ones so records can be re-derived without re-fetching.
package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

// DB wraps a SQLite database handle. modernc.org/sqlite supports a single
// writer, so writes are serialized through a mutex; reads are concurrent.
type DB struct {
	sql     *sql.DB
	writeMu sync.Mutex
}

const schema = `
CREATE TABLE IF NOT EXISTS pocs(
	cve_id     TEXT NOT NULL,
	source     TEXT NOT NULL,
	url        TEXT NOT NULL,
	owner      TEXT NOT NULL DEFAULT '',
	pushed_at  TEXT NOT NULL DEFAULT '',
	raw        TEXT NOT NULL DEFAULT '',
	fetched_at TEXT NOT NULL,
	UNIQUE (cve_id, source, url)
);
CREATE INDEX IF NOT EXISTS idx_pocs_lookup ON pocs(cve_id, source, fetched_at);

CREATE TABLE IF NOT EXISTS cves(
	id        TEXT PRIMARY KEY,
	published TEXT NOT NULL,
	summary   TEXT NOT NULL DEFAULT '',
	kev       INTEGER NOT NULL DEFAULT 0,
	epss      REAL
);

-- One row per bulk-index snapshot (e.g. ExploitDB CSV revision, Metasploit
-- metadata JSON rev). Lets bulk sources skip re-downloads when the upstream
-- revision is unchanged.
CREATE TABLE IF NOT EXISTS indexes(
	source     TEXT NOT NULL,
	rev        TEXT NOT NULL,
	fetched_at TEXT NOT NULL,
	UNIQUE (source)
);

-- CVE-to-POC links extracted from a bulk-index snapshot, one row per link.
CREATE TABLE IF NOT EXISTS index_pocs(
	source TEXT NOT NULL,
	cve_id TEXT NOT NULL,
	url    TEXT NOT NULL,
	detail TEXT NOT NULL DEFAULT '',
	UNIQUE (source, cve_id, url)
);
`

// Open creates (if necessary) and opens the cache database at path, applies
// pragmas and ensures the schema exists. The parent directory is created too.
func Open(path string) (*DB, error) {
	if path == "" {
		return nil, fmt.Errorf("db: empty database path")
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("db: create directory: %w", err)
		}
	}

	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}
	// WAL keeps reads concurrent; a generous busy timeout plus the write
	// mutex make concurrent goroutines safe. Hard cap to keep file
	// descriptors and lock contention sane.
	sqlDB.SetMaxOpenConns(8)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
	} {
		if _, err := sqlDB.Exec(pragma); err != nil {
			sqlDB.Close()
			return nil, fmt.Errorf("db: %s: %w", pragma, err)
		}
	}
	if _, err := sqlDB.Exec(schema); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("db: schema: %w", err)
	}
	return &DB{sql: sqlDB}, nil
}

// Close closes the database handle.
func (d *DB) Close() error {
	if d == nil || d.sql == nil {
		return nil
	}
	return d.sql.Close()
}

// exec runs a statement under the write mutex.
func (d *DB) exec(query string, args ...any) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if _, err := d.sql.Exec(query, args...); err != nil {
		return fmt.Errorf("db: %w", err)
	}
	return nil
}
