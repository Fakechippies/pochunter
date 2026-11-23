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

// AppVersion is recorded with the cache so derived data can be invalidated
// when the binary is replaced by a release. Overridable at build time:
//
//	go build -ldflags "-X github.com/Fakechippies/pochunter/db.AppVersion=v1.2.3"
var AppVersion = "dev"

// DB wraps a SQLite database handle. modernc.org/sqlite supports a single
// writer, so writes are serialized through a mutex; reads are concurrent.
type DB struct {
	sql        *sql.DB
	writeMu    sync.Mutex
	appVersion string

	// dictionary memoization (CPEEntriesCached)
	dictOnce    sync.Once
	dictEntries []CPEEntry
	dictErr     error
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

-- Query-level cache of CVE source results: one JSON payload per
-- (query key, source). Ephemeral by design — short TTL, evicted on write.
CREATE TABLE IF NOT EXISTS cve_cache(
	key        TEXT NOT NULL,
	source     TEXT NOT NULL,
	payload    TEXT NOT NULL,
	created_at TEXT NOT NULL,
	UNIQUE (key, source)
);

-- CVE-to-POC links extracted from a bulk-index snapshot, one row per link.
CREATE TABLE IF NOT EXISTS index_pocs(
	source    TEXT NOT NULL,
	cve_id    TEXT NOT NULL,
	url       TEXT NOT NULL,
	detail    TEXT NOT NULL DEFAULT '',
	pushed_at TEXT NOT NULL DEFAULT '',
	UNIQUE (source, cve_id, url)
);

-- Small key/value store for maintenance state (schema version, the app
-- version that built the caches, ...).
CREATE TABLE IF NOT EXISTS meta(
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

-- CPE dictionary, deduplicated to one row per product prefix. Built from
-- the NVD CPE API (or its mirror); powers query-to-CPE resolution.
CREATE TABLE IF NOT EXISTS cpes(
	prefix   TEXT PRIMARY KEY,
	vendor   TEXT NOT NULL,
	product  TEXT NOT NULL,
	title    TEXT NOT NULL DEFAULT '',
	versions INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cpes_product ON cpes(product);
`

// Open creates (if necessary) and opens the cache database at path, applies
// pragmas and ensures the schema exists. The parent directory is created too.
func Open(path string) (*DB, error) {
	return openWithVersion(path, AppVersion)
}

func openWithVersion(path, appVersion string) (*DB, error) {
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
	if err := migrateSchema(sqlDB); err != nil {
		sqlDB.Close()
		return nil, err
	}
	d := &DB{sql: sqlDB, appVersion: appVersion}
	if err := d.refreshMaintenanceState(); err != nil {
		sqlDB.Close()
		return nil, err
	}
	return d, nil
}

// schemaVersion identifies the cached-data layout. Bump it when a schema
// change invalidates derived data; bulk indexes are wiped and rebuilt on
// mismatch.
const schemaVersion = "1"

// migrateSchema applies idempotent migrations for databases created by older
// versions of this package.
func migrateSchema(sqlDB *sql.DB) error {
	rows, err := sqlDB.Query("PRAGMA table_info(cves)")
	if err != nil {
		return fmt.Errorf("db: introspect cves: %w", err)
	}
	defer rows.Close()
	hasFetchedAt := false
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			return fmt.Errorf("db: introspect cves: %w", err)
		}
		if name == "fetched_at" {
			hasFetchedAt = true
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("db: introspect cves: %w", err)
	}
	if !hasFetchedAt {
		if _, err := sqlDB.Exec("ALTER TABLE cves ADD COLUMN fetched_at TEXT NOT NULL DEFAULT ''"); err != nil {
			return fmt.Errorf("db: migrate cves.fetched_at: %w", err)
		}
	}
	return nil
}

// refreshMaintenanceState wipes derived data when it was built by a
// different schema or a different app version (a release), so caches are
// rebuilt from upstream on the next use.
func (d *DB) refreshMaintenanceState() error {
	stored, ok, err := d.meta("schema_version")
	if err != nil {
		return err
	}
	if !ok {
		// Fresh database: record current state.
		return d.exec(
			"INSERT INTO meta(key, value) VALUES ('schema_version', ?), ('built_with', ?)",
			schemaVersion, d.appVersion,
		)
	}

	wipe := false
	if stored != schemaVersion {
		wipe = true
	}
	if !wipe {
		if built, ok, err := d.meta("built_with"); err == nil && ok && built != d.appVersion {
			wipe = true
		}
	}
	if wipe {
		if err := d.exec("DELETE FROM indexes; DELETE FROM index_pocs; DELETE FROM cve_cache"); err != nil {
			return err
		}
	}
	return d.exec(
		"INSERT INTO meta(key, value) VALUES ('schema_version', ?), ('built_with', ?)"+
			" ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		schemaVersion, d.appVersion,
	)
}

func (d *DB) meta(key string) (string, bool, error) {
	var value string
	err := d.sql.QueryRow("SELECT value FROM meta WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("db: meta %s: %w", key, err)
	}
	return value, true, nil
}

// Close closes the database handle.
func (d *DB) Close() error {
	if d == nil || d.sql == nil {
		return nil
	}
	return d.sql.Close()
}

// Exec runs a write statement under the write mutex. Exposed for maintenance
// operations and tests.
func (d *DB) Exec(query string, args ...any) error {
	return d.exec(query, args...)
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
