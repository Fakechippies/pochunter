package db

import (
	"fmt"
	"sync"
	"time"
)

// CPE dictionary storage: one row per product prefix (part:vendor:product),
// deduplicated from the NVD CPE API. The dictionary powers query-to-CPE
// resolution for NVD cpeName searches.

// CPEEntry is one deduplicated dictionary row.
type CPEEntry struct {
	Prefix   string // cpe:2.3:part:vendor:product (no version component)
	Vendor   string
	Product  string
	Title    string
	Versions int
}

// StoreCPEs replaces the whole dictionary with the given entries. It must be
// called with a complete dictionary, never incrementally.
func (d *DB) StoreCPEs(entries []CPEEntry) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	tx, err := d.sql.Begin()
	if err != nil {
		return fmt.Errorf("db: begin: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM cpes"); err != nil {
		return fmt.Errorf("db: clear cpes: %w", err)
	}
	stmt, err := tx.Prepare(`
		INSERT INTO cpes(prefix, vendor, product, title, versions)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(prefix) DO NOTHING
	`)
	if err != nil {
		return fmt.Errorf("db: prepare: %w", err)
	}
	defer stmt.Close()

	for _, e := range entries {
		if e.Prefix == "" || e.Product == "" {
			continue
		}
		if _, err := stmt.Exec(e.Prefix, e.Vendor, e.Product, e.Title, e.Versions); err != nil {
			return fmt.Errorf("db: insert cpe: %w", err)
		}
	}
	return tx.Commit()
}

// CPECount returns the number of stored dictionary rows.
func (d *DB) CPECount() (int, error) {
	var n int
	err := d.sql.QueryRow("SELECT COUNT(*) FROM cpes").Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("db: cpe count: %w", err)
	}
	return n, nil
}

// cpeDictCache memoizes the in-memory dictionary for the process lifetime.
type cpeDictCache struct {
	once    sync.Once
	entries []CPEEntry
	err     error
}

// CPEEntriesCached loads the dictionary into memory once per process
// (scoring scans it linearly, so repeated queries must not re-query sqlite).
func (d *DB) CPEEntriesCached() ([]CPEEntry, error) {
	d.dictOnce.Do(func() {
		rows, err := d.sql.Query("SELECT prefix, vendor, product, title, versions FROM cpes")
		if err != nil {
			d.dictErr = fmt.Errorf("db: query cpes: %w", err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var e CPEEntry
			if err := rows.Scan(&e.Prefix, &e.Vendor, &e.Product, &e.Title, &e.Versions); err != nil {
				d.dictErr = fmt.Errorf("db: scan cpe: %w", err)
				return
			}
			d.dictEntries = append(d.dictEntries, e)
		}
		d.dictErr = rows.Err()
	})
	return d.dictEntries, d.dictErr
}

// CPEStale reports whether the stored dictionary needs a rebuild (older than
// the given age, or absent).
func (d *DB) CPEStale(maxAge time.Duration) bool {
	fetchedAt, ok := d.IndexFetchedAt("cpes")
	if !ok {
		return true
	}
	return time.Since(fetchedAt) >= maxAge
}

// CPEMarkRefreshed stamps the dictionary as freshly built.
func (d *DB) CPEMarkRefreshed(now time.Time) error {
	return d.SetIndexRev("cpes", "api", now)
}
