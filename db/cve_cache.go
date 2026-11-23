package db

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// CVE query payload cache (ephemeral) and per-CVE bare info store.

const (
	// CVECacheCapKeys bounds the query payload cache: at most this many
	// distinct queries keep payloads; the oldest keys are dropped beyond it.
	CVECacheCapKeys = 64

	// CVEInfoTTL is how long per-CVE bare info rows stay trusted. CVE
	// metadata is effectively immutable, so this can be long.
	CVEInfoTTL = 7 * 24 * time.Hour

	// CVEInfoCapRows bounds the per-CVE info table; the oldest rows are
	// dropped beyond it.
	CVEInfoCapRows = 5000
)

// CVECacheKey builds a stable cache key for a CVE source query. The version
// prefix invalidates stored payloads when the marshaled shape changes.
func CVECacheKey(vendor, product, version, ecosystem string) string {
	const sep = "\x1f" // unit separator: cannot appear in CLI arguments
	return "v1" + sep + strings.Join([]string{vendor, product, version, ecosystem}, sep)
}

// CVECacheGet returns the stored payload and creation time for a query and
// source. Freshness (TTL) is the caller's concern; ok is false on a miss.
func (d *DB) CVECacheGet(key, source string) (payload []byte, createdAt time.Time, ok bool, err error) {
	var p, created string
	scanErr := d.sql.QueryRow(
		"SELECT payload, created_at FROM cve_cache WHERE key = ? AND source = ?", key, source,
	).Scan(&p, &created)
	if scanErr == sql.ErrNoRows {
		return nil, time.Time{}, false, nil
	}
	if scanErr != nil {
		return nil, time.Time{}, false, fmt.Errorf("db: cve cache get: %w", scanErr)
	}
	when, err := time.Parse(time.RFC3339, created)
	if err != nil {
		// Corrupt stamp: treat as a miss rather than a fresh hit.
		return nil, time.Time{}, false, nil
	}
	return []byte(p), when, true, nil
}

// CVECacheStore upserts a query payload and then evicts: rows past the TTL
// are deleted, and if more than capKeys distinct queries remain, the oldest
// keys are dropped.
func (d *DB) CVECacheStore(key, source string, payload []byte, now time.Time, ttl time.Duration, capKeys int) error {
	if key == "" || source == "" {
		return fmt.Errorf("db: cve cache store: empty key or source")
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	if _, err := d.sql.Exec(`
		INSERT INTO cve_cache(key, source, payload, created_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(key, source) DO UPDATE SET
			payload = excluded.payload,
			created_at = excluded.created_at
	`, key, source, string(payload), now.UTC().Format(time.RFC3339)); err != nil {
		return fmt.Errorf("db: cve cache store: %w", err)
	}
	return d.cveCacheEvict(now, ttl, capKeys)
}

func (d *DB) cveCacheEvict(now time.Time, ttl time.Duration, capKeys int) error {
	cutoff := now.Add(-ttl).UTC().Format(time.RFC3339)
	if _, err := d.sql.Exec("DELETE FROM cve_cache WHERE created_at < ?", cutoff); err != nil {
		return fmt.Errorf("db: cve cache evict: %w", err)
	}
	var count int
	if err := d.sql.QueryRow("SELECT COUNT(DISTINCT key) FROM cve_cache").Scan(&count); err != nil {
		return fmt.Errorf("db: cve cache count: %w", err)
	}
	if excess := count - capKeys; excess > 0 {
		if _, err := d.sql.Exec(`
			DELETE FROM cve_cache WHERE key IN (
				SELECT key FROM cve_cache GROUP BY key ORDER BY MIN(created_at) ASC LIMIT ?
			)`, excess); err != nil {
			return fmt.Errorf("db: cve cache cap: %w", err)
		}
	}
	return nil
}

// CVEInfoRow is the bare, immutable info we keep about a single CVE.
type CVEInfoRow struct {
	ID      string
	Summary string
}

// CVEInfoStore upserts per-CVE bare info rows (filled lazily from any CVE
// source's results) and then evicts expired and over-cap rows. Enrichment
// columns (kev, epss, published) are never overwritten here.
func (d *DB) CVEInfoStore(rows []CVEInfoRow, now time.Time) error {
	if len(rows) == 0 {
		return nil
	}
	fetched := now.UTC().Format(time.RFC3339)

	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	tx, err := d.sql.Begin()
	if err != nil {
		return fmt.Errorf("db: begin: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO cves(id, published, summary, kev, epss, fetched_at) VALUES (?, '', ?, 0, NULL, ?)
		ON CONFLICT(id) DO UPDATE SET
			summary = excluded.summary,
			fetched_at = excluded.fetched_at
	`)
	if err != nil {
		return fmt.Errorf("db: prepare: %w", err)
	}
	defer stmt.Close()

	for _, r := range rows {
		if r.ID == "" {
			continue
		}
		if _, err := stmt.Exec(r.ID, r.Summary, fetched); err != nil {
			return fmt.Errorf("db: cve info store: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("db: cve info store: %w", err)
	}
	return d.cveInfoEvictLocked(now)
}

// cveInfoEvictLocked evicts expired and over-cap rows; the caller holds the
// write lock. RFC3339 UTC stamps compare correctly as strings.
func (d *DB) cveInfoEvictLocked(now time.Time) error {
	cutoff := now.Add(-CVEInfoTTL).UTC().Format(time.RFC3339)
	if _, err := d.sql.Exec("DELETE FROM cves WHERE fetched_at < ?", cutoff); err != nil {
		return fmt.Errorf("db: cve info evict: %w", err)
	}
	if _, err := d.sql.Exec(`
		DELETE FROM cves WHERE id NOT IN (
			SELECT id FROM cves ORDER BY fetched_at DESC LIMIT ?
		)`, CVEInfoCapRows); err != nil {
		return fmt.Errorf("db: cve info cap: %w", err)
	}
	return nil
}

// CVEInfoGet returns the stored bare info for a CVE id, if present and not
// expired.
func (d *DB) CVEInfoGet(id string) (summary string, ok bool, err error) {
	var s, fetched string
	scanErr := d.sql.QueryRow("SELECT summary, fetched_at FROM cves WHERE id = ?", id).Scan(&s, &fetched)
	if scanErr == sql.ErrNoRows {
		return "", false, nil
	}
	if scanErr != nil {
		return "", false, fmt.Errorf("db: cve info get: %w", scanErr)
	}
	when, err := time.Parse(time.RFC3339, fetched)
	if err != nil || time.Since(when) >= CVEInfoTTL {
		return "", false, nil
	}
	return s, true, nil
}
