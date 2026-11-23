package db

import (
	"fmt"
	"time"
)

// POCRow is a stored POC record. Raw keeps the untouched value from the
// source (however badly formatted) so records can be re-normalized without
// re-fetching.
type POCRow struct {
	CVE      string
	Source   string
	URL      string
	Owner    string
	PushedAt string
	Raw      string
}

// StorePOCs upserts rows for the given source, stamping fetched_at with now.
// Existing rows for the same (cve, source, url) are refreshed.
func (d *DB) StorePOCs(source string, now time.Time, rows []POCRow) error {
	if len(rows) == 0 {
		return nil
	}
	if source == "" {
		return fmt.Errorf("db: empty source")
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
		INSERT INTO pocs(cve_id, source, url, owner, pushed_at, raw, fetched_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cve_id, source, url) DO UPDATE SET
			owner = excluded.owner,
			pushed_at = excluded.pushed_at,
			raw = excluded.raw,
			fetched_at = excluded.fetched_at
	`)
	if err != nil {
		return fmt.Errorf("db: prepare: %w", err)
	}
	defer stmt.Close()

	for _, r := range rows {
		if r.CVE == "" || r.URL == "" {
			continue
		}
		if _, err := stmt.Exec(r.CVE, source, r.URL, r.Owner, r.PushedAt, r.Raw, fetched); err != nil {
			return fmt.Errorf("db: insert poc: %w", err)
		}
	}
	return tx.Commit()
}

// CachedPOCs returns the stored rows for cve+source if they were fetched
// within maxAge of now. ok is false when nothing fresh exists (or when rows
// were stored by a different, older fetch).
func (d *DB) CachedPOCs(cve, source string, maxAge time.Duration, now time.Time) ([]POCRow, bool, error) {
	rows, err := d.queryPOCs(cve, source)
	if err != nil {
		return nil, false, err
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	freshSince := now.Add(-maxAge).UTC()
	for _, r := range rows {
		if r.fetchedAt.After(freshSince) {
			return toPOCRows(rows), true, nil
		}
	}
	return nil, false, nil
}

// storedPOC is a row as read from the database, including the fetch time
// needed for TTL checks.
type storedPOC struct {
	row       POCRow
	fetchedAt time.Time
}

func (d *DB) queryPOCs(cve, source string) ([]storedPOC, error) {
	rows, err := d.sql.Query(`
		SELECT url, owner, pushed_at, raw, fetched_at
		FROM pocs
		WHERE cve_id = ? AND source = ?
		ORDER BY url
	`, cve, source)
	if err != nil {
		return nil, fmt.Errorf("db: query pocs: %w", err)
	}
	defer rows.Close()

	var out []storedPOC
	for rows.Next() {
		var (
			u, owner, pushed, raw, fetched string
		)
		if err := rows.Scan(&u, &owner, &pushed, &raw, &fetched); err != nil {
			return nil, fmt.Errorf("db: scan poc: %w", err)
		}
		when, err := time.Parse(time.RFC3339, fetched)
		if err != nil {
			// Unparseable fetch stamp: treat as stale rather than fresh.
			continue
		}
		out = append(out, storedPOC{row: POCRow{CVE: cve, Source: source, URL: u, Owner: owner, PushedAt: pushed, Raw: raw}, fetchedAt: when})
	}
	return out, rows.Err()
}

func toPOCRows(stored []storedPOC) []POCRow {
	out := make([]POCRow, 0, len(stored))
	for _, s := range stored {
		out = append(out, s.row)
	}
	return out
}

// IndexRev returns the stored upstream revision of a bulk-index source, if
// one has ever been recorded.
func (d *DB) IndexRev(source string) (string, bool) {
	var rev string
	err := d.sql.QueryRow("SELECT rev FROM indexes WHERE source = ?", source).Scan(&rev)
	if err != nil {
		return "", false
	}
	return rev, true
}

// SetIndexRev records the upstream revision and fetch time of a bulk-index
// source, so a rebuild can be skipped while the revision is unchanged.
func (d *DB) SetIndexRev(source, rev string, now time.Time) error {
	if source == "" {
		return fmt.Errorf("db: empty source")
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.sql.Exec(`
		INSERT INTO indexes(source, rev, fetched_at) VALUES (?, ?, ?)
		ON CONFLICT(source) DO UPDATE SET
			rev = excluded.rev,
			fetched_at = excluded.fetched_at
	`, source, rev, now.UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("db: set index rev: %w", err)
	}
	return nil
}

// IndexFetchedAt returns when the bulk-index source's snapshot was last
// refreshed, if ever.
func (d *DB) IndexFetchedAt(source string) (time.Time, bool) {
	var fetched string
	err := d.sql.QueryRow("SELECT fetched_at FROM indexes WHERE source = ?", source).Scan(&fetched)
	if err != nil {
		return time.Time{}, false
	}
	when, err := time.Parse(time.RFC3339, fetched)
	if err != nil {
		return time.Time{}, false
	}
	return when, true
}

// WipeIndex deletes a bulk-index source's snapshot revision and all of its
// CVE-to-POC rows, forcing a full rebuild on the next use.
func (d *DB) WipeIndex(source string) error {
	if source == "" {
		return fmt.Errorf("db: empty source")
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	for _, stmt := range []string{
		"DELETE FROM indexes WHERE source = ?",
		"DELETE FROM index_pocs WHERE source = ?",
	} {
		if _, err := d.sql.Exec(stmt, source); err != nil {
			return fmt.Errorf("db: wipe index: %w", err)
		}
	}
	return nil
}

// IndexPOCRow is one CVE-to-POC link extracted from a bulk-index snapshot.
type IndexPOCRow struct {
	CVE      string
	URL      string
	Detail   string
	PushedAt string
}

// StoreIndexPOCs replaces all rows of a bulk-index source with the given
// snapshot rows. It must be called with a complete index, never incrementally.
func (d *DB) StoreIndexPOCs(source string, rows []IndexPOCRow) error {
	if source == "" {
		return fmt.Errorf("db: empty source")
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	tx, err := d.sql.Begin()
	if err != nil {
		return fmt.Errorf("db: begin: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM index_pocs WHERE source = ?", source); err != nil {
		return fmt.Errorf("db: clear index: %w", err)
	}
	stmt, err := tx.Prepare(`
		INSERT INTO index_pocs(source, cve_id, url, detail, pushed_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(source, cve_id, url) DO NOTHING
	`)
	if err != nil {
		return fmt.Errorf("db: prepare: %w", err)
	}
	defer stmt.Close()

	for _, r := range rows {
		if r.CVE == "" || r.URL == "" {
			continue
		}
		if _, err := stmt.Exec(source, r.CVE, r.URL, r.Detail, r.PushedAt); err != nil {
			return fmt.Errorf("db: insert index poc: %w", err)
		}
	}
	return tx.Commit()
}

// IndexPOCs returns the CVE-to-POC links recorded for cve by a bulk-index
// source. Missing rows are an empty, non-error result.
func (d *DB) IndexPOCs(cve, source string) ([]IndexPOCRow, error) {
	rows, err := d.sql.Query(`
		SELECT url, detail, pushed_at
		FROM index_pocs
		WHERE cve_id = ? AND source = ?
		ORDER BY url
	`, cve, source)
	if err != nil {
		return nil, fmt.Errorf("db: query index pocs: %w", err)
	}
	defer rows.Close()

	var out []IndexPOCRow
	for rows.Next() {
		var r IndexPOCRow
		if err := rows.Scan(&r.URL, &r.Detail, &r.PushedAt); err != nil {
			return nil, fmt.Errorf("db: scan index poc: %w", err)
		}
		r.CVE = cve
		out = append(out, r)
	}
	return out, rows.Err()
}
