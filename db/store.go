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
