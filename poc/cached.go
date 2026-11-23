package poc

import (
	"context"
	"time"

	"github.com/Fakechippies/POC-Hunter/db"
)

// CachedSource wraps a Source with SQLite-backed caching. Findings are
// normalized (canonical URL, owner, timestamps) before being stored; the raw
// value is kept in the database so records can be re-derived later.
//
// A nil DB or a non-positive TTL disables caching and queries pass straight
// through to the wrapped source.
type CachedSource struct {
	Inner Source
	DB    *db.DB
	TTL   time.Duration
}

func (c CachedSource) Name() string { return c.Inner.Name() }

func (c CachedSource) Query(ctx context.Context, CVE string) ([]Finding, error) {
	name := c.Inner.Name()

	if c.DB != nil && c.TTL > 0 {
		if rows, ok, err := c.DB.CachedPOCs(CVE, name, c.TTL, time.Now()); err == nil && ok {
			return findingsFromRows(rows), nil
		}
		// A cache error must never break a search; fall through to the network.
	}

	findings, err := c.Inner.Query(ctx, CVE)
	if err != nil {
		return findings, err
	}
	if c.DB != nil {
		rows := make([]db.POCRow, 0, len(findings))
		out := make([]Finding, 0, len(findings))
		for _, f := range findings {
			u := db.CanonicalURL(f.POC)
			if u == "" {
				// Nothing storable; pass the original finding through.
				out = append(out, f)
				continue
			}
			nf := f
			nf.POC = u
			out = append(out, nf)
			rows = append(rows, db.POCRow{
				CVE:      CVE,
				Source:   name,
				URL:      u,
				Owner:    f.Owner,
				PushedAt: f.PushedAt,
				Raw:      f.POC,
			})
		}
		// Storage failures are non-fatal: results are still returned.
		_ = c.DB.StorePOCs(name, time.Now(), rows)
		_ = c.DB.EvictStalePOCs(c.TTL, time.Now())
		return out, nil
	}
	return findings, nil
}

func findingsFromRows(rows []db.POCRow) []Finding {
	out := make([]Finding, 0, len(rows))
	for _, r := range rows {
		out = append(out, Finding{
			CVE:      r.CVE,
			POC:      r.URL,
			Owner:    r.Owner,
			PushedAt: r.PushedAt,
			Source:   r.Source,
		})
	}
	return out
}
