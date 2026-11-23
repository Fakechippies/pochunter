package poc

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Fakechippies/POC-Hunter/db"
)

// DefaultMaxIndexAge is how long a built bulk index is trusted without a
// revision check.
const DefaultMaxIndexAge = time.Hour

// ForceUpdater is implemented by sources backed by a local bulk index that
// can be rebuilt from upstream on demand (used by `pochunter update`).
type ForceUpdater interface {
	ForceUpdate(ctx context.Context) (int, error)
}

// BulkSource is a POC source backed by a bulk index downloaded once and
// cached in the SQLite database (index_pocs table). Lookups after the first
// build never touch the network. The index is rebuilt when the upstream
// revision changes (checked via a cheap HEAD request, skipped within
// MaxIndexAge) or forced via ForceUpdate.
//
// Fetch downloads the full index and returns its body plus a revision marker
// (upstream ETag or Last-Modified). Head returns the current revision without
// the body. Parse converts the body into index rows. All three are
// overridable in tests.
type BulkSource struct {
	Name string
	DB   *db.DB

	// MaxIndexAge bounds how long the built index is trusted before a
	// revision check happens. Zero means DefaultMaxIndexAge.
	MaxIndexAge time.Duration

	Fetch func(ctx context.Context) ([]byte, string, error)
	Head  func(ctx context.Context) (string, error)
	Parse func(body []byte) ([]db.IndexPOCRow, error)

	buildMu sync.Mutex // serializes index (re)builds across goroutines
}

func (b *BulkSource) maxIndexAge() time.Duration {
	if b.MaxIndexAge == 0 {
		return DefaultMaxIndexAge
	}
	return b.MaxIndexAge
}

// indexStale reports whether the stored index needs a revision check.
func (b *BulkSource) indexStale() bool {
	fetchedAt, ok := b.DB.IndexFetchedAt(b.Name)
	if !ok {
		return true
	}
	return time.Since(fetchedAt) >= b.maxIndexAge()
}

func (b *BulkSource) Query(ctx context.Context, CVE string) ([]Finding, error) {
	if b.DB == nil {
		return nil, fmt.Errorf("%s: requires a cache database (omit --no-cache)", b.Name)
	}

	rows, err := b.DB.IndexPOCs(CVE, b.Name)
	if err != nil {
		return nil, err
	}
	if len(rows) > 0 && !b.indexStale() {
		return findingsFromIndexRows(rows, b.Name), nil
	}

	if err := b.ensureIndex(ctx); err != nil {
		// Graceful degradation: an outdated index beats no results.
		if len(rows) > 0 {
			return findingsFromIndexRows(rows, b.Name), nil
		}
		return nil, err
	}

	rows, err = b.DB.IndexPOCs(CVE, b.Name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return findingsFromIndexRows(rows, b.Name), nil
}

// ForceUpdate unconditionally re-downloads and rebuilds the index, ignoring
// the stored revision and staleness window. Used by `pochunter update`.
func (b *BulkSource) ForceUpdate(ctx context.Context) (int, error) {
	if b.DB == nil {
		return 0, fmt.Errorf("%s: requires a cache database", b.Name)
	}
	b.buildMu.Lock()
	defer b.buildMu.Unlock()

	body, brev, err := b.fetchIndex(ctx)
	if err != nil {
		return 0, fmt.Errorf("%s: fetch index: %w", b.Name, err)
	}
	parsed, err := b.Parse(body)
	if err != nil {
		return 0, fmt.Errorf("%s: parse index: %w", b.Name, err)
	}
	if err := b.DB.StoreIndexPOCs(b.Name, parsed); err != nil {
		return 0, err
	}
	return len(parsed), b.DB.SetIndexRev(b.Name, brev, time.Now())
}

// ensureIndex rebuilds the local index from upstream if its revision changed.
// Concurrent callers are serialized; the first one builds, the rest see a
// fresh index.
func (b *BulkSource) ensureIndex(ctx context.Context) error {
	b.buildMu.Lock()
	defer b.buildMu.Unlock()

	// Someone ahead of us in the queue may have just rebuilt it.
	if !b.indexStale() {
		return nil
	}

	// Cheap revision check first: skip the full download when unchanged.
	if rev, err := b.currentRev(ctx); err == nil {
		if old, ok := b.DB.IndexRev(b.Name); ok && old == rev {
			return b.DB.SetIndexRev(b.Name, rev, time.Now())
		}
	}

	body, brev, err := b.fetchIndex(ctx)
	if err != nil {
		return fmt.Errorf("%s: fetch index: %w", b.Name, err)
	}
	if old, ok := b.DB.IndexRev(b.Name); ok && old == brev {
		return b.DB.SetIndexRev(b.Name, brev, time.Now())
	}

	parsed, err := b.Parse(body)
	if err != nil {
		return fmt.Errorf("%s: parse index: %w", b.Name, err)
	}
	if err := b.DB.StoreIndexPOCs(b.Name, parsed); err != nil {
		return err
	}
	return b.DB.SetIndexRev(b.Name, brev, time.Now())
}

func (b *BulkSource) currentRev(ctx context.Context) (string, error) {
	if b.Head != nil {
		return b.Head(ctx)
	}
	return "", fmt.Errorf("%s: no revision probe configured", b.Name)
}

func (b *BulkSource) fetchIndex(ctx context.Context) ([]byte, string, error) {
	if b.Fetch != nil {
		return b.Fetch(ctx)
	}
	return nil, "", fmt.Errorf("%s: no fetch configured", b.Name)
}

func findingsFromIndexRows(rows []db.IndexPOCRow, source string) []Finding {
	out := make([]Finding, 0, len(rows))
	for _, r := range rows {
		out = append(out, Finding{CVE: r.CVE, POC: r.URL, PushedAt: r.PushedAt, Source: source})
	}
	return out
}
