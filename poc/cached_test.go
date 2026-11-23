package poc

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Fakechippies/pochunter/db"
)

type fakeSource struct {
	calls    int
	findings []Finding
	err      error
}

func (f *fakeSource) Name() string { return "fake" }

func (f *fakeSource) Query(ctx context.Context, CVE string) ([]Finding, error) {
	f.calls++
	return f.findings, f.err
}

func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestCachedSourceHitsCacheOnSecondQuery(t *testing.T) {
	inner := &fakeSource{findings: []Finding{
		{CVE: "CVE-2021-44228", POC: "http://github.com/o/r/", Owner: "o", Source: "fake"},
	}}
	d := openTestDB(t)
	src := CachedSource{Inner: inner, DB: d, TTL: time.Hour}
	ctx := context.Background()

	first, err := src.Query(ctx, "CVE-2021-44228")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if inner.calls != 1 {
		t.Fatalf("inner calls = %d, want 1", inner.calls)
	}
	if first[0].POC != "https://github.com/o/r" {
		t.Errorf("normalized POC = %q, want https URL without trailing slash", first[0].POC)
	}

	second, err := src.Query(ctx, "CVE-2021-44228")
	if err != nil {
		t.Fatalf("Query (2nd): %v", err)
	}
	if inner.calls != 1 {
		t.Errorf("inner calls = %d, want 1 (second query must come from cache)", inner.calls)
	}
	if len(second) != 1 || second[0].POC != "https://github.com/o/r" || second[0].Owner != "o" {
		t.Errorf("cached findings mismatch: %+v", second)
	}
}

func TestCachedSourceTTLExpiry(t *testing.T) {
	inner := &fakeSource{findings: []Finding{{CVE: "CVE-1", POC: "https://x.example/1", Source: "fake"}}}
	d := openTestDB(t)
	src := CachedSource{Inner: inner, DB: d, TTL: -time.Minute} // already stale
	if _, err := src.Query(context.Background(), "CVE-1"); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if inner.calls != 1 {
		t.Fatalf("inner calls = %d", inner.calls)
	}
	// A negative TTL means stored rows are instantly stale, so the inner
	// source is consulted again.
	if _, err := src.Query(context.Background(), "CVE-1"); err != nil {
		t.Fatalf("Query (2nd): %v", err)
	}
	if inner.calls != 2 {
		t.Errorf("inner calls = %d, want 2 (expired cache must re-query)", inner.calls)
	}
}

func TestCachedSourceDisabledWithoutDB(t *testing.T) {
	inner := &fakeSource{findings: []Finding{{CVE: "CVE-1", POC: "https://x.example/1", Source: "fake"}}}
	src := CachedSource{Inner: inner} // DB == nil
	for i := 0; i < 3; i++ {
		if _, err := src.Query(context.Background(), "CVE-1"); err != nil {
			t.Fatalf("Query: %v", err)
		}
	}
	if inner.calls != 3 {
		t.Errorf("inner calls = %d, want 3 (no cache configured)", inner.calls)
	}
}

func TestCachedSourceInnerErrorNotStored(t *testing.T) {
	inner := &fakeSource{err: context.DeadlineExceeded}
	d := openTestDB(t)
	src := CachedSource{Inner: inner, DB: d, TTL: time.Hour}

	if _, err := src.Query(context.Background(), "CVE-1"); err == nil {
		t.Fatal("expected inner error to propagate")
	}
	if _, ok, _ := d.CachedPOCs("CVE-1", "fake", time.Hour, time.Now()); ok {
		t.Error("erroring query must not populate the cache")
	}
}
