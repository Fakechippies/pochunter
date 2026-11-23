package db

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	d, err := Open(filepath.Join(t.TempDir(), "sub", "cache.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestOpenCreatesSchema(t *testing.T) {
	d := openTestDB(t)

	for _, table := range []string{"pocs", "cves", "indexes", "index_pocs"} {
		var name string
		err := d.sql.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name = ?", table,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %s missing: %v", table, err)
		}
	}
}

func TestStoreAndCacheRoundtrip(t *testing.T) {
	d := openTestDB(t)
	now := time.Now()

	rows := []POCRow{
		{CVE: "CVE-2021-44228", URL: "https://github.com/owner/repo", Owner: "owner", PushedAt: "2021-12-10T00:00:00Z", Raw: "http://github.com/owner/repo#readme"},
		{CVE: "CVE-2021-44228", URL: "https://www.exploit-db.com/exploits/50592", Owner: "www.exploit-db.com"},
	}
	if err := d.StorePOCs("poc-in-github", now, rows); err != nil {
		t.Fatalf("StorePOCs: %v", err)
	}

	got, ok, err := d.CachedPOCs("CVE-2021-44228", "poc-in-github", time.Hour, now)
	if err != nil {
		t.Fatalf("CachedPOCs: %v", err)
	}
	if !ok {
		t.Fatal("expected fresh cache hit")
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2", len(got))
	}
	if got[0].URL != rows[0].URL || got[0].Owner != "owner" {
		t.Errorf("row 0 mismatch: %+v", got[0])
	}

	// Other CVE / source combinations must not hit.
	if _, ok, _ := d.CachedPOCs("CVE-2021-44228", "search-vulns", time.Hour, now); ok {
		t.Error("unexpected hit for other source")
	}
	if _, ok, _ := d.CachedPOCs("CVE-9999-0001", "poc-in-github", time.Hour, now); ok {
		t.Error("unexpected hit for other CVE")
	}
}

func TestCacheTTLExpiry(t *testing.T) {
	d := openTestDB(t)
	stored := time.Now().Add(-2 * time.Hour)

	rows := []POCRow{{CVE: "CVE-2021-44228", URL: "https://github.com/o/r"}}
	if err := d.StorePOCs("poc-in-github", stored, rows); err != nil {
		t.Fatalf("StorePOCs: %v", err)
	}

	if _, ok, _ := d.CachedPOCs("CVE-2021-44228", "poc-in-github", time.Hour, time.Now()); ok {
		t.Error("expected stale entry to be reported as miss")
	}
	// Same data, longer TTL: fresh again.
	if _, ok, _ := d.CachedPOCs("CVE-2021-44228", "poc-in-github", 3*time.Hour, time.Now()); !ok {
		t.Error("expected entry within TTL to be a hit")
	}
}

func TestStoreUpsertsRows(t *testing.T) {
	d := openTestDB(t)
	now := time.Now()

	r := POCRow{CVE: "CVE-2021-44228", URL: "https://github.com/o/r", Owner: "first"}
	if err := d.StorePOCs("poc-in-github", now, []POCRow{r}); err != nil {
		t.Fatalf("StorePOCs: %v", err)
	}
	r.Owner = "second"
	if err := d.StorePOCs("poc-in-github", now, []POCRow{r}); err != nil {
		t.Fatalf("StorePOCs (2nd): %v", err)
	}

	got, ok, err := d.CachedPOCs("CVE-2021-44228", "poc-in-github", time.Hour, now)
	if err != nil || !ok {
		t.Fatalf("CachedPOCs: ok=%v err=%v", ok, err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1 (upsert must not duplicate)", len(got))
	}
	if got[0].Owner != "second" {
		t.Errorf("owner = %q, want updated value", got[0].Owner)
	}
}

func TestConcurrentWriters(t *testing.T) {
	d := openTestDB(t)
	now := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			row := POCRow{CVE: "CVE-2021-44228", URL: "https://github.com/o/r" + string(rune('a'+n))}
			if err := d.StorePOCs("poc-in-github", now, []POCRow{row}); err != nil {
				t.Errorf("StorePOCs: %v", err)
			}
		}(i)
	}
	wg.Wait()

	rows, _, err := d.CachedPOCs("CVE-2021-44228", "poc-in-github", time.Hour, now)
	if err != nil {
		t.Fatalf("CachedPOCs: %v", err)
	}
	if len(rows) != 8 {
		t.Errorf("got %d rows, want 8", len(rows))
	}
}
