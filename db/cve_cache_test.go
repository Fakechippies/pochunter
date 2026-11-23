package db

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestCVECacheRoundtrip(t *testing.T) {
	d := openTestDB(t)
	now := time.Now()
	key := CVECacheKey("", "curl", "7.0", "")

	if err := d.CVECacheStore(key, "nvd", []byte(`[{"cve":"CVE-1","source":"nvd"}]`), now, time.Hour, CVECacheCapKeys); err != nil {
		t.Fatalf("store nvd: %v", err)
	}
	if err := d.CVECacheStore(key, "circl", []byte(`[{"cve":"CVE-2","source":"circl"}]`), now, time.Hour, CVECacheCapKeys); err != nil {
		t.Fatalf("store circl: %v", err)
	}

	payload, createdAt, ok, err := d.CVECacheGet(key, "nvd")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if string(payload) != `[{"cve":"CVE-1","source":"nvd"}]` {
		t.Errorf("payload = %s", payload)
	}
	if time.Since(createdAt) > time.Minute {
		t.Errorf("createdAt = %v, want ~now", createdAt)
	}

	// A different query key must not hit.
	other := CVECacheKey("", "curl", "7.57", "")
	if _, _, ok, _ := d.CVECacheGet(other, "nvd"); ok {
		t.Error("unexpected hit for other query key")
	}
}

func TestCVECacheTTLExpiry(t *testing.T) {
	d := openTestDB(t)
	key := CVECacheKey("", "curl", "7.0", "")

	// Stored 2h ago with a 1h TTL: writing another payload evicts it.
	old := time.Now().Add(-2 * time.Hour)
	if err := d.CVECacheStore(key, "nvd", []byte(`[]`), old, time.Hour, CVECacheCapKeys); err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := d.CVECacheStore(CVECacheKey("", "x", "", ""), "nvd", []byte(`[]`), time.Now(), time.Hour, CVECacheCapKeys); err != nil {
		t.Fatalf("store 2nd: %v", err)
	}
	if _, _, ok, _ := d.CVECacheGet(key, "nvd"); ok {
		t.Error("expired payload must be evicted on write")
	}
}

func TestCVECacheCapDropsOldestKeys(t *testing.T) {
	d := openTestDB(t)
	now := time.Now()

	// Fill to the cap, all at the same instant (no TTL interaction).
	for i := 0; i < CVECacheCapKeys; i++ {
		key := CVECacheKey("", "prod", time.Duration(i).String(), "")
		if err := d.CVECacheStore(key, "nvd", []byte(`[]`), now, time.Hour, CVECacheCapKeys); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
	}
	// One more (an hour later): the cap must keep the count fixed by
	// dropping the oldest key(s), never growing beyond it.
	if err := d.CVECacheStore(CVECacheKey("", "new", "", ""), "nvd", []byte(`[]`), now.Add(time.Hour), time.Hour, CVECacheCapKeys); err != nil {
		t.Fatalf("store overflow: %v", err)
	}

	var count int
	if err := d.sql.QueryRow("SELECT COUNT(DISTINCT key) FROM cve_cache").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != CVECacheCapKeys {
		t.Errorf("distinct keys = %d, want %d", count, CVECacheCapKeys)
	}
	if _, _, ok, _ := d.CVECacheGet(CVECacheKey("", "new", "", ""), "nvd"); !ok {
		t.Error("the newest key must survive the cap eviction")
	}
}

func TestCVEInfoStoreAndGet(t *testing.T) {
	d := openTestDB(t)
	now := time.Now()

	rows := []CVEInfoRow{
		{ID: "CVE-2021-44228", Summary: "log4j RCE"},
		{ID: "CVE-2021-45046", Summary: "log4j follow-up"},
		{ID: "", Summary: "dropped"},
	}
	if err := d.CVEInfoStore(rows, now); err != nil {
		t.Fatalf("store: %v", err)
	}
	summary, ok, err := d.CVEInfoGet("CVE-2021-44228")
	if err != nil || !ok || summary != "log4j RCE" {
		t.Errorf("get = %q ok=%v err=%v", summary, ok, err)
	}

	// Upsert refreshes summary; empty-ID rows are skipped.
	if err := d.CVEInfoStore([]CVEInfoRow{{ID: "CVE-2021-44228", Summary: "updated"}}, now); err != nil {
		t.Fatalf("store 2nd: %v", err)
	}
	if summary, _, _ := d.CVEInfoGet("CVE-2021-44228"); summary != "updated" {
		t.Errorf("summary = %q, want updated", summary)
	}

	// Expiry: backdate, then any write evicts.
	if err := d.Exec("UPDATE cves SET fetched_at = ?", time.Now().Add(-8*24*time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if err := d.CVEInfoStore([]CVEInfoRow{{ID: "CVE-9999-9999", Summary: "fresh"}}, now); err != nil {
		t.Fatalf("store 3rd: %v", err)
	}
	if _, ok, _ := d.CVEInfoGet("CVE-2021-44228"); ok {
		t.Error("expired info row must be evicted on write")
	}
	if _, ok, _ := d.CVEInfoGet("CVE-9999-9999"); !ok {
		t.Error("fresh info row must survive eviction")
	}
}

func TestMigrateCvesFetchedAt(t *testing.T) {
	// Create a database with the OLD cves schema (no fetched_at), then open
	// it through Open() and verify the migration ran.
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE cves(
		id TEXT PRIMARY KEY, published TEXT NOT NULL,
		summary TEXT NOT NULL DEFAULT '', kev INTEGER NOT NULL DEFAULT 0, epss REAL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO cves(id, published, summary) VALUES ('CVE-1', '2021-01-01', 'old row')`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	d, err := Open(path)
	if err != nil {
		t.Fatalf("Open on old schema: %v", err)
	}
	defer d.Close()

	// The legacy row has no fetched_at stamp ('' sorts before any RFC3339
	// cutoff): it is treated as expired and disappears on the next write.
	if _, ok, _ := d.CVEInfoGet("CVE-1"); ok {
		t.Error("legacy unstamped row must not be served as fresh")
	}
	if err := d.CVEInfoStore([]CVEInfoRow{{ID: "CVE-2", Summary: "new"}}, time.Now()); err != nil {
		t.Fatalf("store after migration: %v", err)
	}
	if summary, ok, _ := d.CVEInfoGet("CVE-2"); !ok || summary != "new" {
		t.Errorf("store/get after migration failed: %q ok=%v", summary, ok)
	}
	if err := d.CVEInfoStore([]CVEInfoRow{{ID: "CVE-3", Summary: "trigger evict"}}, time.Now()); err != nil {
		t.Fatalf("store 2nd after migration: %v", err)
	}
	if _, ok, _ := d.CVEInfoGet("CVE-1"); ok {
		t.Error("legacy unstamped row must be evicted on write")
	}
}
