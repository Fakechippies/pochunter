package db

import (
	"path/filepath"
	"testing"
	"time"
)

func TestMetaRoundtrip(t *testing.T) {
	d := openTestDB(t)

	if v, ok, _ := d.meta("schema_version"); !ok || v == "" {
		t.Fatalf("schema_version not recorded on fresh db: %q ok=%v", v, ok)
	}
	if v, ok, _ := d.meta("built_with"); !ok || v != "dev" {
		t.Errorf("built_with = %q ok=%v, want %q", v, ok, "dev")
	}
}

func openVersioned(t *testing.T, path, version string) *DB {
	t.Helper()
	d, err := openWithVersion(path, version)
	if err != nil {
		t.Fatalf("openWithVersion(%q): %v", version, err)
	}
	return d
}

func TestAppVersionChangeWipesIndexes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")

	d1 := openVersioned(t, path, "v1.0.0")
	defer d1.Close()

	if err := d1.SetIndexRev("exploitdb", "rev-1", time.Now()); err != nil {
		t.Fatalf("SetIndexRev: %v", err)
	}
	if err := d1.StoreIndexPOCs("exploitdb", []IndexPOCRow{{CVE: "CVE-1", URL: "https://x/1"}}); err != nil {
		t.Fatalf("StoreIndexPOCs: %v", err)
	}
	d1.Close()

	// Same version: indexes survive.
	d2 := openVersioned(t, path, "v1.0.0")
	defer d2.Close()
	if rows, _ := d2.IndexPOCs("CVE-1", "exploitdb"); len(rows) != 1 {
		t.Fatalf("index rows lost on same-version reopen: %d", len(rows))
	}
	d2.Close()

	// New release: derived indexes are wiped and must be rebuilt upstream.
	d3 := openVersioned(t, path, "v1.1.0")
	defer d3.Close()
	if rows, _ := d3.IndexPOCs("CVE-1", "exploitdb"); len(rows) != 0 {
		t.Errorf("index rows survived version change: %d", len(rows))
	}
	if _, ok := d3.IndexRev("exploitdb"); ok {
		t.Error("index revision survived version change")
	}
	if built, ok, _ := d3.meta("built_with"); !ok || built != "v1.1.0" {
		t.Errorf("built_with = %q, want v1.1.0", built)
	}
}

func TestWipeIndex(t *testing.T) {
	d := openTestDB(t)
	if err := d.SetIndexRev("exploitdb", "rev-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := d.StoreIndexPOCs("exploitdb", []IndexPOCRow{{CVE: "CVE-1", URL: "https://x/1"}}); err != nil {
		t.Fatal(err)
	}
	if err := d.StorePOCs("poc-in-github", time.Now(), []POCRow{{CVE: "CVE-1", URL: "https://y/1"}}); err != nil {
		t.Fatal(err)
	}

	if err := d.WipeIndex("exploitdb"); err != nil {
		t.Fatalf("WipeIndex: %v", err)
	}
	if rows, _ := d.IndexPOCs("CVE-1", "exploitdb"); len(rows) != 0 {
		t.Error("index_pocs not wiped")
	}
	if _, ok := d.IndexRev("exploitdb"); ok {
		t.Error("indexes revision not wiped")
	}
	// The plain POC cache is independent of bulk indexes.
	if rows, ok, _ := d.CachedPOCs("CVE-1", "poc-in-github", time.Hour, time.Now()); !ok || len(rows) != 1 {
		t.Error("WipeIndex must not touch the pocs cache")
	}
}
