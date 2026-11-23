package cli

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Fakechippies/POC-Hunter/cve"
	"github.com/Fakechippies/POC-Hunter/db"
)

type fakeCVESource struct {
	name     string
	calls    atomic.Int32
	findings []cve.Finding
	err      error
}

func (f *fakeCVESource) Name() string { return f.name }

func (f *fakeCVESource) Query(ctx context.Context, vendor, product, version, ecosystem string) ([]cve.Finding, error) {
	f.calls.Add(1)
	return f.findings, f.err
}

func openCLICacheDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestCollectCVEsCachesPerSource(t *testing.T) {
	nvd := &fakeCVESource{name: "nvd", findings: []cve.Finding{
		{CVE: "CVE-2021-44228", Source: "nvd", Detail: "log4j RCE", Score: 10.0},
	}}
	circl := &fakeCVESource{name: "circl", findings: []cve.Finding{
		{CVE: "CVE-2021-44228", Source: "circl", Detail: "log4j RCE"},
	}}
	d := openCLICacheDB(t)

	run := func() []cveSourceResult {
		return collectCVEs(context.Background(), []cve.Source{nvd, circl}, "", "log4j", "2.0", "",
			d, 30*time.Minute, false)
	}

	first := run()
	if nvd.calls.Load() != 1 || circl.calls.Load() != 1 {
		t.Fatalf("first run calls: nvd=%d circl=%d, want 1/1", nvd.calls.Load(), circl.calls.Load())
	}
	for _, r := range first {
		if r.cached {
			t.Errorf("%s must not be cached on first run", r.source)
		}
	}

	second := run()
	if nvd.calls.Load() != 1 || circl.calls.Load() != 1 {
		t.Errorf("second run calls: nvd=%d circl=%d, want 1/1 (served from cache)", nvd.calls.Load(), circl.calls.Load())
	}
	for _, r := range second {
		if !r.cached {
			t.Errorf("%s must be cached on second run", r.source)
		}
		if len(r.findings) != 1 || r.findings[0].CVE != "CVE-2021-44228" {
			t.Errorf("%s cached findings = %+v", r.source, r.findings)
		}
	}

	// Per-CVE bare info was filled lazily from the API results.
	info, ok, err := d.CVEInfoGet("CVE-2021-44228")
	if err != nil || !ok || info.Summary != "log4j RCE" {
		t.Errorf("CVEInfoGet = %+v ok=%v err=%v", info, ok, err)
	}
}

func TestCollectCVEsRefreshBypassesReads(t *testing.T) {
	src := &fakeCVESource{name: "nvd", findings: []cve.Finding{{CVE: "CVE-1", Source: "nvd"}}}
	d := openCLICacheDB(t)

	collectCVEs(context.Background(), []cve.Source{src}, "", "p", "", "", d, time.Hour, false)
	collectCVEs(context.Background(), []cve.Source{src}, "", "p", "", "", d, time.Hour, true)
	if src.calls.Load() != 2 {
		t.Errorf("calls = %d, want 2 (--refresh must bypass cache reads)", src.calls.Load())
	}
}

func TestCollectCVEsErrorNotCached(t *testing.T) {
	src := &fakeCVESource{name: "nvd", err: context.DeadlineExceeded}
	d := openCLICacheDB(t)

	collectCVEs(context.Background(), []cve.Source{src}, "", "p", "", "", d, time.Hour, false)
	// A failed response must not populate the cache: the retry below hits the
	// source again.
	src.err = nil
	src.findings = []cve.Finding{{CVE: "CVE-1", Source: "nvd"}}
	res := collectCVEs(context.Background(), []cve.Source{src}, "", "p", "", "", d, time.Hour, false)
	if src.calls.Load() != 2 {
		t.Errorf("calls = %d, want 2 (errors must not be cached)", src.calls.Load())
	}
	if res[0].cached {
		t.Error("unexpected cache hit after an erroring run")
	}
}

func TestPrintCVECacheStatusSilentWhenAllFresh(t *testing.T) {
	results := []cveSourceResult{{source: "nvd", findings: []cve.Finding{{CVE: "CVE-1"}}}}
	printCVECacheStatus(results) // must not print anything; nothing to assert beyond no panic
}
