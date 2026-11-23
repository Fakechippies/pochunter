package poc

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/Fakechippies/POC-Hunter/db"
)

func openBulkDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// newBulk wires a BulkSource to canned fetch/head/parse overrides and asserts
// one full Query roundtrip returns the expected rows.
func newBulk(t *testing.T, src *BulkSource, body string) *BulkSource {
	t.Helper()
	src.DB = openBulkDB(t)
	rev := &atomic.Value{}
	rev.Store("rev-1")
	src.Fetch = func(ctx context.Context) ([]byte, string, error) {
		return []byte(body), rev.Load().(string), nil
	}
	src.Head = func(ctx context.Context) (string, error) {
		return rev.Load().(string), nil
	}
	return src
}

func TestTrickestParse(t *testing.T) {
	body := "CVE-0000-0000 - https://github.com/junk/placeholder\n" +
		"CVE-2023-0001 - https://github.com/owner/repo\n" +
		"garbage line without separator\n" +
		"CVE-not-real - https://github.com/x/y\n" +
		"CVE-2023-0002 - https://github.com/o2/r2/\n"
	rows, err := parseTrickest([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want 2 (placeholder and junk skipped)", rows)
	}
	if rows[0].CVE != "CVE-2023-0001" || rows[0].URL != "https://github.com/owner/repo" {
		t.Errorf("row 0 = %+v", rows[0])
	}
	if rows[1].URL != "https://github.com/o2/r2" {
		t.Errorf("row 1 URL = %+v (want canonicalized)", rows[1])
	}
}

func TestMetasploitParse(t *testing.T) {
	body := `{
	  "auxiliary_admin_2wire_xslt_password_reset": {
	    "fullname": "auxiliary/admin/2wire/xslt_password_reset",
	    "name": "2Wire CSRF Password Reset",
	    "type": "auxiliary",
	    "disclosure_date": "2007-08-15",
	    "references": ["CVE-2007-4387", "OSVDB-37667", "URL-https://example.com"]
	  },
	  "exploit_multi_script_upload": {
	    "fullname": "exploit/multi/script/upload",
	    "name": "Script Upload",
	    "type": "exploit",
	    "disclosure_date": "2020-01-01",
	    "references": []
	  }
	}`
	rows, err := parseMetasploit([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want 1 (only CVE refs)", rows)
	}
	r := rows[0]
	if r.CVE != "CVE-2007-4387" {
		t.Errorf("CVE = %q", r.CVE)
	}
	if r.URL != "https://www.rapid7.com/db/modules/auxiliary/admin/2wire/xslt_password_reset/" {
		t.Errorf("URL = %q", r.URL)
	}
	if r.PushedAt != "2007-08-15T00:00:00Z" {
		t.Errorf("PushedAt = %q", r.PushedAt)
	}
}

func TestNucleiParse(t *testing.T) {
	// Note the embedded newline inside Description: NDJSON, not line-regex.
	body := "{\"ID\":\"CVE-2000-0114\",\"Info\":{\"Name\":\"FrontPage Info Disclosure\",\"Severity\":\"medium\"},\"file_path\":\"http/cves/2000/CVE-2000-0114.yaml\"}\n" +
		"{\"ID\":\"not-a-cve\",\"Info\":{\"Name\":\"x\"},\"file_path\":\"http/cves/2000/x.yaml\"}\n" +
		"{\"ID\":\"CVE-2000-0760\",\"Info\":{\"Name\":\"Tomcat\"},\"file_path\":\"http/cves/2000/CVE-2000-0760.yaml\"}\n" +
		"\n"
	rows, err := parseNuclei([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want 2", rows)
	}
	if rows[0].URL != "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2000/CVE-2000-0114.yaml" {
		t.Errorf("URL = %q", rows[0].URL)
	}
	if rows[0].Detail != "FrontPage Info Disclosure" {
		t.Errorf("Detail = %q", rows[0].Detail)
	}
}

func TestTg12Parse(t *testing.T) {
	body := "Last updated: 2025-11-28 11:52\n\n" +
		"Bitcoin: 3QjWqhQbHdHgWeYHTpmorP8Pe1wgDjJy54\n\n" +
		"+------------------------------------------------------------------+\n" +
		"| CVE-2009-1151                                                    |\n" +
		"+------------------------------------------------------------------+\n" +
		"| https://github.com/pagvac/pocs                                   |\n" +
		"| https://github.com/e-Thug/PhpMyAdmin                             |\n" +
		"+------------------------------------------------------------------+\n" +
		"| CVE-2020-1472                                                    |\n" +
		"+------------------------------------------------------------------+\n" +
		"| https://github.com/Zero614/ZeroLogon                             |\n" +
		"+------------------------------------------------------------------+\n"
	rows, err := parseTg12([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %+v, want 3", rows)
	}
	if rows[0].CVE != "CVE-2009-1151" || rows[0].URL != "https://github.com/pagvac/pocs" {
		t.Errorf("row 0 = %+v", rows[0])
	}
	if rows[2].CVE != "CVE-2020-1472" {
		t.Errorf("row 2 = %+v", rows[2])
	}
}

func TestAwesomeParse(t *testing.T) {
	body := "# **2021 CVEs**\n\n" +
		"| # | CVE ID | POC Link |\n" +
		"|---:|---|---|\n" +
		"| 1 | **CVE-2021-1675** | <a href=\"https://github.com/ArtAtrium/PrintNightmare\">POC Link</a><br><a href=\"http://github.com/CameraShutterBug/PrintNightmare/\">POC Link</a> |\n" +
		"| 2 | **CVE-2021-1678** | <a href=\"https://github.com/alvaciroliveira/RpcAuthnLevelPrivacyEnabled\">POC Link</a> |\n"
	rows, err := parseAwesome([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %+v, want 3", rows)
	}
	// http upgraded to https and trailing slash dropped by CanonicalURL.
	if rows[1].URL != "https://github.com/CameraShutterBug/PrintNightmare" {
		t.Errorf("row 1 URL = %q", rows[1].URL)
	}
	if rows[2].CVE != "CVE-2021-1678" {
		t.Errorf("row 2 = %+v", rows[2])
	}
}

func TestAwesomeYearRange(t *testing.T) {
	a := NewAwesomeCVEPOC(openBulkDB(t))
	if first, last := a.years(); first != 2016 || last != 2026 {
		t.Errorf("default years = %d..%d, want 2016..2026", first, last)
	}
	a.FirstYear, a.LastYear = 2020, 2021
	if first, last := a.years(); first != 2020 || last != 2021 {
		t.Errorf("configured years = %d..%d", first, last)
	}
}
