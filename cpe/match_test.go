package cpe

import (
	"strings"
	"testing"

	"github.com/Fakechippies/pochunter/db"
)

func testEntries() []entry {
	rows := []db.CPEEntry{
		{Prefix: "cpe:2.3:a:apache:http_server", Vendor: "apache", Product: "http_server", Title: "Apache Http Server 2.4.39"},
		{Prefix: "cpe:2.3:a:apache:tomcat", Vendor: "apache", Product: "tomcat", Title: "Apache Tomcat"},
		{Prefix: "cpe:2.3:a:haxx:curl", Vendor: "haxx", Product: "curl", Title: "curl"},
		{Prefix: "cpe:2.3:a:palletsprojects:flask", Vendor: "palletsprojects", Product: "flask", Title: "Flask"},
		{Prefix: "cpe:2.3:a:flaskcaching_project:flask-caching", Vendor: "flaskcaching_project", Product: "flask-caching", Title: "Flask-Caching"},
		{Prefix: "cpe:2.3:a:google:chrome", Vendor: "google", Product: "chrome", Title: "Google Chrome"},
	}
	return LoadEntries(rows)
}

func TestResolveApp(t *testing.T) {
	entries := testEntries()

	cases := []struct {
		query      string
		wantPrefix string // substring the resolved CPE must contain; "" = no match
		wantVer    string
	}{
		{"apache http server 2.4.39", "apache:http_server", "2.4.39"},
		{"Apache Http Server 2.4.39", "apache:http_server", "2.4.39"},
		{"apache tomcat 9.0.50", "apache:tomcat", "9.0.50"},
		{"curl 7.0", "haxx:curl", "7.0"},
		{"curl", "haxx:curl", ""}, // versionless -> "*"
		{"flask", "flask", ""},    // exact product beats flask-caching
		{"chrome v8", "", ""},     // v8 term missing -> no match
		{"wordpres yolo", "", ""}, // unknown terms -> no match
	}

	for _, c := range cases {
		got, _, ver, ok := ResolveApp(c.query, entries)
		if c.wantPrefix == "" {
			if ok {
				t.Errorf("ResolveApp(%q) = %q, want no match", c.query, got)
			}
			continue
		}
		if !ok {
			t.Errorf("ResolveApp(%q) found nothing, want %q", c.query, c.wantPrefix)
			continue
		}
		if !strings.Contains(got, c.wantPrefix) {
			t.Errorf("ResolveApp(%q) = %q, want prefix %q", c.query, got, c.wantPrefix)
		}
		if ver != c.wantVer {
			t.Errorf("ResolveApp(%q) version = %q, want %q", c.query, ver, c.wantVer)
		}
		if c.wantVer != "" && !strings.Contains(got, ":"+c.wantVer+":") {
			t.Errorf("ResolveApp(%q) CPE %q lacks injected version %q", c.query, got, c.wantVer)
		}
		if c.wantVer == "" && !strings.Contains(got, ":*:") {
			t.Errorf("versionless ResolveApp(%q) CPE %q lacks '*' version field", c.query, got)
		}
	}
}

func TestResolveAppThresholdBlocksWeakMatches(t *testing.T) {
	// A query whose terms are only partially present must not match.
	entries := testEntries()
	if got, _, _, ok := ResolveApp("tomcat clustering deep dive", entries); ok {
		t.Errorf("weak match resolved: %q (score below threshold expected)", got)
	}
}
