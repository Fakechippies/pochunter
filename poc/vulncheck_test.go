package poc

import (
	"context"
	"strings"
	"testing"
)

func TestSSHCloneToHTTPS(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"git@github.com:owner/repo.git", "https://github.com/owner/repo"},
		{"git@github.com:owner/repo", "https://github.com/owner/repo"},
		{"  git@gitlab.com:group/proj.git  ", "https://gitlab.com/group/proj"},
		{"https://github.com/o/r", ""}, // not an SSH remote
		{"git@:nopath", ""},            // missing host
		{"git@host.com:", ""},          // missing path
	}
	for _, c := range cases {
		if got := sshCloneToHTTPS(c.in); got != c.want {
			t.Errorf("sshCloneToHTTPS(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestVulncheckXDBFindings(t *testing.T) {
	entries := []vulncheckXDBEntry{
		{
			XdbID:       "024996c990cc",
			XdbURL:      "https://www.vulncheck.com/xdb/024996c990cc",
			DateAdded:   "2024-05-15T10:30:00Z",
			ExploitType: "initial-access",
			CloneSSHURL: "git@github.com:acmacalister/jetty.git",
		},
		{
			XdbID:  "aa11bb22cc33",
			XdbURL: "https://www.vulncheck.com/xdb/aa11bb22cc33",
		},
	}
	findings := vulncheckXDBFindings("CVE-2024-4577", entries)
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	if findings[0].POC != "https://github.com/acmacalister/jetty" {
		t.Errorf("POC = %q, want the https repo from the SSH remote", findings[0].POC)
	}
	if findings[0].Owner != "acmacalister" {
		t.Errorf("Owner = %q", findings[0].Owner)
	}
	if findings[0].PushedAt != "2024-05-15T10:30:00Z" {
		t.Errorf("PushedAt = %q", findings[0].PushedAt)
	}
	// No SSH remote: fall back to the XDB landing page.
	if findings[1].POC != "https://www.vulncheck.com/xdb/aa11bb22cc33" {
		t.Errorf("fallback POC = %q", findings[1].POC)
	}
	if findings[1].Owner != "www.vulncheck.com" {
		t.Errorf("fallback Owner = %q", findings[1].Owner)
	}
	if !strings.Contains(findings[1].Source, "vulncheck") {
		t.Errorf("Source = %q", findings[1].Source)
	}
}

func TestVulncheckRequiresAPIKey(t *testing.T) {
	src := VulnCheckXDB{}
	if _, err := src.Query(testContext(), "CVE-2024-4577"); err == nil {
		t.Error("expected error without API key")
	}
	iac := VulnCheckIAC{}
	if _, err := iac.Query(testContext(), "CVE-2024-4577"); err == nil {
		t.Error("expected error without API key (IAC)")
	}
}

func testContext() context.Context { return context.Background() }
