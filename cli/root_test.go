package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/Fakechippies/POC-Hunter/cve"
	"github.com/Fakechippies/POC-Hunter/poc"
)

func TestResolveSearchInput(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		opts        options
		wantProduct string
		wantVersion string
		wantErr     bool
	}{
		{
			name:        "search with app and version in args",
			args:        []string{"curl", "7.0"},
			opts:        options{searchMode: true},
			wantProduct: "curl",
			wantVersion: "7.0",
		},
		{
			name:        "search with single arg containing app and version",
			args:        []string{"curl 7.0"},
			opts:        options{searchMode: true},
			wantProduct: "curl",
			wantVersion: "7.0",
		},
		{
			name:        "positional args without search flag",
			args:        []string{"curl", "7.0"},
			opts:        options{},
			wantProduct: "curl",
			wantVersion: "7.0",
		},
		{
			name:        "search with multi-word app and version",
			args:        []string{"apache", "tomcat", "9.0.50"},
			opts:        options{searchMode: true},
			wantProduct: "apache tomcat",
			wantVersion: "9.0.50",
		},
		{
			name:        "search with app and explicit version flag",
			args:        []string{"curl"},
			opts:        options{version: "7.0"},
			wantProduct: "curl",
			wantVersion: "7.0",
		},
		{
			name:        "app flag and explicit version flag",
			args:        nil,
			opts:        options{app: "curl", version: "7.0"},
			wantProduct: "curl",
			wantVersion: "7.0",
		},
		{
			name:        "app flag with version in positional arg",
			args:        []string{"7.0"},
			opts:        options{app: "curl"},
			wantProduct: "curl",
			wantVersion: "7.0",
		},
		{
			name:        "free-form keyword query without version",
			args:        []string{"log4j"},
			opts:        options{searchMode: true},
			wantProduct: "log4j",
			wantVersion: "",
		},
		{
			name:        "multi-word query without version",
			args:        []string{"apache", "tomcat"},
			opts:        options{searchMode: true},
			wantProduct: "apache tomcat",
			wantVersion: "",
		},
		{
			name:    "empty search mode",
			args:    nil,
			opts:    options{searchMode: true},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, prod, ver, _, err := resolveSearchInput(tc.args, tc.opts)
			if (err != nil) != tc.wantErr {
				t.Fatalf("resolveSearchInput() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if prod != tc.wantProduct {
				t.Errorf("product = %q, want %q", prod, tc.wantProduct)
			}
			if ver != tc.wantVersion {
				t.Errorf("version = %q, want %q", ver, tc.wantVersion)
			}
		})
	}
}

func TestIsRateLimitError(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{fmt.Errorf("search-vulns: status 429: Too many requests"), true},
		{fmt.Errorf("rate limit exceeded"), true},
		{fmt.Errorf("connection refused"), false},
		{fmt.Errorf("status 500: internal server error"), false},
		{nil, false},
	}

	for _, tc := range tests {
		got := isRateLimitError(tc.err)
		if got != tc.want {
			t.Errorf("isRateLimitError(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestPrintPOCErrors_SummarizesByDefault(t *testing.T) {
	verboseMode = false
	defer func() { verboseMode = false }()

	results := []pocResult{
		{cveID: "CVE-2004-0369", err: fmt.Errorf("search-vulns: status 429: {\"message\":\"Too many requests\"}")},
		{cveID: "CVE-2004-0605", err: fmt.Errorf("search-vulns: status 429: {\"message\":\"Too many requests\"}")},
		{cveID: "CVE-2004-0674", err: fmt.Errorf("search-vulns: status 429: {\"message\":\"Too many requests\"}")},
		{cveID: "CVE-2004-9999", err: fmt.Errorf("other-source: connection timeout")},
	}

	output := captureStdout(t, func() { printPOCErrors(results) })

	// Default mode: one summary line, no full errors.
	if !strings.Contains(output, "4 error(s) from search-vulns, other-source") {
		t.Errorf("expected compact summary, got:\n%s", output)
	}
	if strings.Contains(output, "status 429") || strings.Contains(output, "connection timeout") {
		t.Errorf("full errors must be hidden without -v, got:\n%s", output)
	}
}

func TestPrintPOCErrors_VerboseSuppressesDuplicateRateLimits(t *testing.T) {
	verboseMode = true
	defer func() { verboseMode = false }()

	results := []pocResult{
		{cveID: "CVE-2004-0369", err: fmt.Errorf("search-vulns: status 429: {\"message\":\"Too many requests\"}")},
		{cveID: "CVE-2004-0605", err: fmt.Errorf("search-vulns: status 429: {\"message\":\"Too many requests\"}")},
		{cveID: "CVE-2004-0674", err: fmt.Errorf("search-vulns: status 429: {\"message\":\"Too many requests\"}")},
		{cveID: "CVE-2004-9999", err: fmt.Errorf("other-source: connection timeout")},
	}

	output := captureStdout(t, func() { printPOCErrors(results) })

	// Verbose mode: rate limit printed once per source, other errors in full.
	if count429 := strings.Count(output, "rate limit reached"); count429 != 1 {
		t.Errorf("expected 1 rate limit warning, got %d. Output:\n%s", count429, output)
	}
	if !strings.Contains(output, "other-source: connection timeout") {
		t.Errorf("expected non-rate-limit error to be printed. Output:\n%s", output)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	return buf.String()
}

func TestSetOutputFormat(t *testing.T) {
	defer func() { _ = setOutputFormat("table") }()
	for _, ok := range []string{"", "table", "json", "jsonl", "csv", "JSON"} {
		if err := setOutputFormat(ok); err != nil {
			t.Errorf("setOutputFormat(%q) unexpected error: %v", ok, err)
		}
	}
	before := outputFormat
	if err := setOutputFormat("xml"); err == nil {
		t.Errorf("setOutputFormat(\"xml\") expected error, got nil")
	}
	if outputFormat != before {
		t.Errorf("failed validation must not change outputFormat, got %q want %q", outputFormat, before)
	}
}

func TestEmitStructuredJSON(t *testing.T) {
	defer func() { _ = setOutputFormat("table") }()
	if err := setOutputFormat("json"); err != nil {
		t.Fatal(err)
	}

	cves := []cve.Finding{{CVE: "CVE-2023-0001", Source: "NVD", Detail: "a bug", Score: 9.8}}
	pocs := []poc.Finding{{CVE: "CVE-2023-0001", Source: "poc-in-github", Owner: "alice", PushedAt: "2023-01-01", POC: "https://example.com"}}

	out := captureStdout(t, func() {
		if err := emitStructured("curl 7.0", cves, []string{"CVE-2023-0001"}, pocs); err != nil {
			t.Fatalf("emitStructured: %v", err)
		}
	})

	var report structuredReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, out)
	}
	if report.Query != "curl 7.0" {
		t.Errorf("query = %q, want %q", report.Query, "curl 7.0")
	}
	if len(report.CVEFindings) != 1 || report.CVEFindings[0].CVE != "CVE-2023-0001" || report.CVEFindings[0].Score != 9.8 {
		t.Errorf("unexpected cve findings: %+v", report.CVEFindings)
	}
	if len(report.POCFindings) != 1 || report.POCFindings[0].Owner != "alice" {
		t.Errorf("unexpected poc findings: %+v", report.POCFindings)
	}
}

func TestEmitStructuredJSONL(t *testing.T) {
	defer func() { _ = setOutputFormat("table") }()
	if err := setOutputFormat("jsonl"); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		_ = emitStructured("q", []cve.Finding{{CVE: "CVE-1", Source: "NVD"}}, nil, []poc.Finding{{CVE: "CVE-1", Owner: "bob"}})
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 JSONL lines, got %d:\n%s", len(lines), out)
	}
	for i, line := range lines {
		var l jsonlLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			t.Fatalf("line %d invalid JSON: %v", i, err)
		}
	}
}

func TestEmitStructuredCSV(t *testing.T) {
	defer func() { _ = setOutputFormat("table") }()
	if err := setOutputFormat("csv"); err != nil {
		t.Fatal(err)
	}

	cves := []cve.Finding{{CVE: "CVE-1", Source: "NVD", Detail: "d, with comma", Score: 7.5}}
	pocs := []poc.Finding{{CVE: "CVE-1", Source: "search-vulns", Owner: "bob", POC: "u"}}

	out := captureStdout(t, func() {
		_ = emitStructured("q", cves, nil, pocs)
	})

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected header + 2 rows, got %d:\n%s", len(lines), out)
	}
	if lines[0] != "type,cve,source,detail,score,owner,pushed_at,poc,match" {
		t.Errorf("unexpected header: %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "cve,CVE-1,NVD,") {
		t.Errorf("unexpected cve row: %q", lines[1])
	}
	if !strings.HasPrefix(lines[2], "poc,CVE-1,search-vulns,") {
		t.Errorf("unexpected poc row: %q", lines[2])
	}
	if !strings.Contains(lines[1], `"d, with comma"`) {
		t.Errorf("expected comma-containing detail to be quoted, got: %q", lines[1])
	}
}
