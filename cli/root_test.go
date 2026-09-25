package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
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

func TestPrintPOCErrors_SuppressesDuplicateRateLimits(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	results := []pocResult{
		{
			cveID: "CVE-2004-0369",
			err:   fmt.Errorf("search-vulns: status 429: {\"message\":\"Too many requests\"}"),
		},
		{
			cveID: "CVE-2004-0605",
			err:   fmt.Errorf("search-vulns: status 429: {\"message\":\"Too many requests\"}"),
		},
		{
			cveID: "CVE-2004-0674",
			err:   fmt.Errorf("search-vulns: status 429: {\"message\":\"Too many requests\"}"),
		},
		{
			cveID: "CVE-2004-9999",
			err:   fmt.Errorf("other-source: connection timeout"),
		},
	}

	printPOCErrors(results)

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	// Should only mention 429 / rate limit once
	count429 := strings.Count(output, "rate limit reached")
	if count429 != 1 {
		t.Errorf("expected 1 rate limit warning, got %d. Output:\n%s", count429, output)
	}

	// Should print the non-rate-limit error normally
	if !strings.Contains(output, "other-source: connection timeout") {
		t.Errorf("expected non-rate-limit error to be printed. Output:\n%s", output)
	}
}
