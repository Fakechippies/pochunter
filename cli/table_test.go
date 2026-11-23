package cli

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Fakechippies/POC-Hunter/poc"
)

var ansiRe = regexp.MustCompile(`\033\[[0-9;]*m`)

// TestPOCTableAlignmentColored asserts that ANSI colors never shift the POC
// table's columns: with colors forced on, the visible (ANSI-stripped)
// separator positions of the header and data rows must be identical.
func TestPOCTableAlignmentColored(t *testing.T) {
	old := colorEnabled
	colorEnabled = true
	defer func() { colorEnabled = old }()

	findings := []poc.Finding{
		{CVE: "CVE-1", Source: "trickest", POC: "https://github.com/a/b"},
		{CVE: "CVE-1", Source: "search-vulns", Owner: "a", POC: "http://github.com/a/b/"},
		{CVE: "CVE-22222222-111111", Source: "exploitdb", PushedAt: "2024-01-01T00:00:00Z", POC: "https://www.exploit-db.com/exploits/1"},
	}

	out := captureStdout(t, func() { printPOCFindings("POC Discovery", findings) })
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 { // progress + success + header + 2 data rows... progress lines go to stdout too
		// progressf/successf also write here; find the header line instead.
	}
	var header string
	var data []string
	for _, l := range lines {
		stripped := ansiRe.ReplaceAllString(l, "")
		switch {
		case strings.HasPrefix(stripped, "CVE\t") || strings.HasPrefix(stripped, "CVE ") && strings.Contains(stripped, "SOURCES"):
			header = stripped
		case strings.HasPrefix(stripped, "CVE-"):
			data = append(data, stripped)
		}
	}
	if header == "" || len(data) < 2 {
		t.Fatalf("could not locate header/data lines in:\n%s", out)
	}

	hsep := cellSepRe.FindAllStringIndex(header, -1)
	for _, d := range data {
		dsep := cellSepRe.FindAllStringIndex(d, -1)
		// Stacked multi-source rows end with an extra whitespace run from
		// the  continuation marker; one extra separator is expected.
		if len(dsep) != len(hsep) && len(dsep) != len(hsep)+1 {
			t.Errorf("cell count mismatch: header %d, row %d\nheader: %q\nrow:    %q", len(hsep), len(dsep), header, d)
			continue
		}
		// Cells are left-aligned and padded to the column width, so the
		// separator START shifts with cell length; the END (== start of the
		// next column) must be identical across rows. Stacked multi-source
		// rows carry a trailing whitespace run that is not a column
		// boundary, so each line's LAST separator is skipped.
		last := min(len(hsep), len(dsep)) - 1
		for i := 0; i < last; i++ {
			if hsep[i][1] != dsep[i][1] {
				t.Errorf("column %d misaligned: header cell ends at %d, row cell ends at %d\nheader: %q\nrow:    %q", i, hsep[i][1], dsep[i][1], header, d)
			}
		}
	}
}
