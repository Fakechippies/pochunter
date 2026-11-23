package poc

import (
	"bufio"
	"bytes"
	"context"
	"regexp"
	"strings"

	"github.com/Fakechippies/pochunter/db"
)

const tg12URL = "https://raw.githubusercontent.com/tg12/PoC_CVEs/main/cve_links.txt"

// Tg12 maps CVE IDs to public PoC repository links from tg12/PoC_CVEs. The
// machine-readable index is cve_links.txt (~5.7 MB, ASCII box format); the
// sibling cve_links.csv is empty upstream and must not be used.
type Tg12 struct {
	BulkSource
}

func (t *Tg12) Name() string { return t.BulkSource.Name }

func NewTg12(d *db.DB) *Tg12 {
	return &Tg12{BulkSource{
		Name:  "tg12",
		DB:    d,
		Fetch: fetchTg12,
		Head:  fetchTg12Rev,
		Parse: parseTg12,
	}}
}

func fetchTg12(ctx context.Context) ([]byte, string, error) {
	return fetchRawGitHub(ctx, tg12URL)
}

func fetchTg12Rev(ctx context.Context) (string, error) {
	return headRawGitHub(ctx, tg12URL)
}

var tg12URLPrefix = regexp.MustCompile(`^https?://\S+$`)

// parseTg12 parses the ASCII box format: a "| CVE-YYYY-NNNN |" line starts a
// group, and the following "| https://... |" lines are that CVE's links.
// Lines outside the boxes (preamble, separators) are skipped.
func parseTg12(body []byte) ([]db.IndexPOCRow, error) {
	var rows []db.IndexPOCRow
	current := ""

	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.Trim(sc.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") || !strings.HasSuffix(trimmed, "|") {
			continue
		}
		inner := strings.TrimSpace(strings.Trim(trimmed, "|"))
		switch {
		case cveNameRe.MatchString(inner):
			current = inner
		case current != "" && tg12URLPrefix.MatchString(inner):
			rows = append(rows, db.IndexPOCRow{CVE: current, URL: inner})
		}
	}
	return rows, sc.Err()
}
