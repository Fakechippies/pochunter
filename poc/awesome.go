package poc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Fakechippies/POC-Hunter/db"
)

const awesomeURLBase = "https://raw.githubusercontent.com/hackthacker-sec/Awesome-CVE-POC-Index/main/cve_"

// AwesomeCVEPOC maps CVE IDs to public PoC links from the
// Awesome-CVE-POC-Index repo: eleven per-year markdown files (cve_2016 …
// cve_2026), each a table of CVE IDs and HTML anchors. Highest-coverage but
// lowest-quality source; expect junk entries.
type AwesomeCVEPOC struct {
	BulkSource

	// Years is the inclusive range of per-year files to fetch. Overridable in
	// tests; defaults to 2016..2026.
	FirstYear, LastYear int
}

func (a *AwesomeCVEPOC) Name() string { return a.BulkSource.Name }

func NewAwesomeCVEPOC(d *db.DB) *AwesomeCVEPOC {
	a := &AwesomeCVEPOC{BulkSource: BulkSource{
		Name:  "awesome-cve-poc",
		DB:    d,
		Parse: parseAwesome,
	}}
	a.Fetch = a.fetchAll
	a.Head = a.headAll
	return a
}

// years returns the configured inclusive year range.
func (a *AwesomeCVEPOC) years() (int, int) {
	first, last := a.FirstYear, a.LastYear
	if first == 0 {
		first = 2016
	}
	if last == 0 {
		last = 2026
	}
	return first, last
}

func (a *AwesomeCVEPOC) url(year int) string {
	return awesomeURLBase + strconv.Itoa(year) + "/README.md"
}

func (a *AwesomeCVEPOC) fetchAll(ctx context.Context) ([]byte, string, error) {
	first, last := a.years()
	var buf bytes.Buffer
	var etags []string
	for year := first; year <= last; year++ {
		body, rev, err := fetchRawGitHub(ctx, a.url(year))
		if err != nil {
			return nil, "", fmt.Errorf("year %d: %w", year, err)
		}
		buf.Write(body)
		buf.WriteByte('\n')
		etags = append(etags, rev)
	}
	// Combined revision: the SHA-256 over all per-file ETags.
	sum := sha256.Sum256([]byte(strings.Join(etags, "|")))
	return buf.Bytes(), hex.EncodeToString(sum[:]), nil
}

func (a *AwesomeCVEPOC) headAll(ctx context.Context) (string, error) {
	first, last := a.years()
	var etags []string
	for year := first; year <= last; year++ {
		rev, err := headRawGitHub(ctx, a.url(year))
		if err != nil {
			return "", fmt.Errorf("year %d: %w", year, err)
		}
		etags = append(etags, rev)
	}
	sum := sha256.Sum256([]byte(strings.Join(etags, "|")))
	return hex.EncodeToString(sum[:]), nil
}

var (
	awesomeCVEMark = regexp.MustCompile(`\*\*(CVE-\d{4}-\d+)\*\*`)
	awesomeHREF    = regexp.MustCompile(`href="([^"]+)"`)
)

// parseAwesome extracts CVE IDs (bold markers) and PoC links (HTML anchors)
// from the markdown table rows. Several links may share one row.
func parseAwesome(body []byte) ([]db.IndexPOCRow, error) {
	var rows []db.IndexPOCRow
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			continue
		}
		m := awesomeCVEMark.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		cve := m[1]
		for _, href := range awesomeHREF.FindAllStringSubmatch(trimmed, -1) {
			url := db.CanonicalURL(href[1])
			if url == "" {
				continue
			}
			rows = append(rows, db.IndexPOCRow{CVE: cve, URL: url})
		}
	}
	return rows, nil
}
