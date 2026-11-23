package poc

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Fakechippies/pochunter/db"
)

const trickestURL = "https://raw.githubusercontent.com/trickest/cve/main/github.txt"

// trickestCVEName reuses the shared CVE-name validation; placeholders like
// CVE-0000-0000 in the upstream file are rejected.
var trickestCVEName = cveNameRe

// Trickest maps CVE IDs to public GitHub PoC repositories using the
// trickest/cve repo's github.txt (flat "CVE - URL" lines) as a local bulk
// index. No auth needed; the raw URL is not meaningfully rate-limited.
type Trickest struct {
	BulkSource
}

func (t *Trickest) Name() string { return t.BulkSource.Name }

func NewTrickest(d *db.DB) *Trickest {
	return &Trickest{BulkSource{
		Name:  "trickest",
		DB:    d,
		Fetch: fetchTrickest,
		Head:  fetchTrickestRev,
		Parse: parseTrickest,
	}}
}

func fetchTrickest(ctx context.Context) ([]byte, string, error) {
	return fetchRawGitHub(ctx, trickestURL)
}

func fetchTrickestRev(ctx context.Context) (string, error) {
	return headRawGitHub(ctx, trickestURL)
}

// parseTrickest parses "CVE-YYYY-NNNN - https://github.com/owner/repo" lines.
// Junk placeholders (CVE-0000-0000) and malformed lines are skipped.
func parseTrickest(body []byte) ([]db.IndexPOCRow, error) {
	var rows []db.IndexPOCRow
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.Contains(line, " - ") {
			continue
		}
		parts := strings.SplitN(line, " - ", 2)
		cve, url := strings.TrimSpace(parts[0]), db.CanonicalURL(strings.TrimSpace(parts[1]))
		if !trickestCVEName.MatchString(cve) || url == "" {
			continue
		}
		rows = append(rows, db.IndexPOCRow{CVE: cve, URL: url})
	}
	return rows, sc.Err()
}

// fetchRawGitHub is the shared download helper for raw.githubusercontent.com
// sources: plain GET, ETag (or Last-Modified) as revision marker.
func fetchRawGitHub(ctx context.Context, url string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("unexpected status %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	return body, revisionHeaders(resp.Header), nil
}

// headRawGitHub probes the current revision of a raw.githubusercontent.com
// file without downloading the body.
func headRawGitHub(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %s", resp.Status)
	}
	rev := revisionHeaders(resp.Header)
	if rev == "" {
		return "", fmt.Errorf("no revision headers")
	}
	return rev, nil
}
