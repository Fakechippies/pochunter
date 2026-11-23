package poc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/Fakechippies/pochunter/db"
)

const nucleiURL = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"

// Nuclei maps CVE IDs to projectdiscovery/nuclei-templates using the repo's
// cves.json (~2.4 MB) as a local bulk index. The file is newline-delimited
// JSON; the top-level ID *is* the CVE ID and file_path points at the template
// YAML. Coverage is template-only (high signal, ~5k CVEs).
type Nuclei struct {
	BulkSource
}

func (n *Nuclei) Name() string { return n.BulkSource.Name }

func NewNuclei(d *db.DB) *Nuclei {
	return &Nuclei{BulkSource{
		Name:  "nuclei",
		DB:    d,
		Fetch: fetchNuclei,
		Head:  fetchNucleiRev,
		Parse: parseNuclei,
	}}
}

func fetchNuclei(ctx context.Context) ([]byte, string, error) {
	return fetchRawGitHub(ctx, nucleiURL)
}

func fetchNucleiRev(ctx context.Context) (string, error) {
	return headRawGitHub(ctx, nucleiURL)
}

type nucleiTemplate struct {
	ID   string `json:"ID"`
	Info struct {
		Name     string `json:"Name"`
		Severity string `json:"Severity"`
	} `json:"Info"`
	FilePath string `json:"file_path"`
}

// parseNuclei parses NDJSON lines into one row per template. Descriptions
// can contain newlines, so lines must be parsed as JSON, not split by regex.
func parseNuclei(body []byte) ([]db.IndexPOCRow, error) {
	var rows []db.IndexPOCRow
	sc := bufio.NewScanner(bytes.NewReader(body))
	// Long descriptions: allow up to 4 MB per line.
	sc.Buffer(make([]byte, 0, 64*1024), 1<<22)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var t nucleiTemplate
		if err := json.Unmarshal(line, &t); err != nil {
			continue // skip malformed lines, keep parsing the rest
		}
		if !cveNameRe.MatchString(t.ID) || t.FilePath == "" {
			continue
		}
		rows = append(rows, db.IndexPOCRow{
			CVE:    t.ID,
			URL:    "https://github.com/projectdiscovery/nuclei-templates/blob/main/" + strings.TrimPrefix(t.FilePath, "/"),
			Detail: t.Info.Name,
		})
	}
	return rows, sc.Err()
}

// cveNameRe matches real CVE identifiers: years 1999..2099 (CVE records
// start in 1999) and 4..7 digit sequences. Rejects placeholders like
// CVE-0000-0000 found in upstream files.
var cveNameRe = regexp.MustCompile(`^CVE-(1999|20\d{2})-\d{4,7}$`)
