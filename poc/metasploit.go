package poc

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/Fakechippies/POC-Hunter/db"
)

const metasploitURL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"

// Metasploit maps CVE IDs to Metasploit Framework modules using
// modules_metadata_base.json (~11 MB, one-time download) as a local bulk
// index. CVE IDs live in each module's references[] array (there is no cve
// field); top-level keys are mangled fullnames, so use the fullname field.
type Metasploit struct {
	BulkSource
}

func (m *Metasploit) Name() string { return m.BulkSource.Name }

func NewMetasploit(d *db.DB) *Metasploit {
	return &Metasploit{BulkSource{
		Name:  "metasploit",
		DB:    d,
		Fetch: fetchMetasploit,
		Head:  fetchMetasploitRev,
		Parse: parseMetasploit,
	}}
}

func fetchMetasploit(ctx context.Context) ([]byte, string, error) {
	return fetchRawGitHub(ctx, metasploitURL)
}

func fetchMetasploitRev(ctx context.Context) (string, error) {
	return headRawGitHub(ctx, metasploitURL)
}

type msfModule struct {
	Fullname       string   `json:"fullname"`
	Name           string   `json:"name"`
	Type           string   `json:"type"`
	DisclosureDate string   `json:"disclosure_date"`
	References     []string `json:"references"`
}

// parseMetasploit extracts one row per (module, CVE reference). Module URLs
// follow the Rapid7 module page pattern; the disclosure date doubles as
// PushedAt. Non-CVE references (OSVDB-*, EDB-*, ...) are ignored.
func parseMetasploit(body []byte) ([]db.IndexPOCRow, error) {
	var modules map[string]msfModule
	if err := json.Unmarshal(body, &modules); err != nil {
		return nil, err
	}

	var rows []db.IndexPOCRow
	for _, m := range modules {
		url := "https://www.rapid7.com/db/modules/" + m.Fullname + "/"
		for _, ref := range m.References {
			if !strings.HasPrefix(ref, "CVE-") {
				continue
			}
			rows = append(rows, db.IndexPOCRow{
				CVE:      ref,
				URL:      url,
				Detail:   m.Name,
				PushedAt: db.NormalizeDate(m.DisclosureDate),
			})
		}
	}
	return rows, nil
}
