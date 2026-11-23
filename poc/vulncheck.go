package poc

import (
	"context"
	"fmt"
	"strings"

	"github.com/Fakechippies/pochunter/db"
	"github.com/Fakechippies/pochunter/httpclient"
)

const vulncheckBaseURL = "https://api.vulncheck.com/v3/index/"

// vulncheckHeaders builds the auth headers shared by all VulnCheck calls.
func vulncheckHeaders(apiKey string) map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + apiKey,
		"Accept":        "application/json",
	}
}

// VulnCheckXDB maps CVE IDs to VulnCheck XDB entries (community exploit
// intelligence). On-demand API source; community tier allows 1000 requests
// per minute and results are cached by the standard POC cache decorator.
type VulnCheckXDB struct {
	APIKey string
}

func (v VulnCheckXDB) Name() string { return "vulncheck-xdb" }

func (v VulnCheckXDB) Query(ctx context.Context, CVE string) ([]Finding, error) {
	if v.APIKey == "" {
		return nil, fmt.Errorf("API key needed for vulncheck (set VULNCHECK_API_TOKEN)")
	}
	url := vulncheckBaseURL + "xdb?cve=" + CVE

	var resp struct {
		Data []vulncheckXDBEntry `json:"data"`
	}
	if err := httpclient.JSON(ctx, "GET", url, vulncheckHeaders(v.APIKey), nil, &resp); err != nil {
		return nil, err
	}
	return vulncheckXDBFindings(CVE, resp.Data), nil
}

type vulncheckXDBEntry struct {
	XdbID       string `json:"xdb_id"`
	XdbURL      string `json:"xdb_url"`
	DateAdded   string `json:"date_added"`
	ExploitType string `json:"exploit_type"`
	CloneSSHURL string `json:"clone_ssh_url"`
}

func vulncheckXDBFindings(cve string, entries []vulncheckXDBEntry) []Finding {
	var findings []Finding
	for _, e := range entries {
		// Prefer the actual repository over the XDB landing page.
		pocURL := sshCloneToHTTPS(e.CloneSSHURL)
		if pocURL == "" {
			pocURL = e.XdbURL
		}
		findings = append(findings, Finding{
			CVE:      cve,
			POC:      pocURL,
			Owner:    db.ExtractOwner(pocURL),
			PushedAt: db.NormalizeDate(e.DateAdded),
			Source:   "vulncheck-xdb",
		})
	}
	return findings
}

// sshCloneToHTTPS converts "git@github.com:owner/repo.git" into a browsable
// https URL. Non-GitHub SSH remotes are converted the same way; unparseable
// input yields "".
func sshCloneToHTTPS(ssh string) string {
	s := strings.TrimSpace(ssh)
	if s == "" {
		return ""
	}
	s = strings.TrimSuffix(s, ".git")
	rest, ok := strings.CutPrefix(s, "git@")
	if !ok {
		return ""
	}
	host, path, found := strings.Cut(rest, ":")
	if !found || host == "" || path == "" {
		return ""
	}
	return "https://" + host + "/" + strings.TrimPrefix(path, "/")
}

// VulnCheckIAC maps CVE IDs to VulnCheck's Initial Access Community artifacts
// (exploits, PCAPs, detection rules) via the initial-access-community index.
// Same token as XDB; coverage is intentionally small (~50 CVEs) but the
// artifacts are high-quality.
type VulnCheckIAC struct {
	APIKey string
}

func (v VulnCheckIAC) Name() string { return "vulncheck-iac" }

func (v VulnCheckIAC) Query(ctx context.Context, CVE string) ([]Finding, error) {
	if v.APIKey == "" {
		return nil, fmt.Errorf("API key needed for vulncheck (set VULNCHECK_API_TOKEN)")
	}
	url := vulncheckBaseURL + "initial-access-community?cve=" + CVE
	headers := vulncheckHeaders(v.APIKey)

	var resp struct {
		Data []struct {
			CVE       string `json:"cve"`
			Artifacts []struct {
				ArtifactName string   `json:"artifactName"`
				DateAdded    string   `json:"dateAdded"`
				ArtifactsURL []string `json:"artifactsURL"`
			} `json:"artifacts"`
		} `json:"data"`
	}
	if err := httpclient.JSON(ctx, "GET", url, headers, nil, &resp); err != nil {
		return nil, err
	}

	var findings []Finding
	for _, entry := range resp.Data {
		for _, art := range entry.Artifacts {
			// The browsable GitHub tree is the most useful link; the exploit
			// binary/launcher name is a fallback detail.
			pocURL := ""
			if len(art.ArtifactsURL) > 0 {
				pocURL = art.ArtifactsURL[0]
			}
			if pocURL == "" {
				continue
			}
			findings = append(findings, Finding{
				CVE:      CVE,
				POC:      pocURL,
				Owner:    db.ExtractOwner(pocURL),
				PushedAt: db.NormalizeDate(art.DateAdded),
				Source:   "vulncheck-iac",
			})
		}
	}
	return findings, nil
}

// VulnCheckKEV fetches VulnCheck's extended KEV (CISA KEV plus VulnCheck
// enrichment, ~6k records). It is not a poc.Source: the data is used for
// bulk enrichment of the local CVE table (kev flag), refreshed via
// `pochunter update vulncheck-kev`. Community-tier entitled.
type VulnCheckKEV struct {
	APIKey string
}

func (v VulnCheckKEV) Name() string { return "vulncheck-kev" }

type vulncheckKEVEntry struct {
	CVE []string `json:"cve"`
}

// FetchAll retrieves every KEV record by page-paginating the index (1000 per
// page, ~7 pages today). The cve field is an array of aliases.
func (v VulnCheckKEV) FetchAll(ctx context.Context) ([]vulncheckKEVEntry, error) {
	if v.APIKey == "" {
		return nil, fmt.Errorf("API key needed for vulncheck (set VULNCHECK_API_TOKEN)")
	}

	var all []vulncheckKEVEntry
	for page := 1; ; page++ {
		url := fmt.Sprintf("%svulncheck-kev?limit=1000&page=%d", vulncheckBaseURL, page)
		var resp struct {
			Data []vulncheckKEVEntry `json:"data"`
			Meta struct {
				Page       int `json:"page"`
				TotalPages int `json:"total_pages"`
			} `json:"_meta"`
		}
		if err := httpclient.JSON(ctx, "GET", url, vulncheckHeaders(v.APIKey), nil, &resp); err != nil {
			return nil, err
		}
		all = append(all, resp.Data...)
		if len(resp.Data) == 0 || resp.Meta.Page >= resp.Meta.TotalPages || page > 100 {
			break
		}
	}
	return all, nil
}
