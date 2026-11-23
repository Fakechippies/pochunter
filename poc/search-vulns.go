package poc

import (
	"context"
	"fmt"

	"github.com/Fakechippies/pochunter/db"
	"github.com/Fakechippies/pochunter/httpclient"
)

type SearchVulns struct {
	APIKey string
}

func (o SearchVulns) Name() string { return "search-vulns" }

func (o SearchVulns) Query(ctx context.Context, CVE string) ([]Finding, error) {
	if o.APIKey == "" {
		return nil, fmt.Errorf("API key needed for search-vulns.com")
		// Not standarized; use: SEARCHVULNS_API_KEY
	}

	URL := "https://search-vulns.com/api/search-vulns?query=" + CVE

	var searchVulnResp struct {
		Vulns map[string]struct {
			Exploits []string `json:"exploits"`
		} `json:"vulns"`
	}

	if err := httpclient.JSON(ctx, "GET", URL, map[string]string{"API-Key": o.APIKey}, nil, &searchVulnResp); err != nil {
		return nil, err
	}

	var findings []Finding
	for _, v := range searchVulnResp.Vulns {
		for _, poc := range v.Exploits {
			findings = append(findings, Finding{CVE: CVE, Owner: db.ExtractOwner(poc), POC: poc, PushedAt: "-", Source: "search-vulns"})
		}
	}

	return findings, nil
}
