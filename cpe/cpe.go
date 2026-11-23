// Package cpe resolves free-form product queries ("apache http server 2.4.39")
// to canonical CPE 2.3 names using the official CPE Dictionary. The resolved
// names let the NVD source query by exact cpeName/virtualMatchString instead
// of keyword search, which eliminates keyword false positives.
package cpe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/Fakechippies/POC-Hunter/db"
)

// ResolveThreshold is the minimum similarity score for a CPE match to be
// used. Conservative on purpose: a wrong CPE silently returns the wrong CVE
// set, which is worse than falling back to keyword search.
const ResolveThreshold = 0.7

const (
	nvdCPESAPI       = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
	vulncheckCPESAPI = "https://api.vulncheck.com/rest/json/cpes/2.0"
)

// CPEDictionary fetcher: token-based (VulnCheck mirror first — 1000 req/min —
// then NVD with an apiKey). Without any token the fetch is not attempted; the
// unauthenticated NVD limit (5 req/30s) makes a full build impractical.
func FetchDictionary(ctx context.Context) ([]db.CPEEntry, error) {
	if token := os.Getenv("VULNCHECK_API_TOKEN"); token != "" {
		return fetchCPEDictionary(ctx, vulncheckCPESAPI, map[string]string{
			"Authorization": "Bearer " + token,
			"Accept":        "application/json",
		})
	}
	if token := os.Getenv("VULNCHECK_API_KEY"); token != "" {
		return fetchCPEDictionary(ctx, vulncheckCPESAPI, map[string]string{
			"Authorization": "Bearer " + token,
			"Accept":        "application/json",
		})
	}
	if key := os.Getenv("NVD_API_KEY"); key != "" {
		return fetchCPEDictionary(ctx, nvdCPESAPI, map[string]string{
			"apiKey": key,
			"Accept": "application/json",
		})
	}
	return nil, fmt.Errorf("cpe: dictionary build needs VULNCHECK_API_TOKEN (preferred) or NVD_API_KEY")
}

type cpeAPIPage struct {
	TotalResults   int `json:"totalResults"`
	ResultsPerPage int `json:"resultsPerPage"`
	Products       []struct {
		CPE struct {
			CPEName string `json:"cpeName"`
			Titles  []struct {
				Title string `json:"title"`
				Lang  string `json:"lang"`
			} `json:"titles"`
			Deprecated bool `json:"deprecated"`
		} `json:"cpe"`
	} `json:"products"`
}

// fetchCPEDictionary pages the CPE API (max 2000 per page; ~941 pages for
// 1.88M records) and dedupes to one entry per product prefix.
func fetchCPEDictionary(ctx context.Context, baseURL string, headers map[string]string) ([]db.CPEEntry, error) {
	client := &http.Client{}
	dedup := map[string]*db.CPEEntry{}

	const perPage = 2000
	start := 0
	for {
		url := fmt.Sprintf("%s?resultsPerPage=%d&startIndex=%d", baseURL, perPage, start)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("status %d at startIndex=%d", resp.StatusCode, start)
		}

		var page cpeAPIPage
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decode page at startIndex=%d: %w", start, err)
		}
		for _, p := range page.Products {
			name := p.CPE.CPEName
			if name == "" {
				continue
			}
			prefix := cpePrefix(name)
			if prefix == "" {
				continue
			}
			e, ok := dedup[prefix]
			if !ok {
				vendor, product := prefixParts(prefix)
				e = &db.CPEEntry{Prefix: prefix, Vendor: vendor, Product: product}
				dedup[prefix] = e
			}
			e.Versions++
			if e.Title == "" {
				for _, t := range p.CPE.Titles {
					if t.Lang == "en" || len(p.CPE.Titles) == 1 {
						e.Title = t.Title
						break
					}
				}
			}
		}
		if len(page.Products) == 0 || start+len(page.Products) >= page.TotalResults {
			break
		}
		start += len(page.Products)
	}

	entries := make([]db.CPEEntry, 0, len(dedup))
	for _, e := range dedup {
		entries = append(entries, *e)
	}
	return entries, nil
}

// cpePrefix returns the first five components of a CPE 2.3 name
// ("cpe:2.3:part:vendor:product"), or "" if the name is malformed.
func cpePrefix(name string) string {
	parts := strings.Split(name, ":")
	if len(parts) < 5 {
		return ""
	}
	return strings.Join(parts[:5], ":")
}

func prefixParts(prefix string) (vendor, product string) {
	parts := strings.Split(prefix, ":")
	if len(parts) >= 5 {
		return parts[3], parts[4]
	}
	return "", ""
}
