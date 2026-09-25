package cve

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/Fakechippies/pochunter/httpclient"
	"github.com/Fakechippies/pochunter/versioncanon"
)

var cveAliases = map[string]string{
	"shellshock": "bash",
	"heartbleed": "openssl",
	"meltdown":   "intel processors",
	"spectre":    "intel processors",
	"poodle":     "ssl 3.0",
	"drown":      "openssl",
	"logjam":     "diffie-hellman",
	"freak":      "openssl",
}

type NVDSource struct{}

func (o NVDSource) Name() string { return "NVD" }

type nvdItem struct {
	id     string
	detail string
	score  float64
	cpes   []nvdCPE
}

type nvdCPE struct {
	criteria string
	startInc string
	startExc string
	endInc   string
	endExc   string
}

func (o NVDSource) Query(ctx context.Context, vendor, product, version, ecosystem string) ([]Finding, error) {
	// If version is not set, check if the product string contains an embedded version (e.g. "curl 7.0")
	if version == "" {
		if app, ver := versioncanon.ExtractAppAndVersion(product); ver != "" {
			product = app
			version = ver
		}
	}

	if version == "" {
		return o.freeFormQuery(ctx, product)
	}

	return o.queryByProductAndVersion(ctx, product, version)
}

func (o NVDSource) queryByProductAndVersion(ctx context.Context, product, version string) ([]Finding, error) {
	// 1. Query NVD for the product to retrieve candidate CVEs with full CPE metadata
	items, err := o.queryRawNVD(ctx, product)
	if err != nil {
		return nil, err
	}

	filtered := filterNVDItems(items, product, version)
	if len(filtered) > 0 {
		return filtered, nil
	}

	// 2. Fallback: targeted keyword search with product + version
	targetedItems, err := o.queryRawNVD(ctx, product+" "+version)
	if err == nil && len(targetedItems) > 0 {
		targetedFiltered := filterNVDItems(targetedItems, product, version)
		if len(targetedFiltered) > 0 {
			return targetedFiltered, nil
		}
	}

	// 3. Fallback: check aliases if any
	if alias, ok := cveAliases[strings.ToLower(strings.TrimSpace(product))]; ok {
		aliasItems, aliasErr := o.queryRawNVD(ctx, alias)
		if aliasErr == nil && len(aliasItems) > 0 {
			aliasFiltered := filterNVDItems(aliasItems, alias, version)
			if len(aliasFiltered) > 0 {
				return aliasFiltered, nil
			}
		}
	}

	return nil, nil
}

func (o NVDSource) freeFormQuery(ctx context.Context, keyword string) ([]Finding, error) {
	findings, err := o.queryByKeyword(ctx, keyword)
	if err != nil {
		return nil, err
	}
	if len(findings) > 0 {
		return findings, nil
	}

	if alias, ok := cveAliases[strings.ToLower(strings.TrimSpace(keyword))]; ok {
		aliasResults, aliasErr := o.queryByKeyword(ctx, alias)
		if aliasErr == nil && len(aliasResults) > 0 {
			return aliasResults, nil
		}
	}

	words := strings.Fields(keyword)
	if len(words) <= 1 {
		return nil, nil
	}

	seen := make(map[string]struct{})
	for _, word := range words {
		// Skip tokens that are versions, pure numbers, or stop words to avoid querying random things
		if len(word) < 3 || versioncanon.IsVersion(word) || isPureNumber(word) || isStopWord(word) {
			continue
		}
		wordResults, err := o.queryByKeyword(ctx, word)
		if err != nil {
			continue
		}
		for _, f := range wordResults {
			key := f.CVE + "|" + f.Source + "|" + f.Detail
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				findings = append(findings, f)
			}
		}
	}
	return findings, nil
}

func (o NVDSource) queryRawNVD(ctx context.Context, keyword string) ([]nvdItem, error) {
	URL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=200",
		url.QueryEscape(strings.TrimSpace(keyword)),
	)
	var nvdResp struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics *struct {
					CvssMetricV31 []struct {
						CvssData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CvssMetricV30 []struct {
						CvssData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV30"`
					CvssMetricV2 []struct {
						CvssData struct {
							BaseScore float64 `json:"baseScore"`
						} `json:"cvssData"`
					} `json:"cvssMetricV2"`
				} `json:"metrics"`
				Configurations []struct {
					Nodes []struct {
						CPEMatch []struct {
							Vulnerable            bool   `json:"vulnerable"`
							Criteria              string `json:"criteria"`
							VersionStartIncluding string `json:"versionStartIncluding"`
							VersionStartExcluding string `json:"versionStartExcluding"`
							VersionEndIncluding   string `json:"versionEndIncluding"`
							VersionEndExcluding   string `json:"versionEndExcluding"`
						} `json:"cpeMatch"`
					} `json:"nodes"`
				} `json:"configurations"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	err := httpclient.JSON(ctx, "GET", URL, nil, nil, &nvdResp)
	if err != nil {
		return nil, err
	}

	var items []nvdItem
	for _, vuln := range nvdResp.Vulnerabilities {
		var item nvdItem
		item.id = vuln.CVE.ID
		for _, d := range vuln.CVE.Descriptions {
			if d.Lang == "en" {
				item.detail = d.Value
				break
			}
		}
		if vuln.CVE.Metrics != nil {
			if len(vuln.CVE.Metrics.CvssMetricV31) > 0 {
				item.score = vuln.CVE.Metrics.CvssMetricV31[0].CvssData.BaseScore
			} else if len(vuln.CVE.Metrics.CvssMetricV30) > 0 {
				item.score = vuln.CVE.Metrics.CvssMetricV30[0].CvssData.BaseScore
			} else if len(vuln.CVE.Metrics.CvssMetricV2) > 0 {
				item.score = vuln.CVE.Metrics.CvssMetricV2[0].CvssData.BaseScore
			}
		}
		for _, conf := range vuln.CVE.Configurations {
			for _, node := range conf.Nodes {
				for _, m := range node.CPEMatch {
					if m.Vulnerable {
						item.cpes = append(item.cpes, nvdCPE{
							criteria: m.Criteria,
							startInc: m.VersionStartIncluding,
							startExc: m.VersionStartExcluding,
							endInc:   m.VersionEndIncluding,
							endExc:   m.VersionEndExcluding,
						})
					}
				}
			}
		}
		items = append(items, item)
	}

	return items, nil
}

func (o NVDSource) queryByKeyword(ctx context.Context, keyword string) ([]Finding, error) {
	items, err := o.queryRawNVD(ctx, keyword)
	if err != nil {
		return nil, err
	}
	findings := make([]Finding, len(items))
	for i, item := range items {
		findings[i] = Finding{
			CVE:    item.id,
			Source: o.Name(),
			Detail: item.detail,
			Score:  item.score,
		}
	}
	return findings, nil
}

func filterNVDItems(items []nvdItem, product, version string) []Finding {
	productLower := strings.ToLower(strings.TrimSpace(product))
	var findings []Finding

	for _, item := range items {
		if !matchesProductAndVersion(item, productLower, version) {
			continue
		}
		findings = append(findings, Finding{
			CVE:    item.id,
			Source: "NVD",
			Detail: item.detail,
			Score:  item.score,
		})
	}

	return findings
}

func matchesProductAndVersion(item nvdItem, productLower, version string) bool {
	hasCPE := len(item.cpes) > 0
	cpeProductMatched := false
	cpeVersionMatched := false

	for _, cpe := range item.cpes {
		// CPE format: cpe:2.3:part:vendor:product:version:...
		parts := strings.Split(cpe.criteria, ":")
		if len(parts) >= 5 {
			cpeProd := strings.ToLower(parts[4])
			if isProductMatch(cpeProd, productLower) {
				cpeProductMatched = true
				if version == "" {
					return true
				}

				// Check exact or variant version in criteria
				if len(parts) >= 6 {
					cpeVer := parts[5]
					if cpeVer != "" && cpeVer != "*" && cpeVer != "-" {
						if versioncanon.Compare(version, cpeVer) == 0 {
							cpeVersionMatched = true
							break
						}
					}
				}

				// Check version range
				if cpe.startInc != "" || cpe.startExc != "" || cpe.endInc != "" || cpe.endExc != "" {
					if versioncanon.MatchesRange(version, cpe.startInc, cpe.startExc, cpe.endInc, cpe.endExc) {
						cpeVersionMatched = true
						break
					}
				}
			}
		}
	}

	if cpeVersionMatched {
		return true
	}

	// If CPEs exist but none matched the product, this CVE is for another software
	if hasCPE && !cpeProductMatched {
		return false
	}

	// Description fallback: verify product and version match in description
	descLower := strings.ToLower(item.detail)
	if !containsWord(descLower, productLower) && !containsWord(descLower, "lib"+productLower) {
		return false
	}

	if version != "" {
		return versioncanon.MatchVersionInText(item.detail, version)
	}

	return true
}

func isProductMatch(cpeProd, userProd string) bool {
	cp := strings.ToLower(strings.TrimSpace(cpeProd))
	up := strings.ToLower(strings.TrimSpace(userProd))
	if cp == up {
		return true
	}
	if cp == "lib"+up || up == "lib"+cp {
		return true
	}
	// Normalize spaces, dashes and underscores
	cpNorm := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(cp, "-", ""), "_", ""), " ", "")
	upNorm := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(up, "-", ""), "_", ""), " ", "")
	if cpNorm == upNorm {
		return true
	}
	if strings.Contains(cpNorm, upNorm) || strings.Contains(upNorm, cpNorm) {
		return true
	}
	return false
}

func containsWord(text, word string) bool {
	idx := 0
	for {
		pos := strings.Index(text[idx:], word)
		if pos == -1 {
			return false
		}
		absPos := idx + pos
		endPos := absPos + len(word)
		idx = endPos

		validBefore := absPos == 0 || !isAlnum(text[absPos-1])
		validAfter := endPos == len(text) || !isAlnum(text[endPos])
		if validBefore && validAfter {
			return true
		}
	}
}

func isAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_'
}

func isPureNumber(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

func isStopWord(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "for", "the", "and", "with", "from", "version", "ver", "all", "cve", "vuln", "vulnerability":
		return true
	default:
		return false
	}
}
