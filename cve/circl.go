package cve

import (
	"context"
	"fmt"
	"strings"

	"github.com/Fakechippies/POC-Hunter/httpclient"
	"github.com/Fakechippies/POC-Hunter/versioncanon"
)

type CIRCLSource struct{}

func (o CIRCLSource) Name() string { return "CIRCL" }

func (o CIRCLSource) Query(ctx context.Context, vendor, product, version, ecosystem string) ([]Finding, error) {
	if version == "" {
		if app, ver := versioncanon.ExtractAppAndVersion(product); ver != "" {
			product = app
			version = ver
		}
	}

	if vendor == "" {
		vendor = product // fallback: some CIRCL endpoints tolerate vendor == product
	}

	url := fmt.Sprintf("https://cve.circl.lu/api/search/%s/%s", vendor, product)

	var circlResp struct {
		Results map[string][][]interface{} `json:"results"`
	}

	if err := httpclient.JSON(ctx, "GET", url, nil, nil, &circlResp); err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	var findings []Finding
	for _, entries := range circlResp.Results {
		for _, entry := range entries {
			if len(entry) == 0 {
				continue
			}

			var cveID string
			detail := "Matched by CIRCL vendor/product search"

			if id, ok := entry[0].(string); ok && id != "" {
				cveID = strings.ToUpper(id)
			} else if m, ok := entry[0].(map[string]interface{}); ok {
				if meta, ok := m["cveMetadata"].(map[string]interface{}); ok {
					if id, ok := meta["cveId"].(string); ok {
						cveID = strings.ToUpper(id)
					}
				}
				if cveID == "" {
					if id, ok := m["id"].(string); ok {
						cveID = strings.ToUpper(id)
					}
				}
				if cont, ok := m["containers"].(map[string]interface{}); ok {
					if cna, ok := cont["cna"].(map[string]interface{}); ok {
						if title, ok := cna["title"].(string); ok && title != "" {
							detail = title
						} else if descs, ok := cna["descriptions"].([]interface{}); ok && len(descs) > 0 {
							if dMap, ok := descs[0].(map[string]interface{}); ok {
								if val, ok := dMap["value"].(string); ok && val != "" {
									detail = val
								}
							}
						}
					}
				}
			}

			if cveID == "" || !strings.HasPrefix(cveID, "CVE-") {
				continue
			}
			if _, ok := seen[cveID]; ok {
				continue
			}
			seen[cveID] = struct{}{}

			findings = append(findings, Finding{
				CVE:    cveID,
				Source: o.Name(),
				Detail: detail,
			})
		}
	}
	return findings, nil
}
