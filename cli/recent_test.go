package cli

import (
	"encoding/json"
	"testing"
)

func TestFetchRecentCVEsParse(t *testing.T) {
	// fetchRecentCVEs hits the network; test the parser instead by feeding
	// the same structures it decodes.
	raw := `[
	  {"fetchTime":"2026-11-23T15:27:33Z","numberOfChanges":2,
	   "new":[{"cveId":"CVE-2026-9999","cveOrgLink":"https://www.cve.org/CVERecord?id=CVE-2026-9999","dateAdded":"2026-11-23T10:00:00.000Z"}],
	   "updated":[{"cveId":"CVE-2026-8888","cveOrgLink":"https://www.cve.org/CVERecord?id=CVE-2026-8888","dateUpdated":"2026-11-23T15:21:58.500Z"}]},
	  {"fetchTime":"2026-11-23T16:27:33Z",
	   "new":[{"cveId":"CVE-2026-7777","cveOrgLink":"x","dateAdded":"2026-11-23T16:00:00.000Z"}],
	   "updated":[{"cveId":"CVE-2026-8888","cveOrgLink":"x","dateUpdated":"2026-11-23T14:00:00.000Z"}]}
	]`
	var records []deltaRecord
	if err := json.Unmarshal([]byte(raw), &records); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	latest := map[string]recentEntry{}
	for _, rec := range records {
		for _, n := range rec.New {
			keepLatest(latest, recentEntry{CVE: n.CVEID, Action: "added", Date: n.DateAdded, Link: n.CveOrgLink})
		}
		for _, u := range rec.Updated {
			keepLatest(latest, recentEntry{CVE: u.CVEID, Action: "updated", Date: u.DateUpdated, Link: u.CveOrgLink})
		}
	}

	if len(latest) != 3 {
		t.Fatalf("entries = %d, want 3", len(latest))
	}
	if e := latest["CVE-2026-8888"]; e.Action != "updated" || e.Date != "2026-11-23T15:21:58.500Z" {
		t.Errorf("keepLatest kept the wrong event: %+v", e)
	}
	if e := latest["CVE-2026-9999"]; e.Action != "added" {
		t.Errorf("new entry misclassified: %+v", e)
	}
}
