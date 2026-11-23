package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

const deltaLogURL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/deltaLog.json"

// recentEntry is one row of the `pochunter recent` table.
type recentEntry struct {
	CVE    string
	Action string // added | updated
	Date   string
	Link   string
}

type deltaRecord struct {
	FetchTime string `json:"fetchTime"`
	New       []struct {
		CVEID      string `json:"cveId"`
		CveOrgLink string `json:"cveOrgLink"`
		DateAdded  string `json:"dateAdded"`
	} `json:"new"`
	Updated []struct {
		CVEID       string `json:"cveId"`
		CveOrgLink  string `json:"cveOrgLink"`
		DateUpdated string `json:"dateUpdated"`
	} `json:"updated"`
}

func newRecentCommand() *cobra.Command {
	var count int

	cmd := &cobra.Command{
		Use:   "recent",
		Short: "List the most recently added/updated CVEs from the cvelistV5 delta log",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			entries, err := fetchRecentCVEs(ctx)
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				warnf("delta log contained no CVE records")
				return nil
			}
			sort.Slice(entries, func(i, j int) bool {
				if entries[i].Date == entries[j].Date {
					return entries[i].CVE < entries[j].CVE
				}
				return entries[i].Date > entries[j].Date
			})
			if count > len(entries) {
				count = len(entries)
			}
			entries = entries[:count]

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, paint(colorBold, "CVE")+"\t"+paint(colorBold, "ACTION")+"\t"+paint(colorBold, "DATE")+"\t"+paint(colorBold, "LINK"))
			for _, e := range entries {
				action := e.Action
				if action == "added" {
					action = paint(colorGreen, action)
				} else {
					action = paint(colorYellow, action)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.CVE, action, e.Date, e.Link)
			}
			return w.Flush()
		},
	}

	cmd.Flags().IntVarP(&count, "count", "n", 20, "number of entries to show")
	return cmd
}

// fetchRecentCVEs downloads the cvelistV5 delta log (a rolling window of the
// last ~30 days of record changes, refreshed hourly) and reduces it to one
// row per CVE id, keeping the newest event.
func fetchRecentCVEs(ctx context.Context) ([]recentEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, deltaLogURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("delta log fetch failed with status %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var records []deltaRecord
	if err := json.Unmarshal(body, &records); err != nil {
		return nil, fmt.Errorf("parse delta log: %w", err)
	}

	latest := map[string]recentEntry{}
	for _, rec := range records {
		for _, n := range rec.New {
			if n.CVEID == "" {
				continue
			}
			keepLatest(latest, recentEntry{CVE: n.CVEID, Action: "added", Date: n.DateAdded, Link: n.CveOrgLink})
		}
		for _, u := range rec.Updated {
			if u.CVEID == "" {
				continue
			}
			keepLatest(latest, recentEntry{CVE: u.CVEID, Action: "updated", Date: u.DateUpdated, Link: u.CveOrgLink})
		}
	}

	out := make([]recentEntry, 0, len(latest))
	for _, e := range latest {
		out = append(out, e)
	}
	return out, nil
}

// keepLatest keeps the entry with the newest date for a CVE id. RFC3339
// timestamps compare correctly as strings.
func keepLatest(m map[string]recentEntry, e recentEntry) {
	if e.Date == "" {
		e.Date = "0000-00-00T00:00:00Z"
	}
	if old, ok := m[e.CVE]; !ok || strings.Compare(e.Date, old.Date) > 0 {
		m[e.CVE] = e
	}
}
