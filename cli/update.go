package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Fakechippies/POC-Hunter/cpe"
	"github.com/Fakechippies/POC-Hunter/db"
	"github.com/Fakechippies/POC-Hunter/poc"
	"github.com/spf13/cobra"
)

// updaterPair bundles the two refresh modes: force always re-downloads;
// smart skips sources whose snapshot is still fresh (bare `pochunter update`).
type updaterPair struct {
	force func(ctx context.Context) (int, error)
	smart func(ctx context.Context) (int, error)
}

// updatableSources maps bulk-index source names to their refreshers.
// Named updates force; bare updates use smart, which skips fresh snapshots.
func updatableSources(cacheDB *db.DB) map[string]updaterPair {
	bulkSmart := func(src *poc.BulkSource) func(ctx context.Context) (int, error) {
		return src.RefreshIfStale
	}
	kevForce := func(ctx context.Context) (int, error) {
		entries, err := poc.VulnCheckKEV{APIKey: vulncheckToken()}.FetchAll(ctx)
		if err != nil {
			return 0, err
		}
		var ids []string
		for _, e := range entries {
			ids = append(ids, e.CVE...)
		}
		n, err := cacheDB.CVEKEVMark(ids, time.Now())
		if err != nil {
			return 0, err
		}
		return n, cacheDB.SetIndexRev("vulncheck-kev", "api", time.Now())
	}
	cpesForce := func(ctx context.Context) (int, error) {
		entries, err := cpe.FetchDictionary(ctx)
		if err != nil {
			return 0, err
		}
		if err := cacheDB.StoreCPEs(entries); err != nil {
			return 0, err
		}
		return len(entries), cacheDB.CPEMarkRefreshed(time.Now())
	}

	updaters := map[string]updaterPair{
		"exploitdb":       {poc.NewExploitDB(cacheDB).ForceUpdate, bulkSmart(&poc.NewExploitDB(cacheDB).BulkSource)},
		"trickest":        {poc.NewTrickest(cacheDB).ForceUpdate, bulkSmart(&poc.NewTrickest(cacheDB).BulkSource)},
		"metasploit":      {poc.NewMetasploit(cacheDB).ForceUpdate, bulkSmart(&poc.NewMetasploit(cacheDB).BulkSource)},
		"nuclei":          {poc.NewNuclei(cacheDB).ForceUpdate, bulkSmart(&poc.NewNuclei(cacheDB).BulkSource)},
		"tg12":            {poc.NewTg12(cacheDB).ForceUpdate, bulkSmart(&poc.NewTg12(cacheDB).BulkSource)},
		"awesome-cve-poc": {poc.NewAwesomeCVEPOC(cacheDB).ForceUpdate, bulkSmart(&poc.NewAwesomeCVEPOC(cacheDB).BulkSource)},
		"vulncheck-kev": updaterPair{
			force: kevForce,
			smart: func(ctx context.Context) (int, error) {
				if fetchedAt, ok := cacheDB.IndexFetchedAt("vulncheck-kev"); ok && time.Since(fetchedAt) < 24*time.Hour {
					return 0, poc.ErrUpToDate
				}
				return kevForce(ctx)
			},
		},
		"cpes": updaterPair{
			force: cpesForce,
			smart: func(ctx context.Context) (int, error) {
				if !cacheDB.CPEStale(24 * time.Hour) {
					return 0, poc.ErrUpToDate
				}
				return cpesForce(ctx)
			},
		},
	}
	return updaters
}

func newUpdateCommand() *cobra.Command {
	var dbPath string

	cmd := &cobra.Command{
		Use:   "update [sources...]",
		Short: "Force-refresh cached bulk data sources (e.g. exploitdb); no args updates all",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cacheDB, err := openUpdateDB(dbPath)
			if err != nil {
				return err
			}
			defer cacheDB.Close()

			updaters := updatableSources(cacheDB)

			// Bare `pochunter update` smartly skips fresh snapshots; naming a
			// source forces a full re-download.
			forceMode := len(args) > 0
			pick := func(name string) func(ctx context.Context) (int, error) {
				if forceMode {
					return updaters[name].force
				}
				return updaters[name].smart
			}

			var names []string
			if len(args) == 0 {
				for name := range updaters {
					names = append(names, name)
				}
			} else {
				for _, arg := range args {
					name := strings.ToLower(strings.TrimSpace(arg))
					if _, ok := updaters[name]; !ok {
						available := make([]string, 0, len(updaters))
						for n := range updaters {
							available = append(available, n)
						}
						return fmt.Errorf("unknown source %q (updatable: %s)", arg, strings.Join(available, ", "))
					}
					names = append(names, name)
				}
			}

			// Bulk indexes (the CPE dictionary alone is ~190 API pages) need a
			// generous budget independent of the per-request --timeout.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()

			var failed bool
			for _, name := range names {
				n, err := pick(name)(ctx)
				if errors.Is(err, poc.ErrUpToDate) {
					successf("%s: up to date", name)
					continue
				}
				if err != nil {
					failed = true
					errorf("%s: %v", name, err)
					continue
				}
				successf("%s: refreshed (%d POC links)", name, n)
			}
			if failed {
				return fmt.Errorf("one or more sources failed to update")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "", "cache database path (overrides POCHUNTER_DB; default: os.UserCacheDir()/pochunter/pochunter.db)")
	return cmd
}

func openUpdateDB(dbPath string) (*db.DB, error) {
	path := resolveDBPath(dbPath)
	if path == "" {
		return nil, fmt.Errorf("cannot determine cache directory (set --db or POCHUNTER_DB)")
	}
	d, err := db.Open(path)
	if err != nil {
		return nil, err
	}
	return d, nil
}
