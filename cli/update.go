package cli

import (
	"context"
	"fmt"

	"strings"
	"time"

	"github.com/Fakechippies/POC-Hunter/db"
	"github.com/Fakechippies/POC-Hunter/poc"
	"github.com/spf13/cobra"
)

// updatableSources maps bulk-index source names to a forced refresh. Each
// updater wipes its cached snapshot and rebuilds it from upstream.
func updatableSources(cacheDB *db.DB) map[string]func(ctx context.Context) (int, error) {
	updaters := map[string]func(ctx context.Context) (int, error){
		"exploitdb":       poc.NewExploitDB(cacheDB).ForceUpdate,
		"trickest":        poc.NewTrickest(cacheDB).ForceUpdate,
		"metasploit":      poc.NewMetasploit(cacheDB).ForceUpdate,
		"nuclei":          poc.NewNuclei(cacheDB).ForceUpdate,
		"tg12":            poc.NewTg12(cacheDB).ForceUpdate,
		"awesome-cve-poc": poc.NewAwesomeCVEPOC(cacheDB).ForceUpdate,
		"vulncheck-kev": func(ctx context.Context) (int, error) {
			entries, err := poc.VulnCheckKEV{APIKey: vulncheckToken()}.FetchAll(ctx)
			if err != nil {
				return 0, err
			}
			var ids []string
			for _, e := range entries {
				ids = append(ids, e.CVE...)
			}
			return cacheDB.CVEKEVMark(ids, time.Now())
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

			// Bulk indexes are tens of MB; give the refresh a generous budget
			// independent of the per-request --timeout.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			var failed bool
			for _, name := range names {
				n, err := updaters[name](ctx)
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
