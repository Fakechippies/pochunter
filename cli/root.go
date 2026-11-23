package cli

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"
	"unsafe"

	"github.com/Fakechippies/POC-Hunter/cve"
	"github.com/Fakechippies/POC-Hunter/db"
	"github.com/Fakechippies/POC-Hunter/poc"
	"github.com/Fakechippies/POC-Hunter/versioncanon"
	"github.com/spf13/cobra"
)

const (
	colorReset  = "\033[0m"
	colorCyan   = "\033[36m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
)

type options struct {
	pocMode    bool
	searchMode bool
	vendor     string
	app        string
	version    string
	ecosystem  string
	sources    []string
	output     string
	timeout    time.Duration
	dbPath     string
	noCache    bool
	cacheTTL   time.Duration
	cveTTL     time.Duration
	refresh    bool
}

func Execute() error {
	opts := options{}

	rootCmd := &cobra.Command{
		Use:   "pochunter [query words]",
		Short: "Hunt CVEs and related public POCs",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(args, opts)
		},
	}

	rootCmd.Flags().BoolVar(&opts.pocMode, "poc", false, "direct POC mode (treat input as CVE id)")
	rootCmd.Flags().BoolVar(&opts.searchMode, "search", false, "keyword search mode")
	rootCmd.Flags().StringVar(&opts.vendor, "vendor", "", "vendor name")
	rootCmd.Flags().StringVar(&opts.app, "app", "", "application/product name")
	rootCmd.Flags().StringVar(&opts.version, "version", "", "application version")
	rootCmd.Flags().StringVar(&opts.ecosystem, "ecosystem", "", "package ecosystem (for sources that use it)")
	rootCmd.Flags().StringSliceVar(&opts.sources, "sources", nil, "CVE sources to use (comma-separated: nvd,circl,osv,vulners,github)")
	rootCmd.Flags().StringVarP(&opts.output, "output", "o", "table", "output format: table, json, jsonl, csv")
	rootCmd.PersistentFlags().BoolVarP(&verboseMode, "verbose", "v", false, "show per-source API errors (hidden by default)")
	rootCmd.Flags().DurationVar(&opts.timeout, "timeout", 30*time.Second, "request timeout")
	rootCmd.Flags().StringVar(&opts.dbPath, "db", "", "POC cache database path (overrides POCHUNTER_DB; default: os.UserCacheDir()/pochunter/pochunter.db)")
	rootCmd.Flags().BoolVar(&opts.noCache, "no-cache", false, "disable all local caching (POC and CVE)")
	rootCmd.Flags().DurationVar(&opts.cacheTTL, "cache-ttl", 24*time.Hour, "POC cache freshness duration (e.g. 12h, 7d as 168h)")
	rootCmd.Flags().DurationVar(&opts.cveTTL, "cve-ttl", 30*time.Minute, "CVE query cache freshness duration")
	rootCmd.Flags().BoolVar(&opts.refresh, "refresh", false, "bypass cache reads but still write (refresh cached data)")

	rootCmd.SetArgs(normalizeCompatFlags(os.Args[1:]))
	rootCmd.AddCommand(newUpdateCommand())
	return rootCmd.Execute()
}

func normalizeCompatFlags(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "--" {
			continue
		}
		if arg == "-poc" {
			out = append(out, "--poc")
			continue
		}
		out = append(out, arg)
	}
	return out
}

func run(args []string, opts options) error {
	if err := setOutputFormat(opts.output); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()

	cacheDB := openCacheDB(opts)
	if cacheDB != nil {
		defer cacheDB.Close()
	}

	cveSources := buildCVESourcesFromEnv(opts.sources)
	pocSources := buildPOCSources(cacheDB, opts.cacheTTL)

	if opts.pocMode {
		if len(args) == 0 {
			return fmt.Errorf("poc mode expects a CVE id, e.g. -poc CVE-2026-38526")
		}
		cveID := normalizeCVE(args)
		progressf("POC mode enabled for %s", cveID)
		pocs := runPOCSources(ctx, pocSources, cveID)
		printCVEInfoEnrichment(cacheDB, cveID)
		if isStructured() {
			return emitStructured(cveID, nil, nil, pocs)
		}
		if len(pocs) == 0 {
			warnf("%s: no POCs found", cveID)
			return nil
		}
		printPOCFindings("POC Discovery", pocs)
		return nil
	}

	rawQuery := strings.Join(args, " ")
	vendor, product, version, ecosystem, err := resolveSearchInput(args, opts)
	if err != nil {
		return err
	}

	isFreeForm := opts.app == ""
	if isFreeForm {
		displayQuery := rawQuery
		if displayQuery == "" {
			displayQuery = product
		}
		progressf("Free-form CVEs for query=%q", displayQuery)
	} else {
		progressf("Searching CVEs for vendor=%q product=%q version=%q ecosystem=%q", vendor, product, version, ecosystem)
	}

	cveResults := collectCVEs(ctx, cveSources, vendor, product, version, ecosystem, cacheDB, opts.cveTTL, opts.refresh)
	printCVECacheStatus(cveResults)
	allCVEFindings, uniqueCVEs := dedupeCVEs(cveResults)

	if isFreeForm {
		sort.SliceStable(allCVEFindings, func(i, j int) bool {
			return allCVEFindings[i].Score > allCVEFindings[j].Score
		})
	}

	if len(allCVEFindings) == 0 {
		printCVESourceErrors(cveResults)
		if isStructured() {
			return emitStructured(rawQuery, allCVEFindings, uniqueCVEs, nil)
		}
		warnf("No CVEs found for query")
		return nil
	}

	if !isStructured() {
		kevSet := cveKEVSet(cacheDB, uniqueCVEs)
		printCVEFindings("CVE Discovery", allCVEFindings, isFreeForm, kevSet)
		successf("Unique CVEs: %d", len(uniqueCVEs))
	}
	printCVESourceErrors(cveResults)

	progressf("Searching POCs for %d CVEs", len(uniqueCVEs))
	pocResults := collectPOCsForCVEs(ctx, pocSources, uniqueCVEs)
	printPOCErrors(pocResults)
	allPOCs := flattenPOCResults(pocResults)

	if isStructured() {
		return emitStructured(rawQuery, allCVEFindings, uniqueCVEs, allPOCs)
	}

	if len(allPOCs) == 0 {
		warnf("No POCs found across discovered CVEs")
		return nil
	}

	printPOCFindings("POC Discovery", allPOCs)
	return nil
}

type cveSourceResult struct {
	source    string
	findings  []cve.Finding
	err       error
	cached    bool
	cachedAge time.Duration
}

type pocResult struct {
	cveID    string
	findings []poc.Finding
	err      error
}

func buildCVESourcesFromEnv(want []string) []cve.Source {
	all := map[string]cve.Source{
		"nvd":     cve.NVDSource{},
		"circl":   cve.CIRCLSource{},
		"osv":     cve.OSVSource{},
		"vulners": nil,
		"github":  nil,
	}
	if key := strings.TrimSpace(os.Getenv("VULNERS_API_KEY")); key != "" {
		all["vulners"] = &cve.VulnersSource{APIKey: key}
	}
	if key := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); key != "" {
		all["github"] = cve.GithubSource{APIKey: key}
	}

	filter := make(map[string]bool, len(want))
	for _, name := range want {
		filter[strings.ToLower(strings.TrimSpace(name))] = true
	}

	var sources []cve.Source
	for key, src := range all {
		if src == nil {
			continue
		}
		if len(filter) > 0 && !filter[key] {
			continue
		}
		sources = append(sources, src)
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Name() < sources[j].Name() })
	return sources
}

// resolveDBPath applies the standard precedence for the cache database
// location: --db flag (highest), POCHUNTER_DB env var, then the default
// os.UserCacheDir()/pochunter/pochunter.db, which maps to
// ~/.cache/pochunter/ (Linux), ~/Library/Caches/pochunter/ (macOS) and
// %LocalAppData%\pochunter\ (Windows).
func resolveDBPath(flagPath string) string {
	if p := strings.TrimSpace(flagPath); p != "" {
		return p
	}
	if p := strings.TrimSpace(os.Getenv("POCHUNTER_DB")); p != "" {
		return p
	}
	if base, err := os.UserCacheDir(); err == nil {
		return filepath.Join(base, "pochunter", "pochunter.db")
	}
	return ""
}

// printCVEInfoEnrichment surfaces cached bare CVE info in direct POC mode,
// where no CVE source is queried and the cves table may already hold a
// summary from earlier searches.
func printCVEInfoEnrichment(cacheDB *db.DB, cveIDs ...string) {
	if cacheDB == nil {
		return
	}
	for _, id := range cveIDs {
		info, ok, err := cacheDB.CVEInfoGet(id)
		if err != nil || !ok || (info.Summary == "" && !info.KEV) {
			continue
		}
		summary := info.Summary
		if len(summary) > 160 {
			summary = summary[:157] + "..."
		}
		kevTag := ""
		if info.KEV {
			kevTag = " [KEV]"
		}
		if summary == "" {
			summary = "listed in KEV"
		}
		progressf("%s: %s%s (from local CVE cache)", id, summary, kevTag)
	}
}

// vulncheckToken resolves the VulnCheck API token: the official
// VULNCHECK_API_TOKEN name first, VULNCHECK_API_KEY as a fallback.
func vulncheckToken() string {
	if key := strings.TrimSpace(os.Getenv("VULNCHECK_API_TOKEN")); key != "" {
		return key
	}
	return strings.TrimSpace(os.Getenv("VULNCHECK_API_KEY"))
}

// openCacheDB opens the shared cache database unless caching is disabled.
// Failures are reported but never fatal: the tool works without a cache.
func openCacheDB(opts options) *db.DB {
	if opts.noCache {
		return nil
	}
	path := resolveDBPath(opts.dbPath)
	if path == "" {
		return nil
	}
	d, err := db.Open(path)
	if err != nil {
		warnf("cache disabled: %v", err)
		return nil
	}
	return d
}

func buildPOCSources(cacheDB *db.DB, ttl time.Duration) []poc.Source {
	var sources []poc.Source
	sources = append(sources, poc.POCInGithub{})
	if key := strings.TrimSpace(os.Getenv("SEARCHVULNS_API_KEY")); key != "" {
		sources = append(sources, poc.SearchVulns{APIKey: key})
	}
	if key := vulncheckToken(); key != "" {
		sources = append(sources, poc.VulnCheckXDB{APIKey: key}, poc.VulnCheckIAC{APIKey: key})
	}
	if cacheDB != nil {
		// Bulk-index sources are backed by the cache database.
		sources = append(sources,
			poc.NewExploitDB(cacheDB),
			poc.NewTrickest(cacheDB),
			poc.NewMetasploit(cacheDB),
			poc.NewNuclei(cacheDB),
			poc.NewTg12(cacheDB),
			poc.NewAwesomeCVEPOC(cacheDB),
		)
	}
	if cacheDB != nil && ttl > 0 {
		for i, s := range sources {
			// Bulk-index sources manage their own freshness via the
			// upstream revision; only wrap plain API sources.
			if _, ok := s.(poc.ForceUpdater); ok {
				continue
			}
			sources[i] = poc.CachedSource{Inner: s, DB: cacheDB, TTL: ttl}
		}
	}
	return sources
}

// cveCacheCapKeys mirrors db.CVECacheCapKeys for the per-run store calls.
const cveCacheCapKeys = db.CVECacheCapKeys

// collectCVEs queries all sources concurrently, with a read-through /
// write-through cache per source: cached payloads are served within the TTL,
// fresh results are stored, and per-CVE bare info is filled lazily from every
// successful response (all API results are cached, deduped by CVE id).
func collectCVEs(ctx context.Context, sources []cve.Source, vendor, product, version, ecosystem string, cacheDB *db.DB, cveTTL time.Duration, refresh bool) []cveSourceResult {
	key := db.CVECacheKey(vendor, product, version, ecosystem)
	results := make(chan cveSourceResult, len(sources))
	var wg sync.WaitGroup

	for _, source := range sources {
		wg.Add(1)
		go func(src cve.Source) {
			defer wg.Done()
			var findings []cve.Finding
			var err error
			cached, age := false, time.Duration(0)

			if cacheDB != nil && !refresh {
				if payload, createdAt, ok, gerr := cacheDB.CVECacheGet(key, src.Name()); gerr == nil && ok {
					if decoded, derr := unmarshalCVEPayload(payload); derr == nil {
						findings, cached, age = decoded, true, time.Since(createdAt)
					}
				}
			}
			if !cached {
				findings, err = src.Query(ctx, vendor, product, version, ecosystem)
				if err == nil && cacheDB != nil {
					if payload, merr := json.Marshal(findings); merr == nil {
						_ = cacheDB.CVECacheStore(key, src.Name(), payload, time.Now(), cveTTL, cveCacheCapKeys)
					}
					_ = cacheDB.CVEInfoStore(cveInfoRows(findings), time.Now())
				}
			}
			results <- cveSourceResult{source: src.Name(), findings: findings, err: err, cached: cached, cachedAge: age}
		}(source)
	}

	wg.Wait()
	close(results)

	out := make([]cveSourceResult, 0, len(sources))
	for result := range results {
		out = append(out, result)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].source < out[j].source })
	return out
}

func unmarshalCVEPayload(payload []byte) ([]cve.Finding, error) {
	var findings []cve.Finding
	if err := json.Unmarshal(payload, &findings); err != nil {
		return nil, err
	}
	return findings, nil
}

// cveInfoRows reduces findings to one bare-info row per unique CVE.
func cveInfoRows(findings []cve.Finding) []db.CVEInfoRow {
	seen := map[string]struct{}{}
	rows := make([]db.CVEInfoRow, 0, len(findings))
	for _, f := range findings {
		if f.CVE == "" {
			continue
		}
		if _, dup := seen[f.CVE]; dup {
			continue
		}
		seen[f.CVE] = struct{}{}
		rows = append(rows, db.CVEInfoRow{ID: f.CVE, Summary: f.Detail})
	}
	return rows
}

// printCVECacheStatus makes cache hits visible so nobody debugs stale results.
// Only prints when at least one source was served from cache.
func printCVECacheStatus(results []cveSourceResult) {
	parts := make([]string, 0, len(results))
	cachedAny := false
	for _, r := range results {
		if r.err != nil {
			continue
		}
		if r.cached {
			cachedAny = true
			parts = append(parts, fmt.Sprintf("%s cached (%s old)", r.source, r.cachedAge.Round(time.Second)))
		} else {
			parts = append(parts, r.source+" fresh")
		}
	}
	if cachedAny {
		progressf("CVE cache: %s", strings.Join(parts, ", "))
	}
}

func dedupeCVEs(results []cveSourceResult) ([]cve.Finding, []string) {
	var all []cve.Finding
	seenRow := map[string]struct{}{}
	seenCVE := map[string]struct{}{}
	var cveIDs []string

	for _, result := range results {
		for _, finding := range result.findings {
			key := finding.CVE + "|" + finding.Source + "|" + finding.Detail
			if _, ok := seenRow[key]; ok {
				continue
			}
			seenRow[key] = struct{}{}
			all = append(all, finding)

			if _, ok := seenCVE[finding.CVE]; !ok {
				seenCVE[finding.CVE] = struct{}{}
				cveIDs = append(cveIDs, finding.CVE)
			}
		}
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].CVE == all[j].CVE {
			return all[i].Source < all[j].Source
		}
		return all[i].CVE < all[j].CVE
	})
	sort.Strings(cveIDs)
	return all, cveIDs
}

func collectPOCsForCVEs(ctx context.Context, sources []poc.Source, cveIDs []string) []pocResult {
	const maxWorkers = 8
	sem := make(chan struct{}, maxWorkers)
	results := make(chan pocResult, len(cveIDs))
	var wg sync.WaitGroup
	var rateLimitedSources sync.Map

	for _, cveID := range cveIDs {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			findings, err := queryPOCsForCVE(ctx, sources, id, &rateLimitedSources)
			results <- pocResult{cveID: id, findings: findings, err: err}
		}(cveID)
	}

	wg.Wait()
	close(results)

	out := make([]pocResult, 0, len(cveIDs))
	for result := range results {
		out = append(out, result)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].cveID < out[j].cveID })
	return out
}

func queryPOCsForCVE(ctx context.Context, sources []poc.Source, cveID string, rateLimitedSources *sync.Map) ([]poc.Finding, error) {
	results := make(chan pocSourceResult, len(sources))
	var wg sync.WaitGroup

	for _, source := range sources {
		if rateLimitedSources != nil {
			if _, limited := rateLimitedSources.Load(source.Name()); limited {
				continue
			}
		}
		wg.Add(1)
		go func(s poc.Source) {
			defer wg.Done()
			findings, err := s.Query(ctx, cveID)
			if err != nil && isRateLimitError(err) && rateLimitedSources != nil {
				rateLimitedSources.Store(s.Name(), true)
			}
			results <- pocSourceResult{name: s.Name(), findings: findings, err: err}
		}(source)
	}

	wg.Wait()
	close(results)

	var all []poc.Finding
	var firstErr error
	for result := range results {
		if result.err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", result.name, result.err)
			}
			continue
		}
		all = append(all, result.findings...)
	}
	return all, firstErr
}

func flattenPOCResults(results []pocResult) []poc.Finding {
	var all []poc.Finding
	for _, result := range results {
		all = append(all, result.findings...)
	}
	return sortPOCFindings(all)
}

func sortPOCFindings(all []poc.Finding) []poc.Finding {
	sort.Slice(all, func(i, j int) bool {
		if all[i].CVE == all[j].CVE {
			if all[i].Owner == all[j].Owner {
				return all[i].POC < all[j].POC
			}
			return all[i].Owner < all[j].Owner
		}
		return all[i].CVE < all[j].CVE
	})
	return all
}

// verboseMode controls whether per-source API errors print in full. Set by
// the persistent -v/--verbose flag; hidden by default.
var verboseMode = false

type sourceError struct {
	name   string // display name (source or CVE id)
	source string // owning source, for grouping and rate-limit suppression
	err    error
}

// reportSourceErrors prints API errors from sources. By default they are
// collapsed into one summary line so output stays clean; -v/--verbose prints
// every error in full, with rate-limit warnings suppressed per source.
func reportSourceErrors(label string, errs []sourceError) {
	if len(errs) == 0 {
		return
	}
	if !verboseMode {
		seen := map[string]struct{}{}
		var sources []string
		for _, e := range errs {
			if _, ok := seen[e.source]; !ok {
				seen[e.source] = struct{}{}
				sources = append(sources, e.source)
			}
		}
		warnf("%s: %d error(s) from %s (use -v to show)", label, len(errs), strings.Join(sources, ", "))
		return
	}
	printedRateLimit := map[string]struct{}{}
	for _, e := range errs {
		if isRateLimitError(e.err) {
			if _, ok := printedRateLimit[e.source]; ok {
				continue
			}
			printedRateLimit[e.source] = struct{}{}
			warnf("%s: %v (rate limit reached, suppressing further rate-limit warnings)", e.name, e.err)
			continue
		}
		warnf("%s: %v", e.name, e.err)
	}
}

func printPOCErrors(results []pocResult) {
	var errs []sourceError
	for _, result := range results {
		if result.err != nil {
			errs = append(errs, sourceError{name: result.cveID, source: extractSourceKey(result.err), err: result.err})
		}
	}
	reportSourceErrors("POC lookups", errs)
}

func printCVESourceErrors(results []cveSourceResult) {
	var errs []sourceError
	for _, result := range results {
		if result.err != nil {
			errs = append(errs, sourceError{name: result.source, source: result.source, err: result.err})
		}
	}
	reportSourceErrors("CVE sources", errs)
}

func isRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "429") ||
		strings.Contains(s, "too many requests") ||
		strings.Contains(s, "rate limit") ||
		strings.Contains(s, "ratelimit")
}

func extractSourceKey(err error) string {
	if err == nil {
		return "unknown"
	}
	parts := strings.SplitN(err.Error(), ":", 2)
	if len(parts) > 1 {
		return strings.TrimSpace(parts[0])
	}
	return "rate-limit"
}

func resolveSearchInput(args []string, opts options) (string, string, string, string, error) {
	vendor := strings.TrimSpace(opts.vendor)
	ecosystem := strings.TrimSpace(opts.ecosystem)

	if opts.app != "" {
		tokens := []string{opts.app}
		tokens = append(tokens, args...)

		if opts.version != "" {
			return vendor, strings.Join(tokens, " "), opts.version, ecosystem, nil
		}
		if len(tokens) >= 2 {
			app, ver := versioncanon.ExtractAppAndVersion(strings.Join(tokens, " "))
			if ver != "" {
				return vendor, app, ver, ecosystem, nil
			}
			product := strings.Join(tokens[:len(tokens)-1], " ")
			version := tokens[len(tokens)-1]
			return vendor, product, version, ecosystem, nil
		}
		return "", "", "", "", fmt.Errorf("--app mode expects version in --version or as the last argument")
	}

	if opts.version != "" {
		if len(args) == 0 {
			return "", "", "", "", fmt.Errorf("--version requires product query words or --app")
		}
		return vendor, strings.Join(args, " "), opts.version, ecosystem, nil
	}

	if opts.searchMode || len(args) > 0 {
		if len(args) < 1 {
			return "", "", "", "", fmt.Errorf("search mode expects at least one keyword")
		}
		rawQuery := strings.Join(args, " ")
		app, ver := versioncanon.ExtractAppAndVersion(rawQuery)
		if ver != "" {
			return vendor, app, ver, ecosystem, nil
		}
		return vendor, rawQuery, "", ecosystem, nil
	}

	return "", "", "", "", fmt.Errorf("provide search input via --search <product words...> <version> or --app <name> --version <version>")
}

type pocSourceResult struct {
	name     string
	findings []poc.Finding
	err      error
}

func runPOCSources(ctx context.Context, sources []poc.Source, cveID string) []poc.Finding {
	results := make(chan pocSourceResult, len(sources))
	var wg sync.WaitGroup

	var errs []sourceError
	for _, source := range sources {
		wg.Add(1)
		go func(s poc.Source) {
			defer wg.Done()
			findings, err := s.Query(ctx, cveID)
			results <- pocSourceResult{name: s.Name(), findings: findings, err: err}
		}(source)
	}

	wg.Wait()
	close(results)

	var all []poc.Finding
	for result := range results {
		if result.err != nil {
			errs = append(errs, sourceError{name: result.name, source: result.name, err: result.err})
			continue
		}
		for i := range result.findings {
			if result.findings[i].Source == "" {
				result.findings[i].Source = result.name
			}
		}
		all = append(all, result.findings...)
	}
	reportSourceErrors("POC sources", errs)
	return sortPOCFindings(all)
}

func normalizeCVE(args []string) string {
	return strings.ToUpper(strings.Join(args, "-"))
}

// cveKEVSet returns the set of KEV-listed CVEs among ids, from the local CVE
// cache (filled by `pochunter update vulncheck-kev`). Empty when no cache.
func cveKEVSet(cacheDB *db.DB, ids []string) map[string]bool {
	if cacheDB == nil {
		return nil
	}
	kev := map[string]bool{}
	for _, id := range ids {
		if info, ok, err := cacheDB.CVEInfoGet(id); err == nil && ok && info.KEV {
			kev[id] = true
		}
	}
	return kev
}

func printCVEFindings(source string, findings []cve.Finding, showScore bool, kev map[string]bool) {
	if len(findings) == 0 {
		warnf("%s: no CVEs found", source)
		return
	}

	successf("%s: %d findings", source, len(findings))

	cveW := len("CVE")
	srcW := len("SOURCE")
	scoreW := len("SCORE")
	for _, f := range findings {
		if len(f.CVE) > cveW {
			cveW = len(f.CVE)
		}
		if len(f.Source) > srcW {
			srcW = len(f.Source)
		}
	}
	gap := 2

	if showScore {
		for _, f := range findings {
			s := fmt.Sprintf("%.1f", f.Score)
			if len(s) > scoreW {
				scoreW = len(s)
			}
		}
		detailW := terminalWidth() - cveW - srcW - scoreW - gap*3
		if detailW < 20 {
			detailW = 20
		}

		fmt.Printf("%-*s%*s%*s  %s\n", cveW, "CVE", srcW+gap, "SOURCE", scoreW+gap, "SCORE", "DETAIL")
		fmt.Printf("%s%s%s  %s\n", strings.Repeat("-", cveW), strings.Repeat("-", srcW+gap), strings.Repeat("-", scoreW+gap), strings.Repeat("-", detailW))

		for _, f := range findings {
			detail := strings.ReplaceAll(f.Detail, "\n", " ")
			detail = strings.ReplaceAll(detail, "\r", "")
			if kev[f.CVE] {
				detail = "[KEV] " + detail
			}
			lines := wrapText(detail, detailW)
			score := fmt.Sprintf("%.1f", f.Score)
			for i, line := range lines {
				if i == 0 {
					fmt.Printf("%-*s%*s%*s  %s\n", cveW, f.CVE, srcW+gap, f.Source, scoreW+gap, score, line)
				} else {
					fmt.Printf("%-*s%*s%*s  %s\n", cveW, "", srcW+gap, "", scoreW+gap, "", line)
				}
			}
		}
		return
	}

	detailW := terminalWidth() - cveW - srcW - gap*2
	if detailW < 20 {
		detailW = 20
	}

	fmt.Printf("%-*s%*s  %s\n", cveW, "CVE", srcW+gap, "SOURCE", "DETAIL")
	fmt.Printf("%s%s  %s\n", strings.Repeat("-", cveW), strings.Repeat("-", srcW+gap), strings.Repeat("-", detailW))

	for _, f := range findings {
		detail := strings.ReplaceAll(f.Detail, "\n", " ")
		detail = strings.ReplaceAll(detail, "\r", "")
		if kev[f.CVE] {
			detail = "[KEV] " + detail
		}
		lines := wrapText(detail, detailW)
		for i, line := range lines {
			if i == 0 {
				fmt.Printf("%-*s%*s  %s\n", cveW, f.CVE, srcW+gap, f.Source, line)
			} else {
				fmt.Printf("%-*s%*s  %s\n", cveW, "", srcW+gap, "", line)
			}
		}
	}
}

func printPOCFindings(source string, findings []poc.Finding) {
	successf("%s: %d POCs", source, len(findings))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CVE\tSOURCE\tOWNER\tPUSHED AT\tPOC")
	for _, finding := range findings {
		src := finding.Source
		if src == "" {
			src = source
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", finding.CVE, src, finding.Owner, finding.PushedAt, finding.POC)
	}
	_ = w.Flush()
}

// outputFormat selects how results are rendered: "table" (default, human
// readable) or a machine-readable format ("json", "jsonl", "csv").
var outputFormat = "table"

func setOutputFormat(name string) error {
	f := strings.ToLower(strings.TrimSpace(name))
	if f == "" {
		f = "table"
	}
	switch f {
	case "table", "json", "jsonl", "csv":
		outputFormat = f
		return nil
	default:
		return fmt.Errorf("unsupported --output %q (supported: table, json, jsonl, csv)", name)
	}
}

func isStructured() bool { return outputFormat != "table" }

// diagWriter routes progress/status messages. In structured mode they go to
// stderr so stdout stays a clean, parseable document.
func diagWriter() io.Writer {
	if isStructured() {
		return os.Stderr
	}
	return os.Stdout
}

func progressf(format string, args ...interface{}) {
	fmt.Fprintf(diagWriter(), "%s[*]%s %s\n", colorCyan, colorReset, fmt.Sprintf(format, args...))
}

func successf(format string, args ...interface{}) {
	fmt.Fprintf(diagWriter(), "%s[+]%s %s\n", colorGreen, colorReset, fmt.Sprintf(format, args...))
}

func warnf(format string, args ...interface{}) {
	fmt.Fprintf(diagWriter(), "%s[-]%s %s\n", colorYellow, colorReset, fmt.Sprintf(format, args...))
}

func errorf(format string, args ...interface{}) {
	fmt.Fprintf(diagWriter(), "%s[!]%s %s\n", colorRed, colorReset, fmt.Sprintf(format, args...))
}

type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

func terminalWidth() int {
	if cols := os.Getenv("COLUMNS"); cols != "" {
		if w, err := strconv.Atoi(cols); err == nil && w > 0 {
			return w
		}
	}
	ws := &winsize{}
	ret, _, _ := syscall.Syscall(syscall.SYS_IOCTL, os.Stdout.Fd(), syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(ws)))
	if ret >= 0 && ws.Col > 0 {
		return int(ws.Col)
	}
	return 80
}

func wrapText(s string, width int) []string {
	if width <= 0 || s == "" {
		return []string{s}
	}
	var lines []string
	for _, word := range strings.Fields(s) {
		if len(lines) == 0 {
			lines = append(lines, word)
			continue
		}
		last := len(lines) - 1
		if len(lines[last])+1+len(word) > width {
			lines = append(lines, word)
		} else {
			lines[last] += " " + word
		}
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

type cveRecord struct {
	CVE    string  `json:"cve"`
	Source string  `json:"source"`
	Detail string  `json:"detail"`
	Score  float64 `json:"score"`
}

type pocRecord struct {
	CVE      string `json:"cve"`
	Source   string `json:"source"`
	Owner    string `json:"owner"`
	PushedAt string `json:"pushed_at"`
	POC      string `json:"poc"`
}

type structuredReport struct {
	Query       string      `json:"query,omitempty"`
	CVEFindings []cveRecord `json:"cve_findings"`
	UniqueCVEs  []string    `json:"unique_cves"`
	POCFindings []pocRecord `json:"poc_findings"`
}

type jsonlLine struct {
	Type     string  `json:"type"`
	CVE      string  `json:"cve"`
	Source   string  `json:"source"`
	Detail   string  `json:"detail,omitempty"`
	Score    float64 `json:"score,omitempty"`
	Owner    string  `json:"owner,omitempty"`
	PushedAt string  `json:"pushed_at,omitempty"`
	POC      string  `json:"poc,omitempty"`
}

func toCVERecords(findings []cve.Finding) []cveRecord {
	out := make([]cveRecord, 0, len(findings))
	for _, f := range findings {
		out = append(out, cveRecord{CVE: f.CVE, Source: f.Source, Detail: f.Detail, Score: f.Score})
	}
	return out
}

func toPOCRecords(findings []poc.Finding) []pocRecord {
	out := make([]pocRecord, 0, len(findings))
	for _, f := range findings {
		out = append(out, pocRecord{CVE: f.CVE, Source: f.Source, Owner: f.Owner, PushedAt: f.PushedAt, POC: f.POC})
	}
	return out
}

// emitStructured writes collected CVE/POC findings to stdout in the format
// selected by --output. It is a no-op in table mode.
func emitStructured(query string, cves []cve.Finding, uniqueCVEs []string, pocs []poc.Finding) error {
	switch outputFormat {
	case "json":
		if uniqueCVEs == nil {
			uniqueCVEs = []string{}
		}
		report := structuredReport{
			Query:       query,
			CVEFindings: toCVERecords(cves),
			UniqueCVEs:  uniqueCVEs,
			POCFindings: toPOCRecords(pocs),
		}
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, string(b))
		return nil

	case "jsonl":
		enc := json.NewEncoder(os.Stdout)
		for _, f := range cves {
			line := jsonlLine{Type: "cve", CVE: f.CVE, Source: f.Source, Detail: f.Detail, Score: f.Score}
			if err := enc.Encode(line); err != nil {
				return err
			}
		}
		for _, f := range pocs {
			line := jsonlLine{Type: "poc", CVE: f.CVE, Source: f.Source, Owner: f.Owner, PushedAt: f.PushedAt, POC: f.POC}
			if err := enc.Encode(line); err != nil {
				return err
			}
		}
		return nil

	case "csv":
		w := csv.NewWriter(os.Stdout)
		defer w.Flush()
		if err := w.Write([]string{"type", "cve", "source", "detail", "score", "owner", "pushed_at", "poc"}); err != nil {
			return err
		}
		for _, f := range cves {
			row := []string{"cve", f.CVE, f.Source, f.Detail, strconv.FormatFloat(f.Score, 'f', -1, 64), "", "", ""}
			if err := w.Write(row); err != nil {
				return err
			}
		}
		for _, f := range pocs {
			row := []string{"poc", f.CVE, f.Source, "", "", f.Owner, f.PushedAt, f.POC}
			if err := w.Write(row); err != nil {
				return err
			}
		}
		return w.Error()
	}
	return nil
}
