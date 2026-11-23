# pochunter

![pochunter banner](assets/banner.png)

CLI tool to discover CVEs and hunt public POCs, free-form search or structured product/version queries.

[![Go](https://img.shields.io/badge/go-1.26-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/license-Unlicense-blue)](LICENSE)
[![Release](https://img.shields.io/github/v/release/Fakechippies/pochunter?color=green)](https://github.com/Fakechippies/pochunter/releases)

## Demo

![Made with VHS](https://vhs.charm.sh/vhs-6n6WSJISpeL0d8JYahj9Dm.gif)

## Features

- **CVE discovery** from NVD, CIRCL, OSV, Vulners, and GitHub Advisories — all queried concurrently, deduplicated
- **Query → CPE resolution**: free-form queries ("apache http server 2.4.39") are resolved against the official CPE Dictionary, then NVD is queried by exact `cpeName`/`virtualMatchString` instead of keywords — no keyword false positives ("curl 7.0" never matches SQL Server 7.0)
- **POC discovery** from a dozen sources with a configurable worker pool: poc-in-github, search-vulns, ExploitDB, trickest/cve, Metasploit, Nuclei templates, tg12/PoC_CVEs, Awesome-CVE-POC-Index, VulnCheck XDB/Initial Access
- **Local SQLite cache**: POC results, CVE metadata (with KEV flags), and bulk indexes are cached in a single database with TTLs, revision checks, and forced refresh via `pochunter update`
- **KEV enrichment**: CISA/VulnCheck Known Exploited Vulnerabilities flagged with a red `[KEV]` marker
- **Version canonicalization**: detects, extracts, and compares software versions (`7.0`, `8.5p1`, `v1.2.3`, `20.0-u1559`, `7.0a1`)
- **CPE-based filtering**: NVD results are filtered against CPE configurations (version ranges, vendor/product fields)
- **Match reasons**: every CVE finding is labeled (`cpe_version`, `version_in_range`, `cpe_product`, `description`) and exposed in machine-readable output
- **Rate-limit suppression**: duplicate 429 warnings print once per source; source errors are hidden by default and shown with `-v`
- **TTY-aware output**: colors, bold headers, and severity-colored scores in the terminal; plain, stable-width output when piped (`NO_COLOR`/`FORCE_COLOR` honored)
- Exact variant matching in descriptions (zero-padding and same-length wildcards on token boundaries), so `7.0` never matches `7.57.0`
- CVE nickname aliases: `shellshock`, `heartbleed`, `logjam` and friends map to their product names

## Install

From a release (recommended):

```bash
# grab the latest binary for your OS/arch from the releases page
# https://github.com/Fakechippies/pochunter/releases
```

From source:

```bash
go install github.com/Fakechippies/pochunter/cmd/pochunter@latest
```

## Quick start

```bash
pochunter --search curl 7.0                 # free-form search, version auto-detected
pochunter --app django --version 3.2        # structured product/version query
pochunter -poc CVE-2026-38526               # hunt POCs for a known CVE
pochunter update                            # refresh cached data sources
```

## Usage

### Modes

**Free-form search (default)** — dump any keywords, no version required. Results are sorted by CVSS score. Pass the product and version as free-form keywords and pochunter splits them automatically (`--search curl version 7.0` works too).

```bash
pochunter --search ShellShock
pochunter --search log4j
pochunter --search Krayin CRM 2.20 --vendor Webkul --ecosystem php
```

**Structured product/version mode** — for precise lookups:

```bash
pochunter --app django --version 3.2 --ecosystem PyPI --timeout 20s
```

**Direct POC mode** — skip CVE discovery, search POCs by CVE ID:

```bash
pochunter -poc CVE-2026-38526
pochunter -poc CVE 2026 38526
```

### Flags

| Flag | Description |
|------|-------------|
| `--search` | Free-form keyword search (no version required) |
| `--poc` / `-poc` | Direct POC mode (CVE ID input) |
| `--app` | Application/product name (structured mode) |
| `--version` | Application version (structured mode) |
| `--vendor` | Vendor name (search hint) |
| `--ecosystem` | Package ecosystem (`npm`, `pypi`, `go`, `maven`, `rubygems`, ...) |
| `--sources` | Comma-separated CVE sources (`nvd,circl,osv,vulners,github`) |
| `--output` / `-o` | Output format: `table` (default), `json`, `jsonl`, `csv` |
| `--timeout` | Request timeout (default 30s) |
| `--db` | Cache database path (overrides `POCHUNTER_DB`) |
| `--no-cache` | Disable all local caching |
| `--refresh` | Bypass cache reads but still write |
| `--cache-ttl` | POC cache freshness (default 24h) |
| `--cve-ttl` | CVE query cache freshness (default 30m) |
| `-v` / `--verbose` | Show per-source API errors (hidden by default) |

### Output formats

Machine-readable formats write results to **stdout** and route progress/errors to **stderr**, so output pipes straight into `jq` or a file. CSV includes a `match` column with the finding's match reason.

```bash
pochunter --search curl 7.0 --output json | jq '.cve_findings[].cve'
pochunter --search log4j -o jsonl > results.jsonl
pochunter --app django --version 3.2 --ecosystem PyPI -o csv > django.csv
```

## Sources

| Source | Type | Auth | Notes |
|--------|------|------|-------|
| `nvd` | CVE | None / `NVD_API_KEY` / `VULNCHECK_API_TOKEN` | CPE-name queries via local CPE dictionary, CPE config filtering, description fallback. Uses the VulnCheck NVD++ mirror (higher limits, extra enrichment) when its token is set |
| `circl` | CVE | None | `cve.circl.lu/api/search/{vendor}/{product}` |
| `osv` | CVE | None | Ecosystem-based (`--ecosystem` required), POST to `api.osv.dev/v1/query` |
| `vulners` | CVE | `VULNERS_API_KEY` | v4 audit API with structured CPE objects |
| `github` | CVE | `GITHUB_TOKEN` | GitHub Advisories (`--ecosystem` required) |
| `poc-in-github` | POC | None | poc-in-github.motikan2010.net API |
| `search-vulns` | POC | `SEARCHVULNS_API_KEY` | search-vulns.com API |
| `exploitdb` | POC | None | Bulk: `files_exploits.csv`, ETag-tracked |
| `trickest` | POC | None | Bulk: `github.txt` CVE→repo links |
| `metasploit` | POC | None | Bulk: `modules_metadata_base.json` (CVEs from `references[]`) |
| `nuclei` | POC | None | Bulk: nuclei-templates `cves.json` (NDJSON) |
| `tg12` | POC | None | Bulk: tg12/PoC_CVEs box-format `cve_links.txt` |
| `awesome-cve-poc` | POC | None | Bulk: 11 per-year markdown indexes |
| `vulncheck-xdb` | POC | `VULNCHECK_API_TOKEN` | On-demand API. **Paid index** (402 on community tokens) |
| `vulncheck-iac` | POC | `VULNCHECK_API_TOKEN` | On-demand API, community tier, ~50 high-quality CVEs |

## Environment variables

| Variable | Purpose |
|----------|---------|
| `VULNCHECK_API_TOKEN` | VulnCheck API (official SDK/CLI name; `VULNCHECK_API_KEY` also accepted). Enables vulncheck-xdb, vulncheck-iac, the NVD++ mirror and the CPE dictionary build |
| `VULNERS_API_KEY` | Vulners CVE source |
| `GITHUB_TOKEN` | GitHub Advisories CVE source |
| `SEARCHVULNS_API_KEY` | search-vulns POC source |
| `NVD_API_KEY` | NVD API key (CPE dictionary build without a VulnCheck token) |
| `POCHUNTER_DB` | Cache database path (default `os.UserCacheDir()/pochunter/pochunter.db`) |
| `NO_COLOR` / `FORCE_COLOR` | Disable/force ANSI colors |

API-keyed sources are included automatically when their env var is set; filter with `--sources`.

## How it works

1. **Resolve input** — free-form queries are split into product/version (`curl 7.0`), aliases expanded (`shellshock` → bash)
2. **Resolve CPE** — the query is matched against the official CPE Dictionary (cached locally); a confident match switches NVD to exact `cpeName`/`virtualMatchString` queries
3. **Discover CVEs** — all selected CVE sources are queried concurrently, results deduplicated by CVE+source+detail, labeled with match reasons, sorted by CVSS
4. **Hunt POCs** — for every unique CVE, all POC sources are queried (worker pool, max 8 concurrent); bulk-index sources answer from the local SQLite cache
5. **Cache & enrich** — everything lands in one SQLite database (POC findings with TTL, CVE bare info, KEV flags, bulk indexes with revision checks); `pochunter update` force-refreshes, and a new app version automatically invalidates derived data

## Library usage

This is also a Go library. Import the packages you need:

```go
import (
    "context"
    "time"

    "github.com/Fakechippies/pochunter/cve"
    "github.com/Fakechippies/pochunter/cpe"
    "github.com/Fakechippies/pochunter/httpclient"
    "github.com/Fakechippies/pochunter/poc"
    "github.com/Fakechippies/pochunter/versioncanon"
)
```

Query a single CVE source:

```go
src := cve.NVDSource{}
findings, err := src.Query(ctx, "", "log4j", "", "")
for _, f := range findings {
    fmt.Println(f.CVE, f.Score, f.Reason)
}
```

Query all sources concurrently, then hunt POCs:

```go
sources := []cve.Source{
    cve.NVDSource{},
    cve.CIRCLSource{},
    cve.OSVSource{},
    &cve.VulnersSource{APIKey: os.Getenv("VULNERS_API_KEY")},
}

var all []cve.Finding
for _, s := range sources {
    findings, err := s.Query(ctx, "apache", "log4j", "2.0", "maven")
    if err != nil {
        continue
    }
    all = append(all, findings...)
}
```

Query POCs for a CVE (with the SQLite cache decorator):

```go
cache, _ := db.Open("/path/to/pochunter.db")
pocSources := []poc.Source{
    poc.CachedSource{Inner: poc.POCInGithub{}, DB: cache, TTL: 24 * time.Hour},
    &poc.ExploitDB{BulkSource: poc.BulkSource{DB: cache}},
}
for _, src := range pocSources {
    pocs, err := src.Query(ctx, "CVE-2026-38526")
    for _, p := range pocs {
        fmt.Println(p.CVE, p.Owner, p.POC)
    }
}
```

Resolve a free-form query to a CPE name:

```go
rows, _ := cache.CPEEntriesCached()
entries := cpe.LoadEntries(rows)
name, product, version, ok := cpe.ResolveApp("apache http server 2.4.39", entries)
```

### Version canonicalization

```go
versioncanon.IsVersion("7.0")                              // true
versioncanon.ExtractAppAndVersion("curl 7.0")              // app="curl", ver="7.0"
versioncanon.Compare("7.0", "7.0.0")                       // 0 (equal)
versioncanon.Compare("20.0-update1559", "20.0-u1559")      // 0 (CPE update forms equal)
versioncanon.Compare("1.1.1k", "1.1.1")                    // 1 (letter release after)
versioncanon.Compare("2.0.0-rc1", "2.0.0")                 // -1 (pre-release before)
versioncanon.MatchesRange("7.0", "7.0", "", "", "7.15.0")  // true
versioncanon.MatchVersionInText("curl 7.0 buffer overflow", "7.0") // true
versioncanon.MatchVersionInText("fixed in curl 7.57.0", "7.57.0")  // false (negated context)
versioncanon.ExactVariants("2.2.0")                        // zero-padding + wildcard variants
```

### Finding struct

`cve.Finding` includes a `Score` field (CVSS base score, v3.1 → v3.0 → v2.0) and a `Reason` field (why the finding matched). Other sources leave both empty where not applicable.

## Roadmap

- `pochunter recent` — fresh CVEs from cvelistV5 deltas or VulnCheck's mitre-cvelist-v5 index
- EPSS enrichment into the local CVE table (FIRST EPSS API)
- Distro backpatch awareness (Debian/Ubuntu/RHEL)
- Fancier table rendering on top of the new TTY-aware output

## Disclaimer

pochunter aggregates publicly available vulnerability and exploit information for defensive research and authorized testing. You are responsible for complying with the terms of the upstream data sources and for what you do with this tool.
