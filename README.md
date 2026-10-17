# POC-Hunter

CLI tool to discover CVEs and hunt public POCs, free-form search or structured product/version queries.

## What it does

- CVE discovery from **NVD**, **CIRCL**, **OSV**, **Vulners**, and **GitHub Advisories**
- All CVE sources queried concurrently, results deduplicated
- POC discovery from **poc-in-github** and **search-vulns** with a configurable worker pool (max 8)
- Direct POC mode with `--poc` / `-poc`
- **Version canonicalization** — detects, extracts, and compares software versions (e.g. `7.0`, `8.5p1`, `v1.2.3`)
- **CPE-based filtering** — NVD checks CPE configurations (version ranges, vendor/product fields) to eliminate false positives
- **Rate-limit suppression** — duplicate 429 warnings are printed only once per source; rate-limited sources are skipped
- Exact variant matching in descriptions (zero-padding and same-length wildcards) on token boundaries, so `7.0` never matches `7.57.0`
- Selectable CVE sources via `--sources` flag
- CVSS scoring: free-form search results sorted by score with a SCORE column
- Terminal width auto-detection (ioctl TIOCGWINSZ) for full-screen table output
- Word-splitting fallback: if multi-word search returns 0 results, each word is tried individually
- CVE nickname aliases: common names like `shellshock`, `heartbleed`, `logjam` mapped to their product names
- Auto-detects version in free-form queries (e.g. `--search curl 7.0` splits into product=`curl`, version=`7.0`)
- Proper table formatting with word-wrapped DETAIL column
- Vulners source uses `/api/v4/audit/software` (CPE-based, partial match, extended catalog)

## Install

```bash
go install github.com/Fakechippies/POC-Hunter/cmd/pochunter@latest
```

Then run:

```bash
pochunter --search <keywords...>
```

## Modes

### 1) Free-form search (default)

Dump any keywords: no version required. Results are sorted by CVSS score (highest first) and include a SCORE column. Known CVE nicknames like `shellshock`, `heartbleed`, `logjam`, `spectre`, `meltdown` are automatically mapped to their product names.

**Version auto-detection:** pass the product and version as free-form keywords and POC-Hunter automatically splits them into a structured product/version query.

```bash
go run ./cmd/pochunter --search ShellShock
go run ./cmd/pochunter --search shellshock 4.3 bash
go run ./cmd/pochunter --search log4j
go run ./cmd/pochunter --search Krayin CRM 2.20 --vendor Webkul --ecosystem php
go run ./cmd/pochunter --search django 4.2 --sources nvd,vulners
# Auto-detects "curl" and "7.0" from free-form input
go run ./cmd/pochunter --search curl 7.0
# Also handles prefix words: "curl version 7.0"
go run ./cmd/pochunter --search curl version 7.0
```

### 2) Structured product/version mode

For precise product/version lookups:

```bash
go run ./cmd/pochunter --app django --version 3.2 --ecosystem PyPI --timeout 20s
go run ./cmd/pochunter --app "<APP-NAME>" --version <VERSION>
```

Optional source hints for either mode:

| Flag | Description |
|------|-------------|
| `--vendor` | Vendor name (search hint) |
| `--ecosystem` | Package ecosystem (`npm`, `pypi`, `go`, `maven`, etc.) |
| `--sources` | Comma-separated CVE sources (`nvd,circl,osv,vulners,github`) |

Optional API-backed CVE sources:

```bash
export VULNERS_API_KEY="<your-vulners-key>"
export GITHUB_TOKEN="<your-github-token>"
```

These are automatically included when their env var is set, and can be filtered with `--sources`.

Optional API-backed POC sources:

```bash
export SEARCHVULNS_API_KEY="<your-search-vulns-key>"
```

Automatically included when the env var is set.

### 2) Direct POC mode

Skip CVE discovery and directly search POCs by CVE ID.

```bash
go run ./cmd/pochunter -poc CVE-2026-38526
go run ./cmd/pochunter -poc CVE 2026 38526
```

## Available CVE sources

| Flag     | Source            | Auth              | Notes |
|----------|-------------------|-------------------|-------|
| `nvd`    | NVD API 2.0       | None              | CPE configuration parsing with version range filtering (startInc, endExc, etc.). Product matching via normalized vendor/product fields. False positives prevented (e.g. "curl 7.0" won't match SQL Server 7.0). |
| `circl`  | CIRCL CVE search  | None              | Queries `cve.circl.lu/api/search/{vendor}/{product}`. Falls back to `vendor=product` if vendor is empty. Auto-extracts version from product string. |
| `osv`    | OSV.dev           | None              | Package-ecosystem based. **Requires `--ecosystem`**. POSTs version+package to `api.osv.dev/v1/query`. Resolves aliases to CVEs. |
| `vulners`| Vulners v4 audit  | `VULNERS_API_KEY` | Uses `POST /api/v4/audit/software` with structured CPE objects (`"match": "partial"`, `"catalog": "extended"`). Auto-extracts version from product string. |
| `github` | GitHub Advisories | `GITHUB_TOKEN`    | **Requires `--ecosystem`**. Queries `api.github.com/advisories` with ecosystem+package filter. |

## Flags

| Flag             | Description                                      |
|------------------|--------------------------------------------------|
| `--search`       | Free-form keyword search (no version required)   |
| `--poc` / `-poc` | Direct POC mode (CVE ID input)                   |
| `--app`          | Application/product name (structured mode)       |
| `--version`      | Application version (structured mode)            |
| `--vendor`       | Vendor name (search hint)                        |
| `--ecosystem`    | Package ecosystem (`npm`, `pypi`, `go`, `maven`, `rubygems`, etc.) |
| `--sources`      | Comma-separated CVE sources to query             |
| `--timeout`      | Request timeout (default 30s)                    |

## CVE discovery 

1. All selected CVE sources are queried **concurrently** via goroutines.
2. Results are **deduplicated** by CVE + source + detail.
3. Unique CVE IDs are collected and sorted.
4. For each unique CVE, all POC sources are queried (worker pool, **max 8** concurrent).
5. POC findings are flattened and sorted by CVE → owner → URL.

## POC sources

| Source          | Auth                 | Description                                      |
|-----------------|----------------------|--------------------------------------------------|
| `poc-in-github` | None                 | Queries `poc-in-github.motikan2010.net/api/v1/?cve_id=` |
| `search-vulns`  | `SEARCHVULNS_API_KEY`| Queries `search-vulns.com/api/search-vulns?query=` |

## Library usage

This is also a Go library. Import the packages you need:

```go
import (
    "context"
    "time"

    "github.com/Fakechippies/POC-Hunter/cve"
    "github.com/Fakechippies/POC-Hunter/httpclient"
    "github.com/Fakechippies/POC-Hunter/poc"
    "github.com/Fakechippies/POC-Hunter/versioncanon"
)
```

Query a single CVE source:

```go
src := cve.NVDSource{}
findings, err := src.Query(ctx, "", "log4j", "", "")
for _, f := range findings {
    fmt.Println(f.CVE, f.Score, f.Detail)
}
```

Query all sources concurrently:

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

Query POCs for a CVE:

```go
pocSources := []poc.Source{poc.POCInGithub{}}
for _, src := range pocSources {
    pocs, err := src.Query(ctx, "CVE-2026-38526")
    for _, p := range pocs {
        fmt.Println(p.CVE, p.Owner, p.POC)
    }
}
```

### Version canonicalization

The `versioncanon` package provides utilities to work with software versions:

```go
// Detect if a token is a version (7.0, 8.5p1, v1.2.3)
versioncanon.IsVersion("7.0") // true
versioncanon.IsVersion("curl") // false

// Extract product and version from free-form input
app, ver := versioncanon.ExtractAppAndVersion("curl 7.0")
// app="curl", ver="7.0"

// Compare versions: zero-padding and leading zeros ignored,
// letter releases (OpenSSL 1.1.1k) and pre-releases (2.0.0-rc1) ordered.
versioncanon.Compare("7.0", "7.0.0")     // 0 (equal)
versioncanon.Compare("7.0", "7.10.7")    // -1 (7.0 < 7.10.7)
versioncanon.Compare("1.1.1", "1.1.1k")  // -1 (letter release comes after)
versioncanon.Compare("2.0.0-rc1", "2.0.0") // -1 (pre-release comes before)

// Check if version falls within a range
versioncanon.MatchesRange("7.0", "7.0", "", "", "7.15.0") // true ([7.0, 7.15.0))
versioncanon.MatchesRange("1.1.1k", "", "", "", "1.1.1l") // true (< 1.1.1l)

// Boundary-aware version matching in text; occurrences in negating
// contexts (before/prior to/fixed in/earlier than/<) are skipped
versioncanon.MatchVersionInText("curl 7.0 buffer overflow", "7.0") // true
versioncanon.MatchVersionInText("fixed in curl 7.57.0", "7.57.0") // false
versioncanon.MatchVersionInText("curl 7.57.0", "7.0") // false (no false positive)

// ExactVariants holds only information-preserving equivalents (zero-padding
// and same-length wildcards); MatchVersionInText uses these.
versioncanon.ExactVariants("2.2.0")
// ["v2.2.0.0", "v2.2.0.x", "2.2.0.0", "2.2.0.x", "v2.2.0", "2.2.0", "v2.2", "2.2"]

// Variants is a superset that also drops non-zero components, for fuzzy/research use.
versioncanon.Variants("2.2.0") // adds "2.2.x", "2.x", "2", "2.2.*", ...

// MatchVersionInTextAny is the loose counterpart to MatchVersionInText: it also
// matches coarse/wildcard variants, e.g. "2.2.0" against "v2.2.x".
versioncanon.MatchVersionInTextAny("an issue in v2.2.x", "2.2.0") // true
```

Make raw API calls with the HTTP client:

```go
var result map[string]interface{}
err := httpclient.JSON(ctx, "GET", "https://api.example.com/data",
    map[string]string{"Authorization": "Bearer token"}, nil, &result,
)
```

### Finding struct

`cve.Finding` includes a `Score` field with the CVSS base score (parsed from NVD, prefers v3.1 → v3.0 → v2.0). Other sources leave it at `0.0`.

```go
type Finding struct {
    CVE    string
    Source string
    Detail string
    Score  float64
}
```

### Packages

| Package        | Import path                                    | Description |
|----------------|------------------------------------------------|-------------|
| `cve`          | `github.com/Fakechippies/POC-Hunter/cve`        | Source interface + NVD, CIRCL, OSV, Vulners, GitHub Advisories |
| `poc`          | `github.com/Fakechippies/POC-Hunter/poc`        | Source interface + poc-in-github, search-vulns |
| `httpclient`   | `github.com/Fakechippies/POC-Hunter/httpclient` | Shared HTTP/JSON client used by all sources |
| `versioncanon` | `github.com/Fakechippies/POC-Hunter/versioncanon`| Version canonicalization: detection, extraction, comparison, and fuzzy matching |

## Tests

17 unit tests across 3 packages (`versioncanon`, `cve`, `cli`) covering version canonicalization, product/version matching, and CLI search input resolution:

```bash
go test ./...
```

## TODO:

- [ ] Add output formats (JSON/CSV).
- [ ] Add caching and retry/backoff.
