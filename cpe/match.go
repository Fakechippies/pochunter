package cpe

import (
	"math"
	"regexp"
	"strings"

	"github.com/Fakechippies/POC-Hunter/db"

	"github.com/Fakechippies/POC-Hunter/versioncanon"
)

var (
	splitQueryTerms = regexp.MustCompile(`[^a-zA-Z0-9\.]+`)
	splitEntryTerms = regexp.MustCompile(`[^a-zA-Z0-9]+`)
)

// Match is a successful query-to-CPE resolution.
type Match struct {
	Entry   *entry // pointer into the scanned dictionary
	CPE     string // full CPE 2.3 name with the queried version injected
	Version string // version extracted from the query ("" when none)
	Score   float64
}

type entry struct {
	prefix     string
	product    string // vendor + product, lowercased
	haystack   string // vendor + product + title, lowercased
	titleLower string
}

// ResolveApp matches a free-form query ("apache http server 2.4.39",
// "curl 7.0") to a dictionary entry and returns the full CPE 2.3 name with
// the queried version injected (or "*" when the query had none). ok is false
// when nothing clears the threshold.
func ResolveApp(query string, entries []entry) (cpe string, product, version string, ok bool) {
	product, version = versioncanon.ExtractAppAndVersion(strings.TrimSpace(query))
	if product == "" {
		return "", "", "", false
	}

	terms := terms(product)
	if len(terms) == 0 {
		return "", "", "", false
	}

	best, bestScore := (*entry)(nil), 0.0
	for i := range entries {
		if score := scoreEntry(&entries[i], terms, product); score > bestScore {
			best, bestScore = &entries[i], score
		}
	}
	if best == nil || bestScore < ResolveThreshold {
		return "", "", "", false
	}

	verField := version
	if verField == "" {
		verField = "*"
	}
	full := best.prefix + ":" + verField + ":*:*:*:*:*:*:*"
	return full, product, version, true
}

// scoreEntry scores one dictionary entry against the query terms. Every term
// must appear in the entry's haystack (vendor/product/title); terms found in
// the vendor/product fields count fully, title-only hits count at 60%.
// An exact product-field match gets a bonus.
func scoreEntry(e *entry, terms []string, product string) float64 {
	totalWeight, matchedWeight := 0.0, 0.0
	for i, term := range terms {
		weight := math.Exp2(-float64(i) * 0.25)
		totalWeight += weight
		switch {
		case strings.Contains(e.product, term):
			matchedWeight += weight
		case strings.Contains(e.haystack, term):
			matchedWeight += weight * 0.6
		default:
			return 0 // every term must match
		}
	}
	score := matchedWeight / totalWeight

	// Exact product-name match ranks above products that merely contain the
	// term ("flask" -> flask, not flask-caching).
	prod := strings.TrimPrefix(product, "lib")
	if e.product == prod || e.product == "lib"+prod {
		score = 1.0
	}
	return score
}

// terms splits a product string into lowercase tokens.
func terms(s string) []string {
	var out []string
	for _, t := range splitQueryTerms.Split(strings.ToLower(s), -1) {
		if t != "" && !isStopTerm(t) {
			out = append(out, t)
		}
	}
	return out
}

func isStopTerm(t string) bool {
	switch t {
	case "the", "and", "for", "with", "version", "ver", "lib", "cve":
		return true
	default:
		return false
	}
}

// LoadEntries converts raw dictionary rows into scoring-ready entries.
func LoadEntries(rows []db.CPEEntry) []entry {
	out := make([]entry, 0, len(rows))
	for _, r := range rows {
		product := strings.ToLower(strings.TrimSpace(r.Vendor + " " + r.Product))
		titleLower := strings.ToLower(r.Title)
		out = append(out, entry{
			prefix:     r.Prefix,
			product:    product,
			titleLower: titleLower,
			haystack:   product + " " + titleLower,
		})
	}
	return out
}
