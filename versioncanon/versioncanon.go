package versioncanon

import (
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var (
	// versionRegex matches tokens that look like software versions, e.g.:
	// 7.0, 7.0.1, 2.4.49, 8.5p1, 1.1.1k, 2.20, 1.0.0-rc1, v1.2, 7.0.x
	versionRegex = regexp.MustCompile(`^[vV]?[0-9]+(\.[0-9a-zA-Z_*xX-]+)+$`)
	// pureVRegex matches v1, v2, etc.
	pureVRegex = regexp.MustCompile(`^[vV][0-9]+$`)
	// pureIntRegex matches bare integers like 17, 2003.
	pureIntRegex = regexp.MustCompile(`^[0-9]+$`)
)

// IsVersion returns true if s looks like a version identifier rather than a product name.
func IsVersion(s string) bool {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "=")
	s = strings.TrimPrefix(s, "^")
	s = strings.TrimPrefix(s, "~")
	s = strings.TrimPrefix(s, "@")
	if s == "" {
		return false
	}
	return versionRegex.MatchString(s) || pureVRegex.MatchString(s)
}

func isMarkerWord(w string) bool {
	l := strings.ToLower(w)
	return l == "v" || l == "ver" || l == "version"
}

// isVersionToken reports whether word is a version token in the context of prev.
// Bare integers ("17") and pure v-prefixed integers ("v8") only count as versions
// when preceded by an explicit version marker, because they are ambiguous
// product names (Node 18, Chrome V8) otherwise.
func isVersionToken(word, prev string) bool {
	if versionRegex.MatchString(word) {
		return true
	}
	if pureVRegex.MatchString(word) || pureIntRegex.MatchString(word) {
		return isMarkerWord(prev)
	}
	return false
}

// ExtractAppAndVersion splits a free-form query or keyword list into application name and version.
// Version tokens are searched anywhere in the input (the rightmost one wins); the token
// and an immediately preceding "v"/"ver"/"version" marker are removed from the remaining keywords.
// For example:
//
//	"curl 7.0"                  -> app="curl", version="7.0"
//	"curl version 7.0"          -> app="curl", version="7.0"
//	"shellshock 4.3 bash"       -> app="shellshock bash", version="4.3"
//	"django 4.2 sql injection"  -> app="django sql injection", version="4.2"
//	"apache tomcat 9.0.50"      -> app="apache tomcat", version="9.0.50"
//	"openssh 8.5p1"             -> app="openssh", version="8.5p1"
//	"log4j"                     -> app="log4j", version=""
//	"chrome v8"                 -> app="chrome v8", version=""  (V8 parses as product)
func ExtractAppAndVersion(query string) (string, string) {
	words := strings.Fields(strings.TrimSpace(query))
	if len(words) < 2 {
		return strings.TrimSpace(query), ""
	}

	verIdx := -1
	for i := len(words) - 1; i >= 1; i-- {
		if isVersionToken(words[i], words[i-1]) {
			verIdx = i
			break
		}
	}
	if verIdx < 0 {
		return strings.TrimSpace(query), ""
	}

	dropMarker := verIdx-1 >= 0 && isMarkerWord(words[verIdx-1])
	appWords := make([]string, 0, len(words)-2)
	for i, w := range words {
		if i == verIdx || (dropMarker && i == verIdx-1) {
			continue
		}
		appWords = append(appWords, w)
	}
	if len(appWords) == 0 {
		return strings.TrimSpace(query), ""
	}
	return strings.Join(appWords, " "), words[verIdx]
}

// Normalize cleans up a version string by stripping prefixes ('v', operator
// characters) and whitespace. Leading zeros are intentionally preserved
// (7.01 stays 7.01, 2024.01 stays 2024.01) since they matter to some version
// schemes; numeric comparison via Compare ignores them anyway.
func Normalize(version string) string {
	v := strings.ToLower(strings.TrimSpace(version))
	for _, prefix := range []string{"<=", ">=", "==", "=", "<", ">", "~", "^", "@"} {
		v = strings.TrimPrefix(v, prefix)
	}
	if len(v) >= 2 && v[0] == 'v' && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}

	parts := strings.Split(v, ".")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			parts[i] = "0"
			continue
		}
		parts[i] = part
	}

	return strings.Join(parts, ".")
}

// ExactVariants returns canonical textual variants that are information-preserving
// equivalents of the version string: "v" prefix, zero-padding ("7.0" == "7.0.0"),
// and same-length "x"/"*" wildcards. Coarser variants that drop non-zero
// components (e.g. "2.4.49" -> "2.4") are deliberately excluded because matching
// them against free text causes false positives.
func ExactVariants(version string) []string {
	v := Normalize(version)
	if v == "" {
		return nil
	}

	set := map[string]struct{}{
		v:              {},
		"v" + v:        {},
		v + ".x":       {},
		"v" + v + ".x": {},
	}

	parts := strings.Split(v, ".")
	allNum := true
	for _, p := range parts {
		if p == "" {
			p = "0"
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				allNum = false
				break
			}
		}
		if !allNum {
			break
		}
	}

	if allNum {
		// Zero-padding equivalents. Trailing zero components may always be
		// added or dropped: "7.0.0" -> "7.0" -> "7" and back.
		n := len(parts)
		for n > 1 && parts[n-1] == "0" {
			n--
			shortened := strings.Join(parts[:n], ".")
			set[shortened] = struct{}{}
			set["v"+shortened] = struct{}{}
		}
		// Padded forms ("7" -> "7.0" -> "7.0.0"), capped at 4 components.
		for len(parts) < 4 {
			v = v + ".0"
			set[v] = struct{}{}
			set["v"+v] = struct{}{}
			parts = append(parts, "0")
		}
	}

	variants := make([]string, 0, len(set))
	for t := range set {
		variants = append(variants, t)
	}
	sort.Slice(variants, func(i, j int) bool {
		if len(variants[i]) == len(variants[j]) {
			return variants[i] < variants[j]
		}
		return len(variants[i]) > len(variants[j])
	})
	return variants
}

// Variants returns all canonical variant representations of a version string,
// including short/coarse ones (major.minor, major.x), for fuzzy and loose
// pattern research. For matching free text, prefer MatchVersionInText which
// uses only the information-preserving ExactVariants.
func Variants(version string) []string {
	v := Normalize(version)
	if v == "" {
		return nil
	}

	set := map[string]struct{}{}
	for _, av := range ExactVariants(version) {
		set[av] = struct{}{}
	}
	if _, ok := set[v+".*"]; !ok {
		set[v+".*"] = struct{}{}
		set["v"+v+".*"] = struct{}{}
	}

	parts := strings.Split(v, ".")
	for i := len(parts) - 1; i >= 1; i-- {
		p := strings.Join(parts[:i], ".")
		set[p] = struct{}{}
		set["v"+p] = struct{}{}
		set[p+".x"] = struct{}{}
		set["v"+p+".x"] = struct{}{}
		set[p+".*"] = struct{}{}
	}

	variants := make([]string, 0, len(set))
	for token := range set {
		variants = append(variants, token)
	}

	// Sort longer variants first so more specific patterns can be matched first.
	sort.Slice(variants, func(i, j int) bool {
		if len(variants[i]) == len(variants[j]) {
			return variants[i] < variants[j]
		}
		return len(variants[i]) > len(variants[j])
	})

	return variants
}

type variantPair struct {
	exact  []string
	coarse []string
}

var variantCache sync.Map // version string -> variantPair

func cachedVariants(version string) (exact, coarse []string) {
	if st, ok := variantCache.Load(version); ok {
		p := st.(variantPair)
		return p.exact, p.coarse
	}
	p := variantPair{exact: ExactVariants(version), coarse: Variants(version)}
	variantCache.Store(version, p)
	return p.exact, p.coarse
}

// MatchVersionInText checks if any information-preserving canonical variant of
// version appears in text on proper token/version boundaries. This prevents
// "7.0" from erroneously matching "7.57.0", "2.7.0.2", "7.27.0", or "3.57.0".
// Occurrences in an exclusive/negating context ("before 7.0", "prior to 7.0",
// "fixed in 7.0.1", "versions earlier than 7.0", "< 7.0") are skipped, because
// they denote bounds the queried version is on the *other* side of.
func MatchVersionInText(text string, version string) bool {
	exact, _ := cachedVariants(version)
	return matchVariantsInText(text, version, exact)
}

// MatchVersionInTextAny additionally matches coarse variants ("2.4.49" ->
// "2.4"). It is a loose, lower-confidence match suitable for research/dedup only.
func MatchVersionInTextAny(text string, version string) bool {
	_, coarse := cachedVariants(version)
	return matchVariantsInText(text, version, coarse)
}

func matchVariantsInText(text string, version string, variants []string) bool {
	if version == "" {
		return true
	}
	if len(variants) == 0 {
		return false
	}
	lowerText := strings.ToLower(text)

	for _, v := range variants {
		idx := 0
		for {
			pos := strings.Index(lowerText[idx:], v)
			if pos == -1 {
				break
			}
			absPos := idx + pos
			endPos := absPos + len(v)
			idx = endPos

			// Check boundary before
			validBefore := false
			if absPos == 0 {
				validBefore = true
			} else {
				prev := lowerText[absPos-1]
				// Valid before: whitespace, punctuation, brackets, quotes, etc.,
				// but NOT digit or dot. A "v" is accepted as a prefix marker.
				if !isAlnumOrDot(prev) || (prev == 'v' && (absPos-1 == 0 || !isAlnum(lowerText[absPos-2]))) {
					validBefore = true
				}
			}
			if !validBefore {
				continue
			}

			// Check boundary after
			validAfter := false
			if endPos == len(lowerText) {
				validAfter = true
			} else {
				next := lowerText[endPos]
				// If next is a dot, it is only valid if followed by space or
				// punctuation or end of text (e.g. "version 7.0.")
				if next == '.' {
					if endPos+1 == len(lowerText) || !isAlnum(lowerText[endPos+1]) {
						validAfter = true
					}
				} else if !isAlnum(next) {
					validAfter = true
				}
			}
			if validAfter && !isNegatedContext(lowerText, absPos) {
				return true
			}
		}
	}
	return false
}

func isAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_'
}

func isAlnumOrDot(b byte) bool {
	return isAlnum(b) || b == '.'
}

// isTokChar marks characters that make up a backwards-scanned token: alnum plus
// comparison operators so "<=", "<" and friends are atomic.
func isTokChar(b byte) bool {
	return isAlnum(b) || b == '<' || b == '>' || b == '=' || b == '!'
}

// tokenBackFrom scans backwards from pos for the last token run and returns it
// along with the index where the run starts (-1 with an empty token if none).
func tokenBackFrom(s string, pos int) (string, int) {
	i := pos - 1
	for i >= 0 && !isTokChar(s[i]) {
		i--
	}
	if i < 0 {
		return "", -1
	}
	j := i
	for j >= 0 && isTokChar(s[j]) {
		j--
	}
	return s[j+1 : i+1], j
}

var negWords = map[string]struct{}{
	"before":  {},
	"prior":   {},
	"earlier": {},
	"later":   {},
	"older":   {},
	"newer":   {},
	"below":   {},
	"above":   {},
	"less":    {},
	"greater": {},
	"fixed":   {},
}

// joinerWords connect a negation word to the version bound it applies to,
// e.g. "prior to", "fixed in", "earlier than".
var joinerWords = map[string]struct{}{
	"in":   {},
	"to":   {},
	"than": {},
}

// isNegatedContext inspects the words immediately preceding a match and
// reports whether the occurrence sits in an exclusive/negating context.
func isNegatedContext(text string, pos int) bool {
	w1, i := tokenBackFrom(text, pos)
	if w1 == "" {
		return false
	}
	if _, neg := negWords[w1]; neg {
		return true
	}
	if w1 == "<" || w1 == "<=" || w1 == ">" || w1 == ">=" {
		return true
	}
	if _, j := joinerWords[w1]; j {
		w2, _ := tokenBackFrom(text, i)
		if _, neg := negWords[w2]; neg {
			return true
		}
	}
	return false
}

// vseg is one component of a version: a numeric run or an alphabetic run.
type vseg struct {
	isNum bool
	num   int
	text  string
}

func atoiClamped(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		// Overflow (> int64): saturate rather than warn on a rare edge case.
		return math.MaxInt
	}
	return n
}

// tokenizeRuns splits a version chunk into numeric and alphabetic runs,
// treating '.', '_', ',', '+' and whitespace as separators. Digit/letter
// transitions split as well, so "8.5p1" -> [8, 5, "p", 1] and "1.1.1k" ->
// [1, 1, 1, "k"].
func tokenizeRuns(s string) []vseg {
	var segs []vseg
	var numSB, txtSB strings.Builder
	flushNum := func() {
		if numSB.Len() > 0 {
			segs = append(segs, vseg{isNum: true, num: atoiClamped(numSB.String())})
			numSB.Reset()
		}
	}
	flushTxt := func() {
		if txtSB.Len() > 0 {
			segs = append(segs, vseg{text: txtSB.String()})
			txtSB.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			if txtSB.Len() > 0 {
				flushTxt()
			}
			numSB.WriteRune(r)
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			if numSB.Len() > 0 {
				flushNum()
			}
			txtSB.WriteRune(r)
		default:
			flushNum()
			flushTxt()
		}
	}
	flushNum()
	flushTxt()
	return segs
}

// parseVersionTokens splits a version into its release components and its
// pre-release components (everything after the first '-', e.g. "-rc1").
// CPE-style update sections ("2.0-u1559", "2.0:update1559") are post-release,
// not pre-release: when the section after '-' starts with an update/patch
// marker it is folded into the release tokens instead.
func parseVersionTokens(v string) (rel, pre []vseg) {
	v = Normalize(v)
	if i := strings.IndexByte(v, '-'); i >= 0 {
		pre = tokenizeRuns(v[i+1:])
		v = v[:i]
	}
	rel = tokenizeRuns(v)
	if len(pre) > 0 && !pre[0].isNum && normalizeSegText(pre[0].text) == "u" {
		rel = append(rel, pre...)
		pre = nil
	}
	return rel, pre
}

// segAt pads out-of-range positions with numeric zero, so "7.0" == "7.0.0".
func segAt(segs []vseg, i int) vseg {
	zero := vseg{isNum: true, num: 0}
	if i < len(segs) {
		return segs[i]
	}
	return zero
}

// normalizeSegText folds equivalent textual version markers: alpha/beta
// abbreviations ("a"/"alpha", "b"/"beta") and update/patch separators
// ("u"/"update", "p"/"patch") compare equal, mirroring CPE practice
// (e.g. cpe 2.0:update1559 vs 2.0-u1559).
func normalizeSegText(s string) string {
	switch strings.ToLower(s) {
	case "alpha":
		return "a"
	case "beta":
		return "b"
	case "update", "u", "patch", "p":
		return "u"
	default:
		return strings.ToLower(s)
	}
}

// compareSegs compares two token lists element-wise. Numeric < alphabetic at
// the same position, so letter releases (1.1.1k) sort after the bare number.
// Textual segments compare after normalization (alpha==a, u==update).
func compareSegs(a, b []vseg) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		sa, sb := segAt(a, i), segAt(b, i)
		switch {
		case sa.isNum && sb.isNum:
			if sa.num < sb.num {
				return -1
			}
			if sa.num > sb.num {
				return 1
			}
		case sa.isNum && !sb.isNum:
			return -1
		case !sa.isNum && sb.isNum:
			return 1
		default:
			na, nb := normalizeSegText(sa.text), normalizeSegText(sb.text)
			if na < nb {
				return -1
			}
			if na > nb {
				return 1
			}
		}
	}
	return 0
}

// Compare compares two version strings.
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
//
// Rules:
//   - zero-padding is ignored: "7.0" == "7.0.0" == "7.0.0.0"
//   - leading zeros are ignored: "1.05" == "1.5"
//   - alphabetic releases directly after digits sort after the bare number:
//     "1.1.1" < "1.1.1k" < "1.1.1l" (OpenSSL style), "8.5" < "8.5p1" < "8.5p2"
//   - a pre-release (anything after '-', e.g. "2.0.0-rc1") sorts before the
//     release: "2.0.0-beta" < "2.0.0-rc1" < "2.0.0"
func Compare(v1, v2 string) int {
	r1, p1 := parseVersionTokens(v1)
	r2, p2 := parseVersionTokens(v2)
	if c := compareSegs(r1, r2); c != 0 {
		return c
	}
	if len(p1) == 0 && len(p2) == 0 {
		return 0
	}
	if len(p1) == 0 {
		return 1
	}
	if len(p2) == 0 {
		return -1
	}
	return compareSegs(p1, p2)
}

// MatchesRange checks if target version falls within a range specified by start/end constraints.
// Empty bounds act as unbounded. If all bounds are empty the range is a
// wildcard that matches any non-empty version; callers that want exclusive
// semantics must check for the presence of a bound themselves (as cve/nvd.go
// does for exact CPE version fields).
func MatchesRange(version, startInc, startExc, endInc, endExc string) bool {
	if version == "" {
		return true
	}
	if startInc != "" && Compare(version, startInc) < 0 {
		return false
	}
	if startExc != "" && Compare(version, startExc) <= 0 {
		return false
	}
	if endInc != "" && Compare(version, endInc) > 0 {
		return false
	}
	if endExc != "" && Compare(version, endExc) >= 0 {
		return false
	}
	return true
}
