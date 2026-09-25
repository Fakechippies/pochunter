package versioncanon

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	// versionRegex matches tokens that look like software versions, e.g.:
	// 7.0, 7.0.1, 2.4.49, 8.5p1, 1.1.1k, 2.20, 1.0.0-rc1, v1.2, 7.0.x
	versionRegex = regexp.MustCompile(`^[vV]?[0-9]+(\.[0-9a-zA-Z_*xX-]+)+$`)
	// pureVRegex matches v1, v2, etc.
	pureVRegex = regexp.MustCompile(`^[vV][0-9]+$`)
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

// ExtractAppAndVersion splits a free-form query or keyword list into application name and version.
// For example:
//   "curl 7.0"             -> app="curl", version="7.0"
//   "curl version 7.0"     -> app="curl", version="7.0"
//   "apache tomcat 9.0.50" -> app="apache tomcat", version="9.0.50"
//   "django 4.2"           -> app="django", version="4.2"
//   "log4j"                -> app="log4j", version=""
//   "apache tomcat"        -> app="apache tomcat", version=""
func ExtractAppAndVersion(query string) (string, string) {
	words := strings.Fields(strings.TrimSpace(query))
	if len(words) < 2 {
		return strings.TrimSpace(query), ""
	}

	last := words[len(words)-1]
	if IsVersion(last) {
		appWords := words[:len(words)-1]
		if len(appWords) > 0 {
			prev := strings.ToLower(appWords[len(appWords)-1])
			if prev == "v" || prev == "version" || prev == "ver" {
				appWords = appWords[:len(appWords)-1]
			}
		}
		if len(appWords) > 0 {
			return strings.Join(appWords, " "), last
		}
	}

	return strings.TrimSpace(query), ""
}

// Variants returns all canonical variant representations of a version string
// for fuzzy and exact matching across vulnerability databases and advisories.
func Variants(version string) []string {
	v := Normalize(version)
	if v == "" {
		return nil
	}

	set := map[string]struct{}{
		v:              {},
		"v" + v:        {},
		v + ".x":       {},
		"v" + v + ".x": {},
		v + ".*":       {},
	}

	parts := strings.Split(v, ".")
	if len(parts) == 1 {
		set[parts[0]+".0"] = struct{}{}
		set["v"+parts[0]+".0"] = struct{}{}
		set[parts[0]+".0.0"] = struct{}{}
		set["v"+parts[0]+".0.0"] = struct{}{}
		set[parts[0]+".x"] = struct{}{}
		set["v"+parts[0]+".x"] = struct{}{}
	} else if len(parts) == 2 {
		majorMinor := parts[0] + "." + parts[1]
		set[majorMinor] = struct{}{}
		set["v"+majorMinor] = struct{}{}
		set[majorMinor+".x"] = struct{}{}
		set["v"+majorMinor+".x"] = struct{}{}
		set[majorMinor+".*"] = struct{}{}

		// 7.0 is equivalent to 7.0.0
		patchZero := majorMinor + ".0"
		set[patchZero] = struct{}{}
		set["v"+patchZero] = struct{}{}
		set[parts[0]+".x"] = struct{}{}
		set["v"+parts[0]+".x"] = struct{}{}
	} else if len(parts) >= 3 {
		majorMinor := parts[0] + "." + parts[1]
		set[majorMinor] = struct{}{}
		set["v"+majorMinor] = struct{}{}
		set[majorMinor+".x"] = struct{}{}
		set["v"+majorMinor+".x"] = struct{}{}
		set[majorMinor+".*"] = struct{}{}
		set[parts[0]+".x"] = struct{}{}

		if parts[2] == "0" {
			set[majorMinor] = struct{}{}
			set["v"+majorMinor] = struct{}{}
		}
	}

	var variants []string
	for token := range set {
		variants = append(variants, token)
	}

	// Sort longer variants first so more specific patterns can be matched first
	sort.Slice(variants, func(i, j int) bool {
		if len(variants[i]) == len(variants[j]) {
			return variants[i] < variants[j]
		}
		return len(variants[i]) > len(variants[j])
	})

	return variants
}

// Normalize cleans up a version string by stripping prefixes ('v', '=', etc.)
// and trimming whitespace.
func Normalize(version string) string {
	v := strings.ToLower(strings.TrimSpace(version))
	for _, prefix := range []string{"<=", ">=", "==", "=", "<", ">", "~", "^", "@", "v"} {
		v = strings.TrimPrefix(v, prefix)
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
		// Only trim leading zeros if the part is numeric
		isNum := true
		for _, r := range part {
			if r < '0' || r > '9' {
				isNum = false
				break
			}
		}
		if isNum {
			trimmed := strings.TrimLeft(part, "0")
			if trimmed == "" {
				trimmed = "0"
			}
			parts[i] = trimmed
		} else {
			parts[i] = part
		}
	}

	return strings.Join(parts, ".")
}

// MatchVersionInText checks if any canonical variant of version appears in text
// on proper token/version boundaries. This prevents "7.0" from erroneously matching
// "7.57.0", "2.7.0.2", "7.27.0", or "3.57.0".
func MatchVersionInText(text string, version string) bool {
	if version == "" {
		return true
	}
	variants := Variants(version)
	lowerText := strings.ToLower(text)

	for _, v := range variants {
		vLower := strings.ToLower(v)
		idx := 0
		for {
			pos := strings.Index(lowerText[idx:], vLower)
			if pos == -1 {
				break
			}
			absPos := idx + pos
			endPos := absPos + len(vLower)
			idx = endPos

			// Check boundary before
			validBefore := false
			if absPos == 0 {
				validBefore = true
			} else {
				prev := lowerText[absPos-1]
				// Valid before: whitespace, punctuation, brackets, quotes, etc., but NOT digit or dot
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
				// If next is a dot, it is only valid if followed by space or punctuation or end of text (e.g. "version 7.0.")
				if next == '.' {
					if endPos+1 == len(lowerText) || !isAlnum(lowerText[endPos+1]) {
						validAfter = true
					}
				} else if !isAlnum(next) {
					validAfter = true
				}
			}
			if validAfter {
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

// ParseVersionSegments extracts numeric components from a version string for comparison.
func ParseVersionSegments(v string) []int {
	v = strings.ToLower(strings.TrimSpace(v))
	for _, p := range []string{"<=", ">=", "==", "=", "<", ">", "~", "^", "@", "v"} {
		v = strings.TrimPrefix(v, p)
	}
	parts := strings.Split(v, ".")
	var segs []int
	for _, p := range parts {
		var numStr string
		for _, r := range p {
			if r >= '0' && r <= '9' {
				numStr += string(r)
			} else {
				break
			}
		}
		if numStr == "" {
			segs = append(segs, 0)
		} else {
			n, _ := strconv.Atoi(numStr)
			segs = append(segs, n)
		}
	}
	// Trim trailing zeros so 7.0 compares equal to 7.0.0
	for len(segs) > 1 && segs[len(segs)-1] == 0 {
		segs = segs[:len(segs)-1]
	}
	return segs
}

// Compare compares two version strings numerically.
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
func Compare(v1, v2 string) int {
	s1 := ParseVersionSegments(v1)
	s2 := ParseVersionSegments(v2)
	maxLen := len(s1)
	if len(s2) > maxLen {
		maxLen = len(s2)
	}
	for i := 0; i < maxLen; i++ {
		p1, p2 := 0, 0
		if i < len(s1) {
			p1 = s1[i]
		}
		if i < len(s2) {
			p2 = s2[i]
		}
		if p1 < p2 {
			return -1
		}
		if p1 > p2 {
			return 1
		}
	}
	return 0
}

// MatchesRange checks if target version falls within a range specified by start/end constraints.
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
