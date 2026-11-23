package db

import (
	"net/url"
	"strings"
	"time"
)

var ownerHosts = map[string]struct{}{
	"github.com":    {},
	"gitee.com":     {},
	"gitlab.com":    {},
	"bitbucket.org": {},
}

// CanonicalURL normalizes a POC link for storage and deduplication:
// surrounding whitespace is trimmed, http is upgraded to https, fragments are
// dropped and a single trailing slash is removed. Empty input stays empty.
func CanonicalURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, "/")
	return "https://" + s
}

// ExtractOwner derives an owner/account name from a POC link. For known git
// hosts it is the first path segment; for other URLs it is the host itself.
// Returns "" for empty input.
func ExtractOwner(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		// Scheme-less input ("github.com/o/r"): retry with an implied scheme.
		u, err = url.Parse("https://" + s)
		if err != nil || u.Host == "" {
			return ""
		}
	}
	if _, ok := ownerHosts[u.Host]; ok {
		seg := strings.Trim(u.Path, "/")
		if i := strings.IndexByte(seg, '/'); i >= 0 {
			seg = seg[:i]
		}
		if seg != "" {
			return seg
		}
	}
	return u.Host
}

// dateLayouts lists the timestamp formats POC sources emit. First match wins.
var dateLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02",
	"2006/01/02",
	"02-01-2006",
	"01-02-2006",
	"January 02, 2006",
	"Mon, 02 Jan 2006 15:04:05 -0700", // RFC1123Z (RSS feeds)
}

// NormalizeDate parses a timestamp from any of the formats POC sources use
// and returns it as RFC3339 (UTC). Unparseable input yields "".
func NormalizeDate(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return ""
}

// CleanDetail collapses all whitespace runs (including newlines) in a
// description into single spaces and trims the result.
func CleanDetail(s string) string {
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}
