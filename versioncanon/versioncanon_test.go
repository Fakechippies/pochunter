package versioncanon

import (
	"testing"
)

func containsString(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

func TestIsVersion(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"7.0", true},
		{"7.0.1", true},
		{"7.88.1", true},
		{"v1.2.3", true},
		{"v2.4", true},
		{"8.5p1", true},
		{"1.1.1k", true},
		{"2.0-beta", true},
		{"2.20", true},
		{"1.0.0-rc1", true},
		{"v1", true},
		{"7.0.x", true},
		{"curl", false},
		{"log4j", false},
		{"python3", false},
		{"oauth2", false},
		{"x86_64", false},
		{"win32", false},
		{"server", false},
		{"crm", false},
		{"2000", false},
		{"", false},
	}

	for _, tc := range tests {
		got := IsVersion(tc.input)
		if got != tc.want {
			t.Errorf("IsVersion(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestExtractAppAndVersion(t *testing.T) {
	tests := []struct {
		query   string
		wantApp string
		wantVer string
	}{
		{"curl 7.0", "curl", "7.0"},
		{"curl v 7.0", "curl", "7.0"},
		{"curl version 7.0", "curl", "7.0"},
		{"apache tomcat 9.0.50", "apache tomcat", "9.0.50"},
		{"django 4.2", "django", "4.2"},
		{"django 4.2 sql injection", "django sql injection", "4.2"},
		{"shellshock 4.3 bash", "shellshock bash", "4.3"},
		{"Krayin CRM 2.20", "Krayin CRM", "2.20"},
		{"openssh 8.5p1", "openssh", "8.5p1"},
		{"java version 17", "java", "17"},
		{"bash v 8", "bash", "8"},
		{"log4j", "log4j", ""},
		{"shellshock", "shellshock", ""},
		{"apache tomcat", "apache tomcat", ""},
		{"python3", "python3", ""},
		{"chrome v8", "chrome v8", ""},
		{"node 18", "node 18", ""},
		{"windows 2003 server", "windows 2003 server", ""},
	}

	for _, tc := range tests {
		gotApp, gotVer := ExtractAppAndVersion(tc.query)
		if gotApp != tc.wantApp || gotVer != tc.wantVer {
			t.Errorf("ExtractAppAndVersion(%q) = (%q, %q), want (%q, %q)",
				tc.query, gotApp, gotVer, tc.wantApp, tc.wantVer)
		}
	}
}

func TestVariants(t *testing.T) {
	variants := Variants("7.0")

	for _, expected := range []string{"7.0", "v7.0", "7.0.0", "v7.0.0", "7.0.x", "7.x"} {
		if !containsString(variants, expected) {
			t.Errorf("Variants(7.0) missing %q in %v", expected, variants)
		}
	}
}

func TestExactVariants(t *testing.T) {
	// Information-preserving equivalent only: zero padding is fine, dropping
	// non-zero components is not.
	exact := ExactVariants("2.4.49")
	for _, expected := range []string{"2.4.49", "v2.4.49", "2.4.49.x"} {
		if !containsString(exact, expected) {
			t.Errorf("ExactVariants(2.4.49) missing %q in %v", expected, exact)
		}
	}
	for _, bad := range []string{"2.4", "v2.4", "2.4.x", "2.x", "2"} {
		if containsString(exact, bad) {
			t.Errorf("ExactVariants(2.4.49) must not contain coarse %q in %v", bad, exact)
		}
	}

	// Zero-padding equivalents stay in the exact set.
	zeros := ExactVariants("7.0.0")
	for _, expected := range []string{"7.0.0", "7.0", "v7.0"} {
		if !containsString(zeros, expected) {
			t.Errorf("ExactVariants(7.0.0) missing %q in %v", expected, zeros)
		}
	}

	// Coarse variants do include dropped components.
	coarse := Variants("2.4.49")
	for _, expected := range []string{"2.4", "2.4.x", "2.x"} {
		if !containsString(coarse, expected) {
			t.Errorf("Variants(2.4.49) missing coarse %q in %v", expected, coarse)
		}
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"v7.0", "7.0"},
		// Leading zeros are preserved (Perl-style and CalVer versions).
		{"7.01", "7.01"},
		{"1.05", "1.05"},
		{"2024.01.05", "2024.01.05"},
		{"2.20", "2.20"},
		{"==1.2.3", "1.2.3"},
		{" 8.5p1 ", "8.5p1"},
		{"V7.0", "7.0"},
		{"<=7.0", "7.0"},
	}

	for _, tc := range tests {
		got := Normalize(tc.input)
		if got != tc.want {
			t.Errorf("Normalize(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestMatchVersionInText(t *testing.T) {
	tests := []struct {
		desc    string
		version string
		want    bool
	}{
		{"In curl 7.0, a buffer overflow occurs", "7.0", true},
		{"In curl 7.0.0, a buffer overflow occurs", "7.0", true},
		{"In curl 7.0.x, a buffer overflow occurs", "7.0", true},
		{"In curl v7.0, a buffer overflow occurs", "7.0", true},
		{"In curl (7.0), a buffer overflow occurs", "7.0", true},
		{"In curl version 7.0.", "7.0", true},
		{"curl and libcurl before 7.57.0", "7.0", false},
		{"curl and libcurl 7.27.0 through 7.35.0", "7.0", false},
		{"Crestron AM-100 firmware 2.7.0.2", "7.0", false},
		{"DTS Monitoring 3.57.0", "7.0", false},
		{"PHP 7.0.10", "7.0", false},
		{"SCO UnixWare 7.0.1", "7.0", false},
		// Negating contexts must not flag the bound itself.
		{"Affected versions before 7.0 are vulnerable", "7.0", false},
		{"Products prior to 7.0 are vulnerable", "7.0", false},
		{"Versions earlier than 7.0 are affected", "7.0", false},
		{"Fixed in 7.0.1", "7.0.1", false},
		{"curl < 7.0 is vulnerable", "7.0", false},
		{"curl <= 8.0 is vulnerable", "8.0", false},
		{"curl 7.0, and versions later than 7.1 are safe", "7.0", true},
		{"Bug exists in 7.0 and was fixed in 7.0.1", "7.0", true},
	}

	for _, tc := range tests {
		got := MatchVersionInText(tc.desc, tc.version)
		if got != tc.want {
			t.Errorf("MatchVersionInText(%q, %q) = %v, want %v", tc.desc, tc.version, got, tc.want)
		}
	}
}

func TestMatchVersionInTextAny(t *testing.T) {
	tests := []struct {
		desc    string
		version string
		want    bool
	}{
		// Coarse variants match truncations/wildcards the exact matcher rejects.
		{"an issue in v2.2.x", "2.2.0", true},
		{"apache 2.4 is affected", "2.4.49", true},
		// Still respects token boundaries.
		{"PHP 7.0.10", "7.0", false},
		{"DTS Monitoring 3.57.0", "7.0", false},
		{"curl and libcurl before 7.57.0", "7.0", false},
	}
	for _, tc := range tests {
		if got := MatchVersionInTextAny(tc.desc, tc.version); got != tc.want {
			t.Errorf("MatchVersionInTextAny(%q, %q) = %v, want %v", tc.desc, tc.version, got, tc.want)
		}
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"7.0", "7.0.0", 0},
		{"1.0", "1", 0},
		{"7.0", "7.10.7", -1},
		{"7.0", "6.5.2", 1},
		{"2.4.49", "2.4.50", -1},
		{"2.20", "2.2", 1},
		// Letter releases sort after the bare number.
		{"1.1.1k", "1.1.1l", -1},
		{"1.1.1", "1.1.1a", -1},
		{"1.0.2a", "1.0.2b", -1},
		{"8.5p1", "8.5p2", -1},
		{"8.5p1", "8.5", 1},
		// Pre-releases sort before the release.
		{"2.0.0-rc1", "2.0.0", -1},
		{"2.0.0-beta", "2.0.0-rc1", -1},
		{"2.0.0-rc2", "2.0.0-rc10", -1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q)=%d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestMatchesRange(t *testing.T) {
	if !MatchesRange("7.0", "7.0", "", "", "7.15.0") {
		t.Errorf("7.0 should match [7.0, 7.15.0)")
	}
	if !MatchesRange("7.0", "", "", "", "7.10.7") {
		t.Errorf("7.0 should match < 7.10.7")
	}
	if MatchesRange("7.0", "", "", "6.5.2", "") {
		t.Errorf("7.0 should not match <= 6.5.2")
	}
	if MatchesRange("7.0", "7.27.0", "", "7.35.0", "") {
		t.Errorf("7.0 should not match [7.27.0, 7.35.0]")
	}

	// Letter releases participate in ranges.
	if !MatchesRange("1.1.1k", "", "", "", "1.1.1l") {
		t.Errorf("1.1.1k should match < 1.1.1l")
	}
	if MatchesRange("1.1.1l", "", "", "", "1.1.1l") {
		t.Errorf("1.1.1l should not match < 1.1.1l")
	}
	if MatchesRange("8.5p2", "", "", "", "8.5p2") {
		t.Errorf("8.5p2 should not match < 8.5p2")
	}
	if !MatchesRange("8.5", "", "", "", "8.5p2") {
		t.Errorf("8.5 should match < 8.5p2")
	}
	// Pre-releases outside a release range.
	if MatchesRange("2.0.0-rc1", "2.0.0", "", "2.1.0", "") {
		t.Errorf("2.0.0-rc1 should not match [2.0.0, 2.1.0]")
	}
	if !MatchesRange("2.0.0-rc1", "", "", "2.0.0", "") {
		t.Errorf("2.0.0-rc1 should match <= 2.0.0")
	}

	// Empty version is a wildcard.
	if !MatchesRange("", "", "", "7.10.7", "") {
		t.Errorf("empty version should match anything")
	}
}

func TestCompareCPESeparators(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.0-update1559", "2.0-u1559", 0},
		{"20.0:update1559", "20.0-update1559", 0},
		{"20.0-update1559", "20.0", 1}, // update sorts after the release
		{"1.2patch3", "1.2p3", 0},
		{"7.0alpha1", "7.0a1", 0},
		{"1.0beta2", "1.0b2", 0},
		{"1.1.1k", "1.1.1", 1}, // letter release still after bare number
		{"8.5p1", "8.5", 1},
		{"2.0-rc1", "2.0", -1}, // pre-release still before release
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
