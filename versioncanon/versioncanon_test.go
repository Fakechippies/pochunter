package versioncanon

import (
	"testing"
)

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
		{"Krayin CRM 2.20", "Krayin CRM", "2.20"},
		{"openssh 8.5p1", "openssh", "8.5p1"},
		{"log4j", "log4j", ""},
		{"shellshock", "shellshock", ""},
		{"apache tomcat", "apache tomcat", ""},
		{"python3", "python3", ""},
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
	contains := func(slice []string, val string) bool {
		for _, s := range slice {
			if s == val {
				return true
			}
		}
		return false
	}

	for _, expected := range []string{"7.0", "v7.0", "7.0.0", "v7.0.0", "7.0.x", "7.x"} {
		if !contains(variants, expected) {
			t.Errorf("Variants(7.0) missing %q in %v", expected, variants)
		}
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"v7.0", "7.0"},
		{"7.01", "7.1"},
		{"2.20", "2.20"},
		{"==1.2.3", "1.2.3"},
		{" 8.5p1 ", "8.5p1"},
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
	}

	for _, tc := range tests {
		got := MatchVersionInText(tc.desc, tc.version)
		if got != tc.want {
			t.Errorf("MatchVersionInText(%q, %q) = %v, want %v", tc.desc, tc.version, got, tc.want)
		}
	}
}

func TestCompare(t *testing.T) {
	if Compare("7.0", "7.0.0") != 0 {
		t.Errorf("7.0 should equal 7.0.0")
	}
	if Compare("7.0", "7.10.7") >= 0 {
		t.Errorf("7.0 should be less than 7.10.7")
	}
	if Compare("7.0", "6.5.2") <= 0 {
		t.Errorf("7.0 should be greater than 6.5.2")
	}
	if Compare("2.4.49", "2.4.50") >= 0 {
		t.Errorf("2.4.49 should be less than 2.4.50")
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
}
