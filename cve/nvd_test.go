package cve

import (
	"testing"
)

func TestIsProductMatch(t *testing.T) {
	tests := []struct {
		cpeProd  string
		userProd string
		want     bool
	}{
		{"curl", "curl", true},
		{"libcurl", "curl", true},
		{"curl", "libcurl", true},
		{"tomcat", "apache tomcat", true},
		{"apache_tomcat", "apache tomcat", true},
		{"php", "curl", false},
		{"dts_monitoring", "curl", false},
		{"am-100", "curl", false},
		{"sql_server", "curl", false},
		{"unixware", "curl", false},
	}

	for _, tc := range tests {
		got := isProductMatch(tc.cpeProd, tc.userProd)
		if got != tc.want {
			t.Errorf("isProductMatch(%q, %q) = %v, want %v", tc.cpeProd, tc.userProd, got, tc.want)
		}
	}
}

func TestMatchesProductAndVersion(t *testing.T) {
	// A curl CVE affecting curl before 7.50.0
	curlCVE := nvdItem{
		id:     "CVE-2016-5419",
		detail: "curl and libcurl before 7.50.1 do not prevent TLS session resumption",
		score:  7.5,
		cpes: []nvdCPE{
			{
				criteria: "cpe:2.3:a:haxx:libcurl:*:*:*:*:*:*:*:*",
				endInc:   "7.50.0",
			},
		},
	}

	// Should match curl 7.0
	if matchNVDItemReason(curlCVE, "curl", "7.0") == "" {
		t.Errorf("curlCVE should match curl 7.0")
	}

	// Should not match curl 8.0
	if matchNVDItemReason(curlCVE, "curl", "8.0") != "" {
		t.Errorf("curlCVE should not match curl 8.0")
	}

	// A non-curl CVE (SQL Server 7.0)
	sqlServerCVE := nvdItem{
		id:     "CVE-2000-1209",
		detail: "The sa account is installed with a default null password on Microsoft SQL Server 7.0",
		score:  10.0,
		cpes: []nvdCPE{
			{
				criteria: "cpe:2.3:a:microsoft:sql_server:7.0:*:*:*:*:*:*:*",
			},
		},
	}

	// Should NOT match curl 7.0
	if matchNVDItemReason(sqlServerCVE, "curl", "7.0") != "" {
		t.Errorf("sqlServerCVE should not match curl 7.0")
	}

	// A non-curl CVE with curl mentioned in description (e.g. PHP ext/curl or Crestron)
	crestronCVE := nvdItem{
		id:     "CVE-2019-3931",
		detail: "Crestron AM-100 with firmware 1.6.0.2 and AM-101 with firmware 2.7.0.2 are vulnerable via curl",
		score:  8.8,
		cpes: []nvdCPE{
			{
				criteria: "cpe:2.3:h:crestron:am-100:1.6.0.2:*:*:*:*:*:*:*",
			},
		},
	}

	// Should NOT match curl 7.0
	if matchNVDItemReason(crestronCVE, "curl", "7.0") != "" {
		t.Errorf("crestronCVE should not match curl 7.0")
	}
}

func TestIsPureNumber(t *testing.T) {
	if !isPureNumber("7.0") {
		t.Errorf("7.0 should be pure number")
	}
	if !isPureNumber("2000") {
		t.Errorf("2000 should be pure number")
	}
	if isPureNumber("curl") {
		t.Errorf("curl should not be pure number")
	}
	if isPureNumber("8.5p1") {
		t.Errorf("8.5p1 should not be pure number")
	}
}
