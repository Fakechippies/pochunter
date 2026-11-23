package db

import "testing"

func TestCanonicalURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"  https://github.com/o/repo  ", "https://github.com/o/repo"},
		{"http://github.com/o/repo", "https://github.com/o/repo"},
		{"https://github.com/o/repo/", "https://github.com/o/repo"},
		{"https://github.com/o/repo#readme", "https://github.com/o/repo"},
		{"https://github.com/o/repo/tree/main/", "https://github.com/o/repo/tree/main"},
		{"https://gitlab.com/x/y?utm_source=rss", "https://gitlab.com/x/y?utm_source=rss"},
		{"ftp://example.com/file", "https://ftp://example.com/file"}, // not a web URL; passes through
	}
	for _, c := range cases {
		if got := CanonicalURL(c.in); got != c.want {
			t.Errorf("CanonicalURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestExtractOwner(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"https://github.com/owner/repo", "owner"},
		{"http://github.com/owner/repo/pulls/1", "owner"},
		{"https://gitee.com/user/project", "user"},
		{"https://gitlab.com/u/p", "u"},
		{"https://bitbucket.org/u/p", "u"},
		{"https://www.exploit-db.com/exploits/50592", "www.exploit-db.com"},
		{"https://packetstormsecurity.com/files/170000/x.html", "packetstormsecurity.com"},
		{"github.com/o/r", "o"}, // scheme-less
	}
	for _, c := range cases {
		if got := ExtractOwner(c.in); got != c.want {
			t.Errorf("ExtractOwner(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeDate(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"   ", ""},
		{"not a date", ""},
		{"2021-12-10T09:51:31Z", "2021-12-10T09:51:31Z"},
		{"2021-12-10T09:51:31+02:00", "2021-12-10T07:51:31Z"},
		{"2021-12-10", "2021-12-10T00:00:00Z"},
		{"2021/12/10", "2021-12-10T00:00:00Z"},
		{"2021-12-10 15:04:05", "2021-12-10T15:04:05Z"},
		{"Fri, 10 Dec 2021 15:04:05 +0000", "2021-12-10T15:04:05Z"},
	}
	for _, c := range cases {
		if got := NormalizeDate(c.in); got != c.want {
			t.Errorf("NormalizeDate(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCleanDetail(t *testing.T) {
	if got := CleanDetail("  a\n\nb\t c  "); got != "a b c" {
		t.Errorf("CleanDetail = %q, want %q", got, "a b c")
	}
	if got := CleanDetail(""); got != "" {
		t.Errorf("CleanDetail(\"\") = %q", got)
	}
}
