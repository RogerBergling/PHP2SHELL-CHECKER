package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func FuzzNormalizeURL(f *testing.F) {
	for _, seed := range []string{
		"example.com",
		"https://example.com/path?x=1#frag",
		"http://127.0.0.1:8080/",
		"//example.com/",
		"example.com:8443/app",
		"ftp://example.com",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		target, _, err := normalizeURL(raw)
		if err != nil {
			return
		}
		u, err := url.Parse(target)
		if err != nil {
			t.Fatalf("normalizeURL(%q) returned unparsable target %q: %v", raw, target, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			t.Fatalf("normalizeURL(%q) returned scheme %q", raw, u.Scheme)
		}
		if u.Host == "" {
			t.Fatalf("normalizeURL(%q) returned empty host", raw)
		}
	})
}

func FuzzParsePHPVersion(f *testing.F) {
	for _, seed := range []string{
		"8.3.36",
		"8.3.36-1ubuntu2",
		"8.4",
		"5.4.0",
		"999999999999999999999.1.1",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		version, ok := parsePHPVersion(raw)
		if !ok {
			return
		}
		if version.String() == "" {
			t.Fatalf("parsePHPVersion(%q) returned an empty String()", raw)
		}
		_ = version.lessThan(version)
	})
}

func FuzzAnalyzePage(f *testing.F) {
	f.Add(`<html><body>PHP Version 8.3.36</body></html>`, "X-Powered-By", "PHP/8.3.36")
	f.Add(`<html><body>Zend Engine v4.3.14</body></html>`, "", "")
	f.Add(`<meta content="PHP 8.2.35" name="generator">`, "Server", "nginx")

	f.Fuzz(func(t *testing.T, body, headerName, headerValue string) {
		headers := http.Header{}
		if headerName != "" && headerValue != "" {
			headers.Set(headerName, headerValue)
		}
		det := analyzePage(&pageInfo{
			headers: headers,
			body:    []byte(body),
		})
		if det.version == "" {
			return
		}
		if _, ok := parsePHPVersion(det.version); !ok {
			t.Fatalf("analyzePage returned unparsable version %q for body %q", det.version, body)
		}
	})
}

func FuzzDeepBaseDir(f *testing.F) {
	for _, seed := range []string{"/", "/app", "/app/", "/app/index.php", "/v1.2/app", ""} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, urlPath string) {
		dir := deepBaseDir(urlPath)
		if !strings.HasPrefix(dir, "/") || !strings.HasSuffix(dir, "/") {
			t.Fatalf("deepBaseDir(%q) = %q, want an absolute directory with trailing slash", urlPath, dir)
		}
	})
}
