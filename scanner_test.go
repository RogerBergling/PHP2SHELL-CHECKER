package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAssessPHPVersion(t *testing.T) {
	tests := []struct {
		version string
		verdict string
		fixed   string
	}{
		{"", "php_unknown", ""},
		{"5.3.29", "safe", ""},
		{"5.4.0", "vulnerable", "Ingen officiell fix – backport krävs"},
		{"7.4.33", "vulnerable", "Ingen officiell fix – backport krävs"},
		{"8.0.30", "vulnerable", "Ingen officiell fix – backport krävs"},
		{"8.1.34", "vulnerable", "Ingen officiell fix – backport krävs"},
		{"8.1.34-1ubuntu2.14", "vulnerable", "Ingen officiell fix – backport krävs"},
		{"8.2", "vulnerable", "8.2.35"},
		{"8.2.34", "vulnerable", "8.2.35"},
		{"8.2.35", "safe", "8.2.35"},
		{"8.3.35", "vulnerable", "8.3.36"},
		{"8.3.36", "safe", "8.3.36"},
		{"8.4.26", "vulnerable", "8.4.27"},
		{"8.4.27", "safe", "8.4.27"},
		{"8.5.11", "vulnerable", "8.5.12"},
		{"8.5.12", "safe", "8.5.12"},
		{"8.5.13", "safe", "8.5.12"},
		{"8.6.0", "php_unknown", ""},
	}

	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			assessment := assessPHPVersion(test.version)
			if assessment.Verdict != test.verdict {
				t.Fatalf("assessPHPVersion(%q).Verdict = %q, want %q", test.version, assessment.Verdict, test.verdict)
			}
			if assessment.FixedIn != test.fixed {
				t.Fatalf("assessPHPVersion(%q).FixedIn = %q, want %q", test.version, assessment.FixedIn, test.fixed)
			}
		})
	}
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input    string
		want     string
		explicit bool
		wantErr  bool
	}{
		{"example.com", "https://example.com/", false, false},
		{"example.com/path?x=1#frag", "https://example.com/path?x=1", false, false},
		{"https://example.com", "https://example.com/", true, false},
		{"http://example.com:8080/a", "http://example.com:8080/a", true, false},
		{"  <https://example.com/a>  ", "https://example.com/a", true, false},
		{"ftp://example.com", "", false, true},
		{"", "", false, true},
		{"not a url", "", false, true},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, explicit, err := normalizeURL(test.input)
			if test.wantErr {
				if err == nil {
					t.Fatalf("normalizeURL(%q) unexpectedly succeeded with %q", test.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeURL(%q) error: %v", test.input, err)
			}
			if got != test.want {
				t.Fatalf("normalizeURL(%q) = %q, want %q", test.input, got, test.want)
			}
			if explicit != test.explicit {
				t.Fatalf("normalizeURL(%q) explicit = %v, want %v", test.input, explicit, test.explicit)
			}
		})
	}
}

func TestScanVulnerablePHP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.1.12")
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><body><a href="/index.php">Hem</a></body></html>`)
	}))
	defer server.Close()

	scanner := NewScanner(ScanOptions{TimeoutSeconds: 3, DeepCheck: false, FollowRedirects: true})
	result := scanner.Scan(context.Background(), server.URL)

	if result.Verdict != "vulnerable" {
		t.Fatalf("Verdict = %q, want vulnerable", result.Verdict)
	}
	if result.PHPVersion != "8.1.12" {
		t.Fatalf("PHPVersion = %q, want 8.1.12", result.PHPVersion)
	}
	if !result.PHPDetected {
		t.Fatal("PHPDetected = false, want true")
	}
	if result.StatusCode != http.StatusOK {
		t.Fatalf("StatusCode = %d, want 200", result.StatusCode)
	}
	if result.ElapsedMS < 0 {
		t.Fatalf("ElapsedMS = %d, want >= 0", result.ElapsedMS)
	}
}

func TestScanFixedPHP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("X-Powered-By", "PHP/8.4.27")
		_, _ = io.WriteString(w, "<html>ok</html>")
	}))
	defer server.Close()

	result := NewScanner(ScanOptions{TimeoutSeconds: 3, DeepCheck: false, FollowRedirects: true}).Scan(context.Background(), server.URL)
	if result.Verdict != "safe" {
		t.Fatalf("Verdict = %q, want safe", result.Verdict)
	}
	if result.FixedIn != "8.4.27" {
		t.Fatalf("FixedIn = %q, want 8.4.27", result.FixedIn)
	}
}

func TestScanPHPWithoutVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "PHPSESSID=abc123; Path=/; HttpOnly")
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><a href="/konto.php">Konto</a></html>`)
	}))
	defer server.Close()

	result := NewScanner(ScanOptions{TimeoutSeconds: 3, DeepCheck: false, FollowRedirects: true}).Scan(context.Background(), server.URL)
	if result.Verdict != "php_unknown" {
		t.Fatalf("Verdict = %q, want php_unknown", result.Verdict)
	}
	if !result.PHPDetected {
		t.Fatal("PHPDetected = false, want true")
	}
	if result.PHPVersion != "" {
		t.Fatalf("PHPVersion = %q, want empty", result.PHPVersion)
	}
}

func TestScanStaticSite(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>Statisk sida</body></html>")
	}))
	defer server.Close()

	result := NewScanner(ScanOptions{TimeoutSeconds: 3, DeepCheck: false, FollowRedirects: true}).Scan(context.Background(), server.URL)
	if result.Verdict != "not_php" {
		t.Fatalf("Verdict = %q, want not_php", result.Verdict)
	}
	if result.PHPDetected {
		t.Fatal("PHPDetected = true, want false")
	}
}

func TestScanDeepCheckFindsPHP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".php") {
			w.Header().Set("X-Powered-By", "PHP/8.2.35")
		}
		_, _ = io.WriteString(w, "<html>sida</html>")
	}))
	defer server.Close()

	result := NewScanner(ScanOptions{TimeoutSeconds: 3, DeepCheck: true, FollowRedirects: true, DelayMS: 0}).Scan(context.Background(), server.URL)
	if !result.PHPDetected {
		t.Fatal("PHPDetected = false, want true")
	}
	if result.Verdict != "safe" {
		t.Fatalf("Verdict = %q, want safe", result.Verdict)
	}
	if result.PHPVersion != "8.2.35" {
		t.Fatalf("PHPVersion = %q, want 8.2.35", result.PHPVersion)
	}
}

func TestScanDeepCheckUsesSiteSubdirectory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/index.php" {
			w.Header().Set("X-Powered-By", "PHP/8.4.27")
		}
		_, _ = io.WriteString(w, "<html>app</html>")
	}))
	defer server.Close()

	result := NewScanner(ScanOptions{TimeoutSeconds: 3, DeepCheck: true, FollowRedirects: true, DelayMS: 0}).Scan(context.Background(), server.URL+"/app/")
	if !result.PHPDetected {
		t.Fatal("PHPDetected = false, want true")
	}
	if result.PHPVersion != "8.4.27" {
		t.Fatalf("PHPVersion = %q, want 8.4.27", result.PHPVersion)
	}
}

func TestScanConnectionError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	address := server.URL
	server.Close()

	result := NewScanner(ScanOptions{TimeoutSeconds: 2, DeepCheck: false, FollowRedirects: true}).Scan(context.Background(), address)
	if result.Verdict != "error" {
		t.Fatalf("Verdict = %q, want error", result.Verdict)
	}
	if result.Error == "" {
		t.Fatal("Error is empty, want a connection error")
	}
}

func TestScanInvalidURL(t *testing.T) {
	result := NewScanner(ScanOptions{}).Scan(context.Background(), "ftp://example.com")
	if result.Verdict != "error" {
		t.Fatalf("Verdict = %q, want error", result.Verdict)
	}
}

func TestAnalyzePageBodyVersion(t *testing.T) {
	page := &pageInfo{
		headers: http.Header{"Content-Type": {"text/html"}},
		body:    []byte(`<html><body>PHP Version 8.3.36</body></html>`),
	}
	det := analyzePage(page)
	if !det.php {
		t.Fatal("php = false, want true")
	}
	if det.version != "8.3.36" {
		t.Fatalf("version = %q, want 8.3.36", det.version)
	}
}

func TestDedupeTargets(t *testing.T) {
	got := dedupeTargets([]string{
		"example.com",
		"https://example.com/",
		"https://example.com/",
		"  ",
		"https://other.example",
	})
	if len(got) != 2 {
		t.Fatalf("dedupeTargets returned %d targets, want 2: %#v", len(got), got)
	}
}

func TestIsLocalHost(t *testing.T) {
	for _, host := range []string{"127.0.0.1:8080", "localhost:1234", "[::1]:9999", "127.0.0.1", "localhost"} {
		if !isLocalHost(host) {
			t.Fatalf("isLocalHost(%q) = false, want true", host)
		}
	}
	for _, host := range []string{"example.com", "10.0.0.1:80", "localhost.evil.com"} {
		if isLocalHost(host) {
			t.Fatalf("isLocalHost(%q) = true, want false", host)
		}
	}
}
