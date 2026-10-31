package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func intPtr(value int) *int {
	return &value
}

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
		{"8.4.27-1", "safe", "8.4.27"},
		{"8.4.27-1ubuntu2.14", "safe", "8.4.27"},
		{"8.4.27RC1", "php_unknown", ""},
		{"8.4.27-dev", "php_unknown", ""},
		{"8.4.27-beta1", "php_unknown", ""},
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

func TestParsePHPVersionRejectsInvalidNumbers(t *testing.T) {
	for _, raw := range []string{"", "PHP 8.4", "999999999999999999999999.1.1", "8.4.27RC1", "8.4.27-dev", "8.4.27-beta1"} {
		if _, ok := parsePHPVersion(raw); ok {
			t.Fatalf("parsePHPVersion(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestCleanVersionPreservesPreReleaseSuffix(t *testing.T) {
	if got := cleanVersion("8.4.27RC1"); got != "8.4.27RC1" {
		t.Fatalf("cleanVersion(8.4.27RC1) = %q, want the pre-release marker preserved", got)
	}
	if got := cleanVersion("8.4.27-1ubuntu2.14"); got != "8.4.27" {
		t.Fatalf("cleanVersion(8.4.27-1ubuntu2.14) = %q, want 8.4.27", got)
	}
}

func TestDefaultUserAgentUsesAppVersion(t *testing.T) {
	opts := ScanOptions{}
	opts.applyDefaults()
	if !strings.Contains(opts.UserAgent, appVersion) {
		t.Fatalf("UserAgent = %q, want it to contain app version %q", opts.UserAgent, appVersion)
	}
}

func TestApplyDefaultsSanitizesUserAgent(t *testing.T) {
	opts := ScanOptions{UserAgent: "skanner\r\nX-Injected: true"}
	opts.applyDefaults()
	if strings.ContainsAny(opts.UserAgent, "\r\n") {
		t.Fatalf("UserAgent = %q, want CR/LF removed", opts.UserAgent)
	}

	long := ScanOptions{UserAgent: strings.Repeat("a", 600)}
	long.applyDefaults()
	if len(long.UserAgent) != 512 {
		t.Fatalf("len(UserAgent) = %d, want 512", len(long.UserAgent))
	}
}

func TestApplyDefaultsRetriesAndProxy(t *testing.T) {
	opts := ScanOptions{}
	opts.applyDefaults()
	if opts.MaxRetries == nil || *opts.MaxRetries != 2 {
		t.Fatalf("MaxRetries = %v, want default 2", opts.MaxRetries)
	}

	zero := 0
	opts = ScanOptions{MaxRetries: &zero}
	opts.applyDefaults()
	if *opts.MaxRetries != 0 {
		t.Fatalf("MaxRetries = %d, want 0", *opts.MaxRetries)
	}

	negative := -1
	opts = ScanOptions{MaxRetries: &negative}
	opts.applyDefaults()
	if *opts.MaxRetries != 0 {
		t.Fatalf("MaxRetries = %d, want clamped 0", *opts.MaxRetries)
	}

	high := 99
	opts = ScanOptions{MaxRetries: &high}
	opts.applyDefaults()
	if *opts.MaxRetries != 5 {
		t.Fatalf("MaxRetries = %d, want clamped 5", *opts.MaxRetries)
	}
}

func TestSanitizeRequestHeaders(t *testing.T) {
	opts := ScanOptions{
		Headers: map[string]string{
			"Host":           "evil.example",
			"Content-Length": "999",
			"X-Test":         " value ",
			"Bad\nName":      "value",
			"Empty":          "",
			"User-Agent":     "Custom/1.0",
		},
	}
	opts.applyDefaults()

	if _, ok := opts.Headers["Host"]; ok {
		t.Fatal("Host header was not filtered out")
	}
	if _, ok := opts.Headers["Content-Length"]; ok {
		t.Fatal("Content-Length header was not filtered out")
	}
	if got := opts.Headers["X-Test"]; got != "value" {
		t.Fatalf("X-Test = %q, want value", got)
	}
	if got := opts.Headers["User-Agent"]; got != "Custom/1.0" {
		t.Fatalf("User-Agent = %q, want Custom/1.0", got)
	}
}

func TestSanitizeRequestCookies(t *testing.T) {
	opts := ScanOptions{
		Cookies: map[string]string{
			"session":  "abc123",
			"bad;name": "value",
			"broken":   "line\nbreak",
		},
	}
	opts.applyDefaults()

	if got := opts.Cookies["session"]; got != "abc123" {
		t.Fatalf("session cookie = %q, want abc123", got)
	}
	if _, ok := opts.Cookies["bad;name"]; ok {
		t.Fatal("invalid cookie name was not filtered out")
	}
	if _, ok := opts.Cookies["broken"]; ok {
		t.Fatal("cookie with CR/LF was not filtered out")
	}
}

func TestValidateProxyURL(t *testing.T) {
	valid := []string{"", "env", "direct", "none", "http://proxy.example:8080", "https://proxy.example:8443"}
	for _, value := range valid {
		opts := ScanOptions{ProxyURL: value}
		opts.applyDefaults()
		if err := opts.validate(); err != nil {
			t.Fatalf("validate(%q) = %v, want nil", value, err)
		}
	}
	for _, value := range []string{"ftp://proxy.example", "http://", "not a url"} {
		opts := ScanOptions{ProxyURL: value}
		opts.applyDefaults()
		if err := opts.validate(); err == nil {
			t.Fatalf("validate(%q) succeeded, want an error", value)
		}
	}
}

func TestConfiguredProxy(t *testing.T) {
	scanner := NewScanner(ScanOptions{ProxyURL: "http://proxy.example:8080", MaxRetries: intPtr(0)})
	transport, ok := scanner.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("scanner transport is not *http.Transport")
	}
	request, err := http.NewRequest(http.MethodGet, "http://target.example/", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	proxy, err := transport.Proxy(request)
	if err != nil || proxy == nil || proxy.String() != "http://proxy.example:8080" {
		t.Fatalf("proxy = %v, err = %v; want http://proxy.example:8080", proxy, err)
	}

	direct := NewScanner(ScanOptions{ProxyURL: "direct", MaxRetries: intPtr(0)})
	directTransport := direct.client.Transport.(*http.Transport)
	if directTransport.Proxy != nil {
		t.Fatal("direct proxy function is set, want nil")
	}
}

func TestRetryDelay(t *testing.T) {
	if got := retryDelay("0", 0); got != 0 {
		t.Fatalf("retryDelay(0) = %v, want 0", got)
	}
	if got := retryDelay("2", 0); got != 2*time.Second {
		t.Fatalf("retryDelay(2) = %v, want 2s", got)
	}
	if got := retryDelay("999", 0); got != retryAfterMax {
		t.Fatalf("retryDelay(999) = %v, want cap %v", got, retryAfterMax)
	}
	if got := retryDelay("invalid", 1); got != time.Second {
		t.Fatalf("retryDelay(invalid, 1) = %v, want 1s", got)
	}
	future := time.Now().Add(2 * time.Second).UTC().Format(http.TimeFormat)
	if got := retryDelay(future, 0); got <= 0 || got > 3*time.Second {
		t.Fatalf("retryDelay(HTTP date) = %v, want a short positive delay", got)
	}
}

func TestScanSendsCustomHeadersAndCookies(t *testing.T) {
	headersCh := make(chan http.Header, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headersCh <- r.Header.Clone()
		w.Header().Set("X-Powered-By", "PHP/8.4.27")
		_, _ = io.WriteString(w, "<html>ok</html>")
	}))
	defer server.Close()

	scanner := NewScanner(ScanOptions{
		TimeoutSeconds:  3,
		DeepCheck:       false,
		FollowRedirects: true,
		DelayMS:         0,
		MaxRetries:      intPtr(0),
		Headers: map[string]string{
			"X-Custom-Header": "custom-value",
			"User-Agent":      "CustomScanner/1.0",
			"Host":            "ignored.example",
		},
		Cookies: map[string]string{"session": "abc123"},
	})
	result := scanner.Scan(context.Background(), server.URL)
	if result.Verdict != "safe" {
		t.Fatalf("Verdict = %q, want safe", result.Verdict)
	}

	headers := <-headersCh
	if got := headers.Get("X-Custom-Header"); got != "custom-value" {
		t.Fatalf("X-Custom-Header = %q, want custom-value", got)
	}
	if got := headers.Get("User-Agent"); got != "CustomScanner/1.0" {
		t.Fatalf("User-Agent = %q, want CustomScanner/1.0", got)
	}
	if got := headers.Get("Host"); got != "" {
		t.Fatalf("Host header = %q, want it filtered out", got)
	}
	if got := headers.Get("Cookie"); !strings.Contains(got, "session=abc123") {
		t.Fatalf("Cookie = %q, want session=abc123", got)
	}
}

func TestScanRetries429And503(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var attempts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if attempts.Add(1) == 1 {
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(status)
					return
				}
				w.Header().Set("X-Powered-By", "PHP/8.4.27")
				_, _ = io.WriteString(w, "<html>ok</html>")
			}))
			defer server.Close()

			result := NewScanner(ScanOptions{
				TimeoutSeconds:  3,
				DeepCheck:       false,
				FollowRedirects: true,
				DelayMS:         0,
				MaxRetries:      intPtr(2),
			}).Scan(context.Background(), server.URL)

			if result.StatusCode != http.StatusOK {
				t.Fatalf("StatusCode = %d, want 200", result.StatusCode)
			}
			if result.Verdict != "safe" {
				t.Fatalf("Verdict = %q, want safe", result.Verdict)
			}
			if got := attempts.Load(); got != 2 {
				t.Fatalf("attempts = %d, want 2", got)
			}
		})
	}
}

func TestScanRetryLimit(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	result := NewScanner(ScanOptions{
		TimeoutSeconds:  3,
		DeepCheck:       false,
		FollowRedirects: true,
		DelayMS:         0,
		MaxRetries:      intPtr(1),
	}).Scan(context.Background(), server.URL)

	if result.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("StatusCode = %d, want 429", result.StatusCode)
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
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

	result := NewScanner(ScanOptions{TimeoutSeconds: 3, DeepCheck: true, FollowRedirects: true}).Scan(context.Background(), server.URL)
	if result.Verdict != "safe" {
		t.Fatalf("Verdict = %q, want safe", result.Verdict)
	}
	if result.FixedIn != "8.4.27" {
		t.Fatalf("FixedIn = %q, want 8.4.27", result.FixedIn)
	}
	if len(result.DeepChecks) != 0 {
		t.Fatalf("DeepChecks = %d, want 0 when a complete version is already known", len(result.DeepChecks))
	}
}

func TestScanCapturesEvidenceWithoutCookieValues(t *testing.T) {
	body := `<html><body><a href="/index.php">Hem</a></body></html>`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.27.3")
		w.Header().Set("X-Powered-By", "PHP/8.4.27")
		w.Header().Set("Set-Cookie", "PHPSESSID=hemlig; Path=/; HttpOnly")
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()

	result := NewScanner(ScanOptions{TimeoutSeconds: 3, DeepCheck: false, FollowRedirects: true}).Scan(context.Background(), server.URL)
	if result.RemoteIP == "" {
		t.Fatal("RemoteIP is empty, want the address that answered")
	}
	sum := sha256.Sum256([]byte(body))
	if result.BodySHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("BodySHA256 = %q, want hash of the response body", result.BodySHA256)
	}
	if result.Server != "nginx/1.27.3" {
		t.Fatalf("Server = %q, want nginx/1.27.3", result.Server)
	}
	if result.ResponseHeaders["Server"] != "nginx/1.27.3" {
		t.Fatalf("ResponseHeaders[Server] = %q, want nginx/1.27.3", result.ResponseHeaders["Server"])
	}
	if _, ok := result.ResponseHeaders["Set-Cookie"]; ok {
		t.Fatal("ResponseHeaders contains Set-Cookie, want cookie values omitted from evidence")
	}
	if len(result.VersionCandidates) == 0 {
		t.Fatal("VersionCandidates is empty, want the X-Powered-By observation")
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
	if len(result.DeepChecks) == 0 {
		t.Fatal("DeepChecks is empty, want the probe that found the version")
	}
	if result.DeepChecks[0].URL != server.URL+"/index.php" {
		t.Fatalf("first DeepCheck URL = %q, want %q", result.DeepChecks[0].URL, server.URL+"/index.php")
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

func TestScanDeepCheckCompletesIncompleteVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/phpinfo.php" {
			w.Header().Set("X-Powered-By", "PHP/8.4.27")
		} else {
			w.Header().Set("X-Powered-By", "PHP/8.4")
		}
		_, _ = io.WriteString(w, "<html>sida</html>")
	}))
	defer server.Close()

	result := NewScanner(ScanOptions{TimeoutSeconds: 3, DeepCheck: true, FollowRedirects: true, DelayMS: 0}).Scan(context.Background(), server.URL)
	if result.PHPVersion != "8.4.27" {
		t.Fatalf("PHPVersion = %q, want 8.4.27 from the phpinfo probe", result.PHPVersion)
	}
	if len(result.DeepChecks) < 2 {
		t.Fatalf("DeepChecks = %d, want at least 2 probes before the full version was found", len(result.DeepChecks))
	}
}

func TestScanDeepCheckTreatsExtensionlessPathAsDirectory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/phpinfo.php" {
			w.Header().Set("X-Powered-By", "PHP/8.3.36")
		}
		_, _ = io.WriteString(w, "<html>app</html>")
	}))
	defer server.Close()

	result := NewScanner(ScanOptions{TimeoutSeconds: 3, DeepCheck: true, FollowRedirects: true, DelayMS: 0}).Scan(context.Background(), server.URL+"/app")
	if result.PHPVersion != "8.3.36" {
		t.Fatalf("PHPVersion = %q, want 8.3.36 from /app/phpinfo.php", result.PHPVersion)
	}
}

func TestScanDeepCheckFallsBackToDocumentRoot(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/phpinfo.php" {
			w.Header().Set("Server", "deep-nginx")
			w.Header().Set("X-Powered-By", "PHP/8.2.35")
		}
		_, _ = io.WriteString(w, "<html>sida</html>")
	}))
	defer server.Close()

	result := NewScanner(ScanOptions{TimeoutSeconds: 3, DeepCheck: true, FollowRedirects: true, DelayMS: 0}).Scan(context.Background(), server.URL+"/app/")
	if result.PHPVersion != "8.2.35" {
		t.Fatalf("PHPVersion = %q, want 8.2.35 from the document root", result.PHPVersion)
	}
	if result.Server != "deep-nginx" {
		t.Fatalf("Server = %q, want the header from the deep phpinfo response", result.Server)
	}

	foundRootProbe := false
	for _, check := range result.DeepChecks {
		if check.URL == server.URL+"/phpinfo.php" && check.StatusCode == http.StatusOK {
			foundRootProbe = true
			break
		}
	}
	if !foundRootProbe {
		t.Fatalf("DeepChecks = %#v, want the document-root phpinfo.php probe", result.DeepChecks)
	}
}

func TestDeepCheckWorstCaseProbeCount(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html>static</html>")
	}))
	defer server.Close()

	result := NewScanner(ScanOptions{TimeoutSeconds: 3, DeepCheck: true, FollowRedirects: true, DelayMS: 0, MaxRetries: intPtr(0)}).Scan(context.Background(), server.URL+"/app/")
	if result.PHPVersion != "" {
		t.Fatalf("PHPVersion = %q, want empty", result.PHPVersion)
	}
	if len(result.DeepChecks) != 14 {
		t.Fatalf("DeepChecks = %d, want 14 probes (7 directory + 7 document root)", len(result.DeepChecks))
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

func TestAnalyzePagePreservesPreReleaseVersion(t *testing.T) {
	page := &pageInfo{
		headers: http.Header{"X-Powered-By": {"PHP/8.4.27RC1"}},
		body:    []byte(`<html><body>ok</body></html>`),
	}
	det := analyzePage(page)
	if det.version != "8.4.27RC1" {
		t.Fatalf("version = %q, want 8.4.27RC1", det.version)
	}
	if assessment := assessPHPVersion(det.version); assessment.Verdict != "php_unknown" {
		t.Fatalf("verdict = %q, want php_unknown for a release candidate", assessment.Verdict)
	}
}

func TestAnalyzePHPInfoHTMLStripsMarkup(t *testing.T) {
	page := &pageInfo{
		headers: http.Header{"Content-Type": {"text/html"}},
		body: []byte(`<html><body><table>
			<tr><td class="e">PHP Version </td><td class="v">8.3.36</td></tr>
			<tr><td class="e">Zend Engine </td><td class="v">v4.3.36</td></tr>
		</table></body></html>`),
	}
	det := analyzePage(page)
	if det.version != "8.3.36" {
		t.Fatalf("version = %q, want 8.3.36", det.version)
	}

	foundZend := false
	for _, candidate := range det.candidates {
		if candidate.Version == "8.3.36" && candidate.Source == "HTML: Zend Engine (omräknad)" {
			foundZend = true
		}
	}
	if !foundZend {
		t.Fatalf("candidates = %#v, want a converted Zend Engine candidate", det.candidates)
	}
}

func TestZendEngineVersionIsConvertedToPHPVersion(t *testing.T) {
	page := &pageInfo{
		headers: http.Header{"Content-Type": {"text/html"}},
		body:    []byte(`<html><body>Zend Engine v4.3.14</body></html>`),
	}
	det := analyzePage(page)
	if det.version != "8.3.14" {
		t.Fatalf("version = %q, want 8.3.14 (Zend 4.3.14 must not be treated as PHP 4.3.14)", det.version)
	}
	if assessment := assessPHPVersion(det.version); assessment.Verdict != "vulnerable" {
		t.Fatalf("verdict = %q, want vulnerable because 8.3.14 predates 8.3.36", assessment.Verdict)
	}
}

func TestPHPVersionFromZend(t *testing.T) {
	tests := map[string]string{
		"4.3.14": "8.3.14",
		"3.4.33": "7.4.33",
		"2.6.40": "5.6.40",
	}
	for zend, want := range tests {
		got, ok := phpVersionFromZend(zend)
		if !ok || got != want {
			t.Fatalf("phpVersionFromZend(%q) = %q, %v; want %q, true", zend, got, ok, want)
		}
	}
	if _, ok := phpVersionFromZend("5.0.0"); ok {
		t.Fatal("phpVersionFromZend(5.0.0) unexpectedly succeeded")
	}
}

func TestAnalyzePageGeneratorAttributeOrder(t *testing.T) {
	page := &pageInfo{
		headers: http.Header{"Content-Type": {"text/html"}},
		body:    []byte(`<html><head><meta content="PHP 8.2.35" name="generator"></head></html>`),
	}
	det := analyzePage(page)
	if det.version != "8.2.35" {
		t.Fatalf("version = %q, want 8.2.35", det.version)
	}
}

func TestVersionCandidatesPreferExplicitHeader(t *testing.T) {
	page := &pageInfo{
		headers: http.Header{"X-Powered-By": {"PHP/8.4.27"}},
		body:    []byte(`<html><body>PHP Version 8.3.36</body></html>`),
	}
	det := analyzePage(page)
	if det.version != "8.4.27" {
		t.Fatalf("version = %q, want 8.4.27", det.version)
	}
	if len(det.candidates) < 2 {
		t.Fatalf("candidates = %#v, want both header and HTML observations", det.candidates)
	}
}

func TestVersionCandidatesCompleteIncompleteHeader(t *testing.T) {
	page := &pageInfo{
		headers: http.Header{"X-Powered-By": {"PHP/8.4"}},
		body:    []byte(`<html><body>PHP Version 8.4.27</body></html>`),
	}
	det := analyzePage(page)
	if det.version != "8.4.27" {
		t.Fatalf("version = %q, want 8.4.27 from the more precise HTML observation", det.version)
	}
}

func TestXPHPVersionHeaderWithoutPrefix(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-PHP-Version", "8.3.36")
	page := &pageInfo{
		headers: headers,
		body:    []byte(`<html><body>ok</body></html>`),
	}
	det := analyzePage(page)
	if det.version != "8.3.36" {
		t.Fatalf("version = %q, want 8.3.36", det.version)
	}
	if det.versionSrc != "X-PHP-Version" {
		t.Fatalf("versionSource = %q, want X-PHP-Version", det.versionSrc)
	}
}

func TestXPHPVersionHeaderPreRelease(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-PHP-Version", "8.4.27RC1")
	page := &pageInfo{
		headers: headers,
		body:    []byte(`<html><body>ok</body></html>`),
	}
	det := analyzePage(page)
	if det.version != "8.4.27RC1" {
		t.Fatalf("version = %q, want 8.4.27RC1", det.version)
	}
	if assessment := assessPHPVersion(det.version); assessment.Verdict != "php_unknown" {
		t.Fatalf("verdict = %q, want php_unknown", assessment.Verdict)
	}
}

func TestVersionNeedsConfirmation(t *testing.T) {
	tests := map[string]bool{
		"":        true,
		"8.4":     true,
		"8.4.27":  false,
		"invalid": true,
	}
	for version, want := range tests {
		if got := versionNeedsConfirmation(version); got != want {
			t.Fatalf("versionNeedsConfirmation(%q) = %v, want %v", version, got, want)
		}
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
