package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	maxBodyBytes = 2 << 20 // 2 MiB per response is enough for fingerprinting.
	maxRedirects = 6
)

type ScanOptions struct {
	TimeoutSeconds  int    `json:"timeoutSeconds"`
	Concurrency     int    `json:"concurrency"`
	DelayMS         int    `json:"delayMs"`
	FollowRedirects bool   `json:"followRedirects"`
	InsecureTLS     bool   `json:"insecureTls"`
	DeepCheck       bool   `json:"deepCheck"`
	UserAgent       string `json:"userAgent"`
}

func (o *ScanOptions) applyDefaults() {
	if o.TimeoutSeconds <= 0 {
		o.TimeoutSeconds = 10
	}
	if o.TimeoutSeconds < 2 {
		o.TimeoutSeconds = 2
	}
	if o.TimeoutSeconds > 120 {
		o.TimeoutSeconds = 120
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 5
	}
	if o.Concurrency > 32 {
		o.Concurrency = 32
	}
	if o.DelayMS < 0 {
		o.DelayMS = 0
	}
	if o.DelayMS > 10000 {
		o.DelayMS = 10000
	}
	o.UserAgent = strings.TrimSpace(o.UserAgent)
	if o.UserAgent == "" {
		o.UserAgent = defaultUserAgent
	}
	if len(o.UserAgent) > 512 {
		o.UserAgent = o.UserAgent[:512]
	}
	if strings.ContainsAny(o.UserAgent, "\r\n") {
		o.UserAgent = defaultUserAgent
	}
}

// VersionCandidate documents one independent observation of a PHP version.
// Candidates are ranked by confidence and precision before a verdict is made.
type VersionCandidate struct {
	Version    string `json:"version"`
	Source     string `json:"source"`
	Confidence int    `json:"confidence"`
}

// DeepCheck records one of the extra probes made during a deep version
// analysis. It is evidence of what was checked, including negative results.
type DeepCheck struct {
	URL           string `json:"url"`
	StatusCode    int    `json:"statusCode,omitempty"`
	PHPDetected   bool   `json:"phpDetected,omitempty"`
	PHPVersion    string `json:"phpVersion,omitempty"`
	VersionSource string `json:"versionSource,omitempty"`
	Error         string `json:"error,omitempty"`
}

type Result struct {
	Input         string     `json:"input"`
	FinalURL      string     `json:"finalUrl,omitempty"`
	StatusCode    int        `json:"statusCode,omitempty"`
	ElapsedMS     int64      `json:"elapsedMs"`
	PHPDetected   bool       `json:"phpDetected"`
	PHPVersion    string     `json:"phpVersion,omitempty"`
	VersionSource string     `json:"versionSource,omitempty"`
	Verdict       string     `json:"verdict"`
	VerdictLabel  string     `json:"verdictLabel"`
	FixedIn       string     `json:"fixedIn,omitempty"`
	Detail        string     `json:"detail,omitempty"`
	Server        string     `json:"server,omitempty"`
	PoweredBy     string     `json:"poweredBy,omitempty"`
	App           string     `json:"app,omitempty"`
	PHPLinks      int        `json:"phpLinks,omitempty"`
	Evidence      []string   `json:"evidence,omitempty"`
	Advisories    []Advisory `json:"advisories,omitempty"`
	Error         string     `json:"error,omitempty"`
	CheckedAt     string     `json:"checkedAt"`
	// The fields below are optional evidence details. They are additive so
	// older exports and the CSV/JSON consumers keep working unchanged.
	RemoteIP          string             `json:"remoteIp,omitempty"`
	BodySHA256        string             `json:"bodySha256,omitempty"`
	ResponseHeaders   map[string]string  `json:"responseHeaders,omitempty"`
	VersionCandidates []VersionCandidate `json:"versionCandidates,omitempty"`
	DeepChecks        []DeepCheck        `json:"deepChecks,omitempty"`
}

type pageInfo struct {
	url     string
	status  int
	headers http.Header
	body    []byte
	remote  string
	sha256  string
}

type detection struct {
	php           bool
	version       string
	versionSrc    string
	candidates    []VersionCandidate
	evidence      []string
	app           string
	phpLinks      int
	server        string
	poweredBy     string
	sessionCookie bool
	uploadForm    bool
}

type hostLimiter struct {
	mu    sync.Mutex
	last  map[string]time.Time
	delay time.Duration
}

func (l *hostLimiter) wait(ctx context.Context, host string) error {
	if l.delay <= 0 {
		return nil
	}
	l.mu.Lock()
	now := time.Now()
	next := l.last[host].Add(l.delay)
	if next.Before(now) {
		next = now
	}
	l.last[host] = next
	l.mu.Unlock()

	d := time.Until(next)
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type Scanner struct {
	opts    ScanOptions
	client  *http.Client
	limiter *hostLimiter
}

func NewScanner(opts ScanOptions) *Scanner {
	opts.applyDefaults()
	timeout := time.Duration(opts.TimeoutSeconds) * time.Second

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       90 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: opts.InsecureTLS}, //nolint:gosec // Opt-in for sites with broken certificates.
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !opts.FollowRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) >= maxRedirects {
			return errors.New("för många omdirigeringar")
		}
		return nil
	}

	return &Scanner{
		opts:    opts,
		client:  client,
		limiter: &hostLimiter{last: make(map[string]time.Time), delay: time.Duration(opts.DelayMS) * time.Millisecond},
	}
}

func (s *Scanner) Scan(ctx context.Context, raw string) (res Result) {
	start := time.Now()
	res = Result{
		Input:     strings.TrimSpace(raw),
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	}
	defer func() { res.ElapsedMS = time.Since(start).Milliseconds() }()

	target, explicitScheme, err := normalizeURL(raw)
	if err != nil {
		res.Verdict = "error"
		res.VerdictLabel = "Ogiltig URL"
		res.Error = err.Error()
		res.Detail = "Webbplatsen kunde inte tolkas som en HTTP- eller HTTPS-adress."
		return res
	}
	res.FinalURL = target

	var notes []string
	page, err := s.fetch(ctx, target)
	if err != nil && !explicitScheme && strings.HasPrefix(target, "https://") {
		httpTarget := "http://" + strings.TrimPrefix(target, "https://")
		if fallback, fallbackErr := s.fetch(ctx, httpTarget); fallbackErr == nil {
			page = fallback
			err = nil
			notes = append(notes, "HTTPS misslyckades – HTTP användes i stället")
		}
	}
	if err != nil {
		res.Verdict = "error"
		res.VerdictLabel = "Anslutningsfel"
		res.Error = friendlyError(err)
		res.Detail = "Ingen kontroll kunde göras. Kontrollera adressen, nätverket eller eventuell brandvägg."
		return res
	}

	res.FinalURL = page.url
	res.StatusCode = page.status
	res.RemoteIP = page.remote
	res.BodySHA256 = page.sha256
	res.ResponseHeaders = evidenceHeaders(page.headers)

	det := analyzePage(page)
	var deepChecks []DeepCheck
	if s.opts.DeepCheck && versionNeedsConfirmation(det.version) {
		deepDetection, checks := s.deepCheck(ctx, page.url)
		mergeDetection(&det, deepDetection)
		deepChecks = checks
	}

	res.PHPDetected = det.php
	res.PHPVersion = det.version
	res.VersionSource = det.versionSrc
	res.VersionCandidates = det.candidates
	res.DeepChecks = deepChecks
	res.Server = det.server
	res.PoweredBy = det.poweredBy
	res.App = det.app
	res.PHPLinks = det.phpLinks
	res.Evidence = appendUnique(det.evidence, notes...)

	assessment := phpAssessment{}
	if det.php {
		assessment = assessPHPVersion(det.version)
		if det.version == "" {
			assessment = phpAssessment{
				Verdict: "php_unknown",
				Label:   "PHP – okänd version",
				Detail:  "PHP-indikatorer hittades, men versionen kunde inte fastställas. Kontrollera serverns PHP-version manuellt – sårbarheten kan inte uteslutas.",
			}
		}
	} else {
		assessment = phpAssessment{
			Verdict: "not_php",
			Label:   "Inga PHP-indikatorer",
			Detail:  "Inga tydliga PHP-indikatorer hittades. Det utesluter inte PHP bakom en CDN-tjänst, WAF eller ett väl dolt gränssnitt.",
		}
	}

	res.Verdict = assessment.Verdict
	res.VerdictLabel = assessment.Label
	res.FixedIn = assessment.FixedIn
	res.Detail = assessment.Detail
	if det.php {
		res.Advisories = append(res.Advisories, assessUploadProgress(det))
	}
	if res.Verdict == "vulnerable" {
		res.Evidence = append(res.Evidence, "PHP2Shell: CVE-2026-109618 och CVE-2026-109619")
	}
	return res
}

func (s *Scanner) fetch(ctx context.Context, target string) (*pageInfo, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if err := s.limiter.wait(ctx, strings.ToLower(u.Host)); err != nil {
		return nil, err
	}

	reqCtx, cancel := context.WithTimeout(ctx, time.Duration(s.opts.TimeoutSeconds)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.opts.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "sv-SE,sv;q=0.9,en;q=0.7")

	// Record the address that actually answered. Behind a CDN or load
	// balancer this documents which endpoint the scanner talked to.
	var remote string
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				remote = info.Conn.RemoteAddr().String()
			}
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)

	finalURL := target
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	return &pageInfo{
		url:     finalURL,
		status:  resp.StatusCode,
		headers: resp.Header,
		body:    body,
		remote:  remote,
		sha256:  hex.EncodeToString(sum[:]),
	}, nil
}

// evidenceHeaders keeps a small, documented set of response headers for the
// evidence report. It deliberately avoids cookies and other secrets.
func evidenceHeaders(h http.Header) map[string]string {
	names := []string{
		"Server",
		"X-Powered-By",
		"X-PHP-Version",
		"X-PHP-Engine",
		"X-Server-Powered-By",
		"X-Backend-Server",
		"Content-Type",
		"Via",
		"CF-Ray",
		"X-Sucuri-ID",
		"X-Akamai-Transformed",
		"X-Fastly-Request-ID",
	}
	out := make(map[string]string, len(names))
	for _, name := range names {
		if value := h.Get(name); value != "" {
			out[name] = truncate(value, 240)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func deepBaseDir(urlPath string) string {
	if urlPath == "" || urlPath == "/" {
		return "/"
	}
	if strings.HasSuffix(urlPath, "/") {
		return urlPath
	}
	// A path with a file extension is treated as a file; an extensionless
	// path is commonly an application mounted at /app and is probed as /app/.
	if path.Ext(urlPath) != "" {
		dir := path.Dir(urlPath)
		if dir == "." || dir == "" {
			return "/"
		}
		return dir + "/"
	}
	return urlPath + "/"
}

func (s *Scanner) deepCheck(ctx context.Context, base string) (detection, []DeepCheck) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return detection{}, nil
	}
	origin := u.Scheme + "://" + u.Host
	dir := deepBaseDir(u.Path)
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		random = []byte("a1b2c3")
	}
	canary := "php2shell-check-" + hex.EncodeToString(random) + ".php"

	// First look in the same directory as the scanned URL. Common
	// diagnostics are ordered from most to least likely to expose a version.
	paths := []string{
		dir + "index.php",
		dir + "phpinfo.php",
		dir + "info.php",
		dir + "php-info.php",
		dir + "phpversion.php",
		dir + "test.php",
		dir + canary,
	}
	merged, checks := s.runDeepProbes(ctx, origin, paths)

	// A site installed under /app/ often still exposes diagnostics at the
	// document root. Only try that fallback when the directory scan did not
	// produce a full patch-level version, so a normal scan does not double
	// its request count.
	if versionNeedsConfirmation(merged.version) && dir != "/" && ctx.Err() == nil {
		rootPaths := []string{
			"/index.php",
			"/phpinfo.php",
			"/info.php",
			"/php-info.php",
			"/phpversion.php",
			"/test.php",
			"/" + canary,
		}
		rootDetection, rootChecks := s.runDeepProbes(ctx, origin, rootPaths)
		mergeDetection(&merged, rootDetection)
		checks = append(checks, rootChecks...)
	}
	return merged, checks
}

func (s *Scanner) runDeepProbes(ctx context.Context, origin string, paths []string) (detection, []DeepCheck) {
	seen := make(map[string]bool, len(paths))
	var merged detection
	checks := make([]DeepCheck, 0, len(paths))
	for _, candidate := range paths {
		if seen[candidate] {
			continue
		}
		seen[candidate] = true

		target := origin + candidate
		check := DeepCheck{URL: target}
		page, err := s.fetch(ctx, target)
		if err != nil {
			check.Error = friendlyError(err)
			checks = append(checks, check)
			if ctx.Err() != nil {
				break
			}
			continue
		}

		d := analyzePage(page)
		check.StatusCode = page.status
		check.PHPDetected = d.php
		check.PHPVersion = d.version
		check.VersionSource = d.versionSrc
		if d.php {
			d.evidence = append(d.evidence, "Hittades via extra kontroll: "+candidate)
		}
		checks = append(checks, check)
		mergeDetection(&merged, d)

		// Stop only when a full patch-level version is known; an incomplete
		// "8.4" still benefits from a later phpinfo page that reveals 8.4.27.
		if merged.version != "" && !versionNeedsConfirmation(merged.version) {
			break
		}
	}
	return merged, checks
}

var (
	phpHeaderVersionRe = regexp.MustCompile(`(?i)\bPHP(?:-CGI|-FPM)?\s*/?\s*v?(\d+\.\d+(?:\.\d+)?)`)
	phpVersionOnlyRe   = regexp.MustCompile(`(?i)^\s*v?(\d+\.\d+(?:\.\d+)?)(?:[-+][\w.\-]+)?\s*$`)
	phpInfoVersionRe   = regexp.MustCompile(`(?i)\bPHP\s+(?:Runtime\s+)?Version\s*[:/]?\s*v?(\d+\.\d+(?:\.\d+)?)`)
	phpPoweredVersion  = regexp.MustCompile(`(?i)\bPowered by\s+PHP\s*[/ ]?\s*v?(\d+\.\d+(?:\.\d+)?)`)
	phpSlashVersionRe  = regexp.MustCompile(`(?i)\bPHP(?:-CGI|-FPM)?\s*/\s*v?(\d+\.\d+(?:\.\d+)?)`)
	phpGeneratorRe     = regexp.MustCompile(`(?is)<meta[^>]+name\s*=\s*["']generator["'][^>]+content\s*=\s*["'][^"']*PHP[^"']*?(\d+\.\d+(?:\.\d+)?)`)
	phpGeneratorAltRe  = regexp.MustCompile(`(?is)<meta[^>]+content\s*=\s*["'][^"']*PHP[^"']*?(\d+\.\d+(?:\.\d+)?)[^"']*["'][^>]+name\s*=\s*["']generator["']`)
	phpLinkRe          = regexp.MustCompile(`(?i)\.php(?:["'?#/&;>)\s]|$)`)
	phpErrorRe         = regexp.MustCompile(`(?is)(?:Fatal error|Parse error|Uncaught (?:Error|Exception)|Warning|Notice|Deprecated)\s*:.{0,200}?\bon line\s+\d+`)
	uploadFormRe       = regexp.MustCompile(`(?is)<form\b[^>]*\benctype\s*=\s*["']?\s*multipart/form-data`)
	fileInputRe        = regexp.MustCompile(`(?is)<input\b[^>]*\btype\s*=\s*["']?\s*file\b`)
	phpVersionInTitle  = regexp.MustCompile(`(?i)<title>[^<]*PHP[^<]*?(\d+\.\d+(?:\.\d+)?)`)
	phpVersionInScript = regexp.MustCompile(`(?i)\bPHP_VERSION\s*[=:]\s*['"](\d+\.\d+(?:\.\d+)?)['"]`)
	phpJSONVersionRe   = regexp.MustCompile(`(?i)["']php_?version["']\s*:\s*["']?v?(\d+\.\d+(?:\.\d+)?)`)
	phpZendVersionRe   = regexp.MustCompile(`(?i)\bZend\s+Engine\s+v?[^\d]*(\d+\.\d+(?:\.\d+)?)`)
	phpZendOpcacheRe   = regexp.MustCompile(`(?i)\bZend\s+OPcache\s+v?(\d+\.\d+(?:\.\d+)?)`)
	phpStandaloneRe    = regexp.MustCompile(`(?i)\bPHP\s+(\d+\.\d+(?:\.\d+)?)\b`)
	htmlTagRe          = regexp.MustCompile(`(?s)<[^>]*>`)
	whitespaceRe       = regexp.MustCompile(`\s+`)
)

func htmlToText(body string) string {
	text := htmlTagRe.ReplaceAllString(body, " ")
	text = html.UnescapeString(text)
	return strings.TrimSpace(whitespaceRe.ReplaceAllString(text, " "))
}

func addVersionCandidate(d *detection, raw, source string, confidence int) {
	version := cleanVersion(raw)
	if version == "" {
		return
	}
	d.php = true
	for i := range d.candidates {
		if d.candidates[i].Version == version && d.candidates[i].Source == source {
			if confidence > d.candidates[i].Confidence {
				d.candidates[i].Confidence = confidence
			}
			return
		}
	}
	d.candidates = append(d.candidates, VersionCandidate{
		Version:    version,
		Source:     source,
		Confidence: confidence,
	})
}

func addFirstVersionMatch(d *detection, re *regexp.Regexp, input, source string, confidence int) {
	if m := re.FindStringSubmatch(input); m != nil {
		addVersionCandidate(d, m[1], source, confidence)
	}
}

func versionPrecision(version string) int {
	v, ok := parsePHPVersion(version)
	if !ok {
		return 0
	}
	if v.hasPatch {
		return 3
	}
	return 2
}

func sameVersionBranch(a, b string) bool {
	av, aok := parsePHPVersion(a)
	bv, bok := parsePHPVersion(b)
	return aok && bok && av.major == bv.major && av.minor == bv.minor
}

// selectVersion ranks observations by source confidence and precision. A
// header may expose only "8.4", so a slightly weaker source that gives the
// full 8.4.27 patch level for the same branch is allowed to complete it.
func selectVersion(d *detection) {
	if len(d.candidates) == 0 {
		return
	}

	best := d.candidates[0]
	for _, candidate := range d.candidates[1:] {
		if candidate.Confidence > best.Confidence ||
			(candidate.Confidence == best.Confidence && versionPrecision(candidate.Version) > versionPrecision(best.Version)) {
			best = candidate
		}
	}

	if versionPrecision(best.Version) < 3 {
		for _, candidate := range d.candidates {
			if versionPrecision(candidate.Version) > versionPrecision(best.Version) &&
				candidate.Confidence >= best.Confidence-20 &&
				sameVersionBranch(candidate.Version, best.Version) {
				best = candidate
			}
		}
	}

	d.version = best.Version
	d.versionSrc = best.Source
	for _, candidate := range d.candidates {
		d.evidence = appendUnique(d.evidence,
			fmt.Sprintf("PHP-version %s via %s (styrka %d)", candidate.Version, candidate.Source, candidate.Confidence))
	}
}

func versionNeedsConfirmation(version string) bool {
	if strings.TrimSpace(version) == "" {
		return true
	}
	v, ok := parsePHPVersion(version)
	return !ok || !v.hasPatch
}

// phpVersionFromZend maps the Zend Engine version reported by phpinfo to the
// PHP release it belongs to. Zend 4.3.x ships with PHP 8.3.x, Zend 3.4.x with
// PHP 7.4.x and Zend 2.6.x with PHP 5.6.x. Treating the Zend number as a PHP
// version would incorrectly classify PHP 8.3.14 as PHP 4.3.14.
func phpVersionFromZend(zend string) (string, bool) {
	v, ok := parsePHPVersion(zend)
	if !ok {
		return "", false
	}
	var major int
	switch v.major {
	case 1, 2:
		major = v.major + 3
	case 3, 4:
		major = v.major + 4
	default:
		return "", false
	}
	if v.hasPatch {
		return fmt.Sprintf("%d.%d.%d", major, v.minor, v.patch), true
	}
	return fmt.Sprintf("%d.%d", major, v.minor), true
}

var phpSessionCookies = []string{
	"phpsessid",
	"laravel_session",
	"ci_session",
	"cakephp",
	"symfony",
	"yii_session",
	"fuelcid",
	"wordpress_test_cookie",
	"wordpress_logged_in_",
	"wp-settings-",
}

func analyzePage(p *pageInfo) detection {
	var d detection
	if p == nil {
		return d
	}

	d.server = p.headers.Get("Server")
	d.poweredBy = p.headers.Get("X-Powered-By")

	headerVersionCandidates := []struct {
		header     string
		source     string
		confidence int
	}{
		{"X-PHP-Version", "X-PHP-Version", 100},
		{"X-Powered-By", "X-Powered-By", 95},
		{"X-PHP-Engine", "X-PHP-Engine", 90},
		{"X-Server-Powered-By", "X-Server-Powered-By", 85},
		{"X-Backend-Server", "X-Backend-Server", 85},
		{"Server", "Server", 80},
	}
	for _, candidate := range headerVersionCandidates {
		value := p.headers.Get(candidate.header)
		if value == "" {
			continue
		}
		matched := false
		if m := phpHeaderVersionRe.FindStringSubmatch(value); m != nil {
			addVersionCandidate(&d, m[1], candidate.source, candidate.confidence)
			matched = true
		} else if candidate.header == "X-PHP-Version" || candidate.header == "X-PHP-Engine" {
			// These headers sometimes contain only the bare version, for
			// example "8.3.36" or "8.3.36-1ubuntu2".
			if m := phpVersionOnlyRe.FindStringSubmatch(value); m != nil {
				addVersionCandidate(&d, m[1], candidate.source, candidate.confidence)
				matched = true
			}
		}
		if matched || strings.Contains(strings.ToUpper(value), "PHP") {
			d.php = true
			d.evidence = appendUnique(d.evidence, candidate.header+": "+truncate(value, 160))
		}
	}

	for _, setCookie := range p.headers.Values("Set-Cookie") {
		name := strings.ToLower(strings.TrimSpace(strings.SplitN(setCookie, "=", 2)[0]))
		for _, needle := range phpSessionCookies {
			if strings.Contains(name, needle) {
				d.php = true
				d.sessionCookie = true
				d.evidence = appendUnique(d.evidence, "PHP-relaterad cookie: "+strings.SplitN(setCookie, "=", 2)[0])
				break
			}
		}
	}

	body := string(p.body)
	lower := strings.ToLower(body)
	text := htmlToText(body)

	if uploadFormRe.MatchString(body) || fileInputRe.MatchString(body) {
		d.uploadForm = true
		d.evidence = appendUnique(d.evidence, "Filuppladdning identifierad i HTML-svaret")
	}

	if n := len(phpLinkRe.FindAllStringIndex(body, 2000)); n > 0 {
		d.php = true
		d.phpLinks = n
		d.evidence = appendUnique(d.evidence, fmt.Sprintf("%d PHP-länkar/referenser i HTML-svaret", n))
	}

	if m := phpErrorRe.FindString(text); m != "" {
		d.php = true
		d.evidence = appendUnique(d.evidence, "PHP-felmeddelande i svaret: "+truncate(strings.Join(strings.Fields(m), " "), 180))
	}

	// Collect every independent version observation instead of stopping at the
	// first match. This lets phpinfo, headers and framework debug pages
	// corroborate or contradict each other. HTML tags are stripped for the
	// text-oriented patterns so phpinfo tables work regardless of markup.
	addFirstVersionMatch(&d, phpInfoVersionRe, text, "HTML: PHP Version", 95)
	addFirstVersionMatch(&d, phpPoweredVersion, text, "HTML: Powered by PHP", 90)
	addFirstVersionMatch(&d, phpSlashVersionRe, body, "HTML: PHP/version", 88)
	addFirstVersionMatch(&d, phpGeneratorRe, body, "HTML: meta generator", 85)
	addFirstVersionMatch(&d, phpGeneratorAltRe, body, "HTML: meta generator", 85)
	addFirstVersionMatch(&d, phpZendOpcacheRe, text, "HTML: Zend OPcache", 78)
	if m := phpZendVersionRe.FindStringSubmatch(text); m != nil {
		if converted, ok := phpVersionFromZend(m[1]); ok {
			addVersionCandidate(&d, converted, "HTML: Zend Engine (omräknad)", 75)
		}
	}
	addFirstVersionMatch(&d, phpVersionInScript, body, "HTML: PHP_VERSION", 70)
	addFirstVersionMatch(&d, phpJSONVersionRe, body, "HTML: JSON-fält", 68)
	addFirstVersionMatch(&d, phpVersionInTitle, body, "HTML: sidtitel", 65)
	addFirstVersionMatch(&d, phpStandaloneRe, text, "HTML: PHP-version i text", 55)

	if app := detectApp(lower, p.headers); app != "" {
		d.php = true
		d.app = app
		d.evidence = appendUnique(d.evidence, "PHP-baserad applikation: "+app)
	}

	if d.server != "" {
		d.evidence = appendUnique(d.evidence, "Server: "+truncate(d.server, 160))
	}
	if d.poweredBy != "" && !strings.Contains(strings.ToUpper(d.poweredBy), "PHP") {
		d.evidence = appendUnique(d.evidence, "X-Powered-By: "+truncate(d.poweredBy, 160))
	}
	if isCDN(p.headers) != "" {
		d.evidence = appendUnique(d.evidence, "CDN/WAF: "+isCDN(p.headers))
	}

	selectVersion(&d)
	return d
}

func detectApp(lowerBody string, headers http.Header) string {
	apps := []struct {
		name    string
		markers []string
	}{
		{"WordPress", []string{"wp-content/", "wp-includes/", "/wp-json"}},
		{"Drupal", []string{"drupal.settings", "sites/default/files/"}},
		{"Joomla", []string{"/media/jui/", "com_content"}},
		{"Magento / Adobe Commerce", []string{"mage/cookies", "/static/version"}},
		{"Shopware", []string{"/bundles/storefront/"}},
		{"Laravel", []string{"laravel_session"}},
		{"Symfony", []string{"sf-toolbar"}},
		{"CodeIgniter", []string{"ci_session"}},
		{"Nextcloud", []string{"nc_session_id", "oc_sessionpassphrase"}},
		{"phpMyAdmin", []string{"pma_lang", "phpmyadmin"}},
		{"MediaWiki", []string{"mediawiki_session", "mediawikiuserid"}},
		{"Roundcube", []string{"roundcube_sessid", "roundcube_sessauth"}},
	}
	cookieHeader := strings.ToLower(strings.Join(headers.Values("Set-Cookie"), " "))
	for _, app := range apps {
		for _, marker := range app.markers {
			if strings.Contains(lowerBody, marker) || strings.Contains(cookieHeader, marker) {
				return app.name
			}
		}
	}
	return ""
}

func isCDN(headers http.Header) string {
	switch {
	case headers.Get("CF-Ray") != "" || strings.Contains(strings.ToLower(headers.Get("Server")), "cloudflare"):
		return "Cloudflare"
	case headers.Get("X-Sucuri-ID") != "":
		return "Sucuri"
	case headers.Get("X-Akamai-Transformed") != "":
		return "Akamai"
	case headers.Get("X-Fastly-Request-ID") != "":
		return "Fastly"
	}
	return ""
}

func mergeDetection(dst *detection, src detection) {
	dst.sessionCookie = dst.sessionCookie || src.sessionCookie
	dst.uploadForm = dst.uploadForm || src.uploadForm
	if !src.php {
		return
	}
	dst.php = true
	for _, candidate := range src.candidates {
		addVersionCandidate(dst, candidate.Version, candidate.Source, candidate.Confidence)
	}
	if src.version != "" && len(src.candidates) == 0 {
		addVersionCandidate(dst, src.version, src.versionSrc, 50)
	}
	selectVersion(dst)
	if dst.app == "" && src.app != "" {
		dst.app = src.app
	}
	if src.phpLinks > dst.phpLinks {
		dst.phpLinks = src.phpLinks
	}
	if dst.server == "" {
		dst.server = src.server
	}
	if dst.poweredBy == "" {
		dst.poweredBy = src.poweredBy
	}
	dst.evidence = appendUnique(dst.evidence, src.evidence...)
}

func appendUnique(list []string, values ...string) []string {
	seen := make(map[string]bool, len(list))
	for _, value := range list {
		seen[value] = true
	}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		list = append(list, value)
	}
	return list
}

func cleanVersion(raw string) string {
	m := phpVersionPrefixRe.FindStringSubmatch(strings.TrimSpace(raw))
	if m == nil {
		return strings.TrimSpace(raw)
	}
	if m[3] != "" {
		return m[1] + "." + m[2] + "." + m[3]
	}
	return m[1] + "." + m[2]
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func normalizeURL(raw string) (target string, explicitScheme bool, err error) {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, "\"'")
	raw = strings.TrimPrefix(raw, "<")
	raw = strings.TrimSuffix(raw, ">")
	if raw == "" {
		return "", false, errors.New("tom webbadress")
	}

	explicitScheme = strings.HasPrefix(strings.ToLower(raw), "http://") || strings.HasPrefix(strings.ToLower(raw), "https://")
	if !strings.Contains(raw, "://") {
		if strings.HasPrefix(raw, "//") {
			raw = "https:" + raw
		} else {
			raw = "https://" + raw
		}
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", explicitScheme, errors.New("ogiltig webbadress: " + err.Error())
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", explicitScheme, errors.New("endast http:// och https:// stöds")
	}
	if u.Host == "" {
		return "", explicitScheme, errors.New("webbadressen saknar värdnamn")
	}
	if strings.ContainsAny(u.Host, " \t\r\n") {
		return "", explicitScheme, errors.New("webbadressen innehåller ogiltiga tecken")
	}
	if u.Path == "" {
		u.Path = "/"
	}
	u.Fragment = ""
	return u.String(), explicitScheme, nil
}

func friendlyError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "tidsgränsen överskreds"
	}
	if errors.Is(err, context.Canceled) {
		return "avbruten"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no such host"):
		return "värdnamnet kunde inte slås upp (DNS)"
	case strings.Contains(msg, "connection refused"):
		return "anslutningen nekades"
	case strings.Contains(msg, "certificate"):
		return "TLS-certifikatet kunde inte verifieras (prova att ignorera TLS-fel)"
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline"):
		return "tidsgränsen överskreds"
	}
	return truncate(msg, 240)
}
