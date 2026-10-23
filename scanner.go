package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
	if strings.TrimSpace(o.UserAgent) == "" {
		o.UserAgent = "PHP2ShellChecker/1.1 (defensive vulnerability check)"
	}
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
}

type pageInfo struct {
	url     string
	status  int
	headers http.Header
	body    []byte
}

type detection struct {
	php           bool
	version       string
	versionSrc    string
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
	res.Server = page.headers.Get("Server")
	res.PoweredBy = page.headers.Get("X-Powered-By")

	det := analyzePage(page)
	if s.opts.DeepCheck && det.version == "" {
		mergeDetection(&det, s.deepCheck(ctx, page.url))
	}

	res.PHPDetected = det.php
	res.PHPVersion = det.version
	res.VersionSource = det.versionSrc
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

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}

	finalURL := target
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	return &pageInfo{
		url:     finalURL,
		status:  resp.StatusCode,
		headers: resp.Header,
		body:    body,
	}, nil
}

func (s *Scanner) deepCheck(ctx context.Context, base string) detection {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return detection{}
	}
	origin := u.Scheme + "://" + u.Host
	dir := path.Dir(u.Path)
	if dir == "." || dir == "" {
		dir = "/"
	}
	if !strings.HasSuffix(dir, "/") {
		dir += "/"
	}
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		random = []byte("a1b2c3")
	}
	paths := []string{
		dir + "index.php",
		dir + "php2shell-check-" + hex.EncodeToString(random) + ".php",
	}

	var merged detection
	for _, path := range paths {
		page, err := s.fetch(ctx, origin+path)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}
		d := analyzePage(page)
		if d.php {
			d.evidence = append(d.evidence, "Hittades via extra kontroll: "+path)
		}
		mergeDetection(&merged, d)
		if merged.version != "" {
			break
		}
	}
	return merged
}

var (
	phpHeaderVersionRe = regexp.MustCompile(`(?i)\bPHP\s*/?\s*v?(\d+\.\d+(?:\.\d+)?)`)
	phpInfoVersionRe   = regexp.MustCompile(`(?i)\bPHP\s*Version\s*[:/]?\s*v?(\d+\.\d+(?:\.\d+)?)`)
	phpPoweredVersion  = regexp.MustCompile(`(?i)\bPowered by\s+PHP\s*[/ ]?\s*v?(\d+\.\d+(?:\.\d+)?)`)
	phpGeneratorRe     = regexp.MustCompile(`(?is)<meta[^>]+name\s*=\s*["']generator["'][^>]+content\s*=\s*["'][^"']*PHP[^"']*?(\d+\.\d+(?:\.\d+)?)`)
	phpLinkRe          = regexp.MustCompile(`(?i)\.php(?:["'?#/&;>)\s]|$)`)
	phpErrorRe         = regexp.MustCompile(`(?is)(?:Fatal error|Parse error|Uncaught (?:Error|Exception)|Warning|Notice|Deprecated)\s*:.{0,200}?\bon line\s+\d+`)
	uploadFormRe       = regexp.MustCompile(`(?is)<form\b[^>]*\benctype\s*=\s*["']?\s*multipart/form-data`)
	fileInputRe        = regexp.MustCompile(`(?is)<input\b[^>]*\btype\s*=\s*["']?\s*file\b`)
)

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
		header string
		source string
	}{
		{"X-Powered-By", "X-Powered-By"},
		{"X-PHP-Version", "X-PHP-Version"},
		{"X-PHP-Engine", "X-PHP-Engine"},
		{"Server", "Server"},
	}
	for _, candidate := range headerVersionCandidates {
		value := p.headers.Get(candidate.header)
		if value == "" {
			continue
		}
		if m := phpHeaderVersionRe.FindStringSubmatch(value); m != nil {
			d.php = true
			d.version = cleanVersion(m[1])
			d.versionSrc = candidate.source
			d.evidence = appendUnique(d.evidence, candidate.header+": "+truncate(value, 160))
			break
		}
		if candidate.header == "X-Powered-By" && strings.Contains(strings.ToUpper(value), "PHP") {
			d.php = true
			d.evidence = appendUnique(d.evidence, "X-Powered-By: "+truncate(value, 160))
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

	if uploadFormRe.MatchString(body) || fileInputRe.MatchString(body) {
		d.uploadForm = true
		d.evidence = appendUnique(d.evidence, "Filuppladdning identifierad i HTML-svaret")
	}

	if n := len(phpLinkRe.FindAllStringIndex(body, 2000)); n > 0 {
		d.php = true
		d.phpLinks = n
		d.evidence = appendUnique(d.evidence, fmt.Sprintf("%d PHP-länkar/referenser i HTML-svaret", n))
	}

	if m := phpErrorRe.FindString(body); m != "" {
		d.php = true
		d.evidence = appendUnique(d.evidence, "PHP-felmeddelande i svaret: "+truncate(strings.Join(strings.Fields(m), " "), 180))
	}

	if d.version == "" {
		for _, re := range []*regexp.Regexp{phpInfoVersionRe, phpPoweredVersion, phpGeneratorRe} {
			if m := re.FindStringSubmatch(body); m != nil {
				d.php = true
				d.version = cleanVersion(m[1])
				d.versionSrc = "HTML-svar"
				d.evidence = appendUnique(d.evidence, "PHP-version anges i HTML-svaret: "+d.version)
				break
			}
		}
	}

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
	if dst.version == "" && src.version != "" {
		dst.version = src.version
		dst.versionSrc = src.versionSrc
	}
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
