package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const appVersion = "1.0.0"

//go:embed web/index.html
var indexHTML string

type App struct {
	token      string
	version    string
	shutdownCh chan struct{}
	closeOnce  sync.Once
}

type ScanRequest struct {
	Targets []string    `json:"targets"`
	Options ScanOptions `json:"options"`
}

type scanEvent struct {
	Type      string  `json:"type"`
	Total     int     `json:"total,omitempty"`
	Result    *Result `json:"result,omitempty"`
	Scanned   int     `json:"scanned,omitempty"`
	ElapsedMS int64   `json:"elapsedMs,omitempty"`
	Message   string  `json:"message,omitempty"`
}

func NewApp() *App {
	return &App{
		token:      randomToken(),
		version:    appVersion,
		shutdownCh: make(chan struct{}),
	}
}

func (a *App) Shutdown() <-chan struct{} {
	return a.shutdownCh
}

func randomToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// This should never happen on a supported platform. If it does, the
		// scanner still runs, but the API token will be less unpredictable.
		return "php2shell-local-scanner"
	}
	return hex.EncodeToString(buf)
}

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/api/health", a.handleHealth)
	mux.HandleFunc("/api/scan", a.handleScan)
	mux.HandleFunc("/api/shutdown", a.handleShutdown)
	return a.securityHeaders(mux)
}

func (a *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	page := strings.ReplaceAll(indexHTML, "{{TOKEN}}", a.token)
	page = strings.ReplaceAll(page, "{{VERSION}}", a.version)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, page)
}

func (a *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"version":       a.version,
		"fixedVersions": fixedVersions,
		"cves":          []string{"CVE-2026-109618", "CVE-2026-109619"},
	})
}

func (a *App) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "content-type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 5<<20)
	var req ScanRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	targets := dedupeTargets(req.Targets)
	if len(targets) == 0 {
		http.Error(w, "inga webbplatser angavs", http.StatusBadRequest)
		return
	}
	if len(targets) > 10000 {
		http.Error(w, "för många webbplatser (max 10 000)", http.StatusBadRequest)
		return
	}

	opts := req.Options
	opts.applyDefaults()
	scanner := NewScanner(opts)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	enc := json.NewEncoder(w)
	writeEvent := func(event scanEvent) bool {
		if err := enc.Encode(event); err != nil {
			return false
		}
		if flusher != nil {
			flusher.Flush()
		}
		return true
	}

	if !writeEvent(scanEvent{Type: "start", Total: len(targets)}) {
		return
	}

	start := time.Now()
	jobs := make(chan string)
	results := make(chan Result, opts.Concurrency)
	var wg sync.WaitGroup

	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				if ctx.Err() != nil {
					return
				}
				select {
				case results <- scanner.Scan(ctx, target):
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, target := range targets {
			select {
			case jobs <- target:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	scanned := 0
	for result := range results {
		scanned++
		res := result
		if !writeEvent(scanEvent{Type: "result", Result: &res}) {
			cancel()
			return
		}
	}
	_ = writeEvent(scanEvent{Type: "done", Scanned: scanned, ElapsedMS: time.Since(start).Milliseconds()})
}

func (a *App) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !a.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	a.closeOnce.Do(func() { close(a.shutdownCh) })
}

func (a *App) authorized(r *http.Request) bool {
	token := r.Header.Get("X-Scanner-Token")
	if token == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(a.token)) != 1 {
		return false
	}
	if !isLocalHost(r.Host) {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(u.Host, r.Host) || !isLocalHost(u.Host) {
			return false
		}
	}
	return true
}

func isLocalHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	switch strings.ToLower(host) {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}

func dedupeTargets(raw []string) []string {
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key := strings.ToLower(item)
		if target, _, err := normalizeURL(item); err == nil {
			key = strings.ToLower(target)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	return out
}
