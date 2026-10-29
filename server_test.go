package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIndexServesTokenAndVersion(t *testing.T) {
	app := NewApp()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Host = "127.0.0.1:8080"
	recorder := httptest.NewRecorder()

	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/html; charset=utf-8", got)
	}
	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	} {
		if got := recorder.Header().Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}

	body := recorder.Body.String()
	for _, want := range []string{
		app.token,
		`name="scanner-version" content="` + appVersion + `"`,
		`value="PHP2ShellChecker/` + appVersion + ` (defensive vulnerability check)"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("index body does not contain %q", want)
		}
	}
	for _, placeholder := range []string{"{{TOKEN}}", "{{VERSION}}"} {
		if strings.Contains(body, placeholder) {
			t.Fatalf("index body still contains unresolved placeholder %q", placeholder)
		}
	}
}

func TestIndexRejectsUnsupportedMethod(t *testing.T) {
	app := NewApp()
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Host = "127.0.0.1:8080"
	recorder := httptest.NewRecorder()

	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", recorder.Code)
	}
	if got := recorder.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("Allow = %q, want GET, HEAD", got)
	}
}

func TestAuthorizedRequiresLocalHostAndMatchingOrigin(t *testing.T) {
	app := NewApp()
	tests := []struct {
		name   string
		host   string
		origin string
		want   bool
	}{
		{"ipv4 loopback", "127.0.0.1:8080", "", true},
		{"localhost", "localhost:8080", "", true},
		{"ipv6 loopback", "[::1]:8080", "", true},
		{"foreign host", "example.com", "", false},
		{"matching origin", "127.0.0.1:8080", "http://127.0.0.1:8080", true},
		{"foreign origin", "127.0.0.1:8080", "http://evil.example", false},
		{"other local origin", "127.0.0.1:8080", "http://localhost:8080", false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/scan", nil)
			request.Host = test.host
			request.Header.Set("X-Scanner-Token", app.token)
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if got := app.authorized(request); got != test.want {
				t.Fatalf("authorized(host=%q, origin=%q) = %v, want %v", test.host, test.origin, got, test.want)
			}
		})
	}
}

func TestScanEndpointStreamsResults(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.3.35")
		_, _ = io.WriteString(w, "<html>test</html>")
	}))
	defer fixture.Close()

	app := NewApp()
	payload := fmt.Sprintf(`{"targets":[%q],"options":{"timeoutSeconds":3,"concurrency":1,"delayMs":0,"followRedirects":true,"deepCheck":false}}`, fixture.URL)
	request := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(payload))
	request.Host = "127.0.0.1"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Scanner-Token", app.token)
	recorder := httptest.NewRecorder()

	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", recorder.Code, recorder.Body.String())
	}

	var events []scanEvent
	decoder := json.NewDecoder(recorder.Body)
	for {
		var event scanEvent
		if err := decoder.Decode(&event); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("decode event: %v", err)
		}
		events = append(events, event)
	}
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3: %#v", len(events), events)
	}
	if events[0].Type != "start" || events[0].Total != 1 {
		t.Fatalf("start event = %#v", events[0])
	}
	if events[1].Type != "result" || events[1].Result == nil {
		t.Fatalf("result event = %#v", events[1])
	}
	if events[1].Result.Verdict != "vulnerable" {
		t.Fatalf("verdict = %q, want vulnerable", events[1].Result.Verdict)
	}
	if events[2].Type != "done" || events[2].Scanned != 1 {
		t.Fatalf("done event = %#v", events[2])
	}
}

func TestScanEndpointRequiresToken(t *testing.T) {
	app := NewApp()
	request := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(`{"targets":["https://example.com"]}`))
	request.Host = "127.0.0.1"
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

func TestScanEndpointRejectsWrongContentType(t *testing.T) {
	app := NewApp()
	request := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(`{"targets":["https://example.com"]}`))
	request.Host = "127.0.0.1"
	request.Header.Set("Content-Type", "text/plain")
	request.Header.Set("X-Scanner-Token", app.token)
	recorder := httptest.NewRecorder()

	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", recorder.Code)
	}
}

func TestShutdownEndpoint(t *testing.T) {
	app := NewApp()
	request := httptest.NewRequest(http.MethodPost, "/api/shutdown", nil)
	request.Host = "127.0.0.1"
	request.Header.Set("X-Scanner-Token", app.token)
	recorder := httptest.NewRecorder()

	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", recorder.Code)
	}
	select {
	case <-app.Shutdown():
	case <-time.After(time.Second):
		t.Fatal("shutdown channel was not closed")
	}
}

func TestHealthEndpoint(t *testing.T) {
	app := NewApp()
	request := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	request.Host = "127.0.0.1"
	recorder := httptest.NewRecorder()

	app.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if body["version"] != appVersion {
		t.Fatalf("version = %v, want %s", body["version"], appVersion)
	}
}
