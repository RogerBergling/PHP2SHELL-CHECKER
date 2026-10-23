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
