package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAssessUploadProgress(t *testing.T) {
	tests := []struct {
		name           string
		det            detection
		status         string
		evidence       int
		detailContains string
	}{
		{
			name:           "php without session or upload",
			det:            detection{php: true, version: "8.4.27"},
			status:         "review",
			detailContains: uploadProgressDirective,
		},
		{
			name:           "php with session",
			det:            detection{php: true, version: "8.4.27", sessionCookie: true},
			status:         "review",
			evidence:       1,
			detailContains: uploadProgressDirective,
		},
		{
			name:           "php with session and upload",
			det:            detection{php: true, version: "8.4.27", sessionCookie: true, uploadForm: true},
			status:         "possible",
			evidence:       2,
			detailContains: "både PHP-sessioner och filuppladdning",
		},
		{
			name:           "php without version",
			det:            detection{php: true},
			status:         "review",
			detailContains: "kunde inte fastställas",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			advisory := assessUploadProgress(test.det)
			if advisory.CVE != cveUploadProgress {
				t.Fatalf("CVE = %q, want %q", advisory.CVE, cveUploadProgress)
			}
			if advisory.Status != test.status {
				t.Fatalf("Status = %q, want %q", advisory.Status, test.status)
			}
			if advisory.Severity != "low" {
				t.Fatalf("Severity = %q, want low", advisory.Severity)
			}
			if len(advisory.Evidence) != test.evidence {
				t.Fatalf("Evidence = %d items, want %d: %#v", len(advisory.Evidence), test.evidence, advisory.Evidence)
			}
			if !strings.Contains(advisory.Detail, test.detailContains) {
				t.Fatalf("Detail = %q, want it to contain %q", advisory.Detail, test.detailContains)
			}
			if !strings.Contains(advisory.Recommendation, uploadProgressDirective+" = Off") {
				t.Fatalf("Recommendation = %q, want it to contain the INI directive", advisory.Recommendation)
			}
		})
	}
}

func TestScanAddsUploadProgressAdvisory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.4.27")
		w.Header().Set("Set-Cookie", "PHPSESSID=abc123; Path=/; HttpOnly")
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><body>
			<form action="/upload" method="post" enctype="multipart/form-data">
				<input type="file" name="file">
			</form>
		</body></html>`)
	}))
	defer server.Close()

	result := NewScanner(ScanOptions{TimeoutSeconds: 3, DeepCheck: false, FollowRedirects: true}).Scan(context.Background(), server.URL)

	// The PHP2Shell verdict must stay independent from the new advisory.
	if result.Verdict != "safe" {
		t.Fatalf("Verdict = %q, want safe", result.Verdict)
	}
	if len(result.Advisories) != 1 {
		t.Fatalf("Advisories = %d, want 1: %#v", len(result.Advisories), result.Advisories)
	}
	advisory := result.Advisories[0]
	if advisory.CVE != cveUploadProgress {
		t.Fatalf("CVE = %q, want %q", advisory.CVE, cveUploadProgress)
	}
	if advisory.Status != "possible" {
		t.Fatalf("Status = %q, want possible", advisory.Status)
	}
	if len(advisory.Evidence) != 2 {
		t.Fatalf("Evidence = %d items, want 2: %#v", len(advisory.Evidence), advisory.Evidence)
	}
}

func TestScanPHPWithoutSessionsOrUploadsGetsReviewAdvisory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "PHP/8.3.36")
		_, _ = io.WriteString(w, "<html><body>En vanlig sida</body></html>")
	}))
	defer server.Close()

	result := NewScanner(ScanOptions{TimeoutSeconds: 3, DeepCheck: false, FollowRedirects: true}).Scan(context.Background(), server.URL)
	if len(result.Advisories) != 1 {
		t.Fatalf("Advisories = %d, want 1: %#v", len(result.Advisories), result.Advisories)
	}
	if result.Advisories[0].Status != "review" {
		t.Fatalf("Status = %q, want review", result.Advisories[0].Status)
	}
}

func TestScanStaticSiteHasNoAdvisory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<html><body>Statisk sida</body></html>")
	}))
	defer server.Close()

	result := NewScanner(ScanOptions{TimeoutSeconds: 3, DeepCheck: false, FollowRedirects: true}).Scan(context.Background(), server.URL)
	if len(result.Advisories) != 0 {
		t.Fatalf("Advisories = %d, want 0: %#v", len(result.Advisories), result.Advisories)
	}
}

func TestMergeDetectionCarriesUploadFlags(t *testing.T) {
	dst := detection{php: true}
	mergeDetection(&dst, detection{sessionCookie: true, uploadForm: true})
	if !dst.sessionCookie {
		t.Fatal("sessionCookie = false, want true")
	}
	if !dst.uploadForm {
		t.Fatal("uploadForm = false, want true")
	}
}
