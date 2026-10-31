package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type benchmarkRoundTripper struct{}

func (benchmarkRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	body := `<html><body>static page without a PHP version</body></html>`
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

// BenchmarkWorstCase10000TargetsDeepCheck measures the 10,000-target
// worst case with deep analysis enabled: seven directory probes plus seven
// document-root probes per target. The transport is in-memory, so the result
// measures scanner and analysis overhead rather than network latency.
//
// Run it explicitly:
//
//	go test -run '^$' -bench BenchmarkWorstCase10000TargetsDeepCheck -benchtime=1x
func BenchmarkWorstCase10000TargetsDeepCheck(b *testing.B) {
	scanner := NewScanner(ScanOptions{
		TimeoutSeconds:  3,
		DeepCheck:       true,
		FollowRedirects: true,
		DelayMS:         0,
		MaxRetries:      intPtr(0),
	})
	scanner.client.Transport = benchmarkRoundTripper{}

	targets := make([]string, 10000)
	for i := range targets {
		targets[i] = fmt.Sprintf("http://bench.example/app/%d", i)
	}

	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		for _, target := range targets {
			_ = scanner.Scan(context.Background(), target)
		}
	}
	b.ReportMetric(10000, "targets/op")
}
