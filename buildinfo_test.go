package main

import (
	"strings"
	"testing"
)

func TestBuildInfoText(t *testing.T) {
	oldTime, oldNumber, oldCommit := buildTime, buildNumber, buildCommit
	t.Cleanup(func() {
		buildTime, buildNumber, buildCommit = oldTime, oldNumber, oldCommit
	})

	buildTime = "2026-11-01T10:20:46Z"
	buildNumber = "42"
	buildCommit = "abc1234"

	got := buildInfoText()
	for _, want := range []string{"#42", buildTime, buildCommit} {
		if !strings.Contains(got, want) {
			t.Fatalf("buildInfoText() = %q, want it to contain %q", got, want)
		}
	}
}
