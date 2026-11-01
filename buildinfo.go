package main

import "fmt"

// These values are injected by build.sh and build-windows.bat through
// -ldflags -X. Development builds keep the defaults.
var (
	buildTime   = "development"
	buildNumber = "dev"
	buildCommit = "unknown"
)

func buildInfoText() string {
	return fmt.Sprintf("build #%s · %s · commit %s", buildNumber, buildTime, buildCommit)
}
