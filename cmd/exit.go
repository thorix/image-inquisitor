package main

// Exit codes. Per-image and per-namespace failures never change the exit code:
// they are reported as metrics and logs, and the rest of the scan is still
// worth having. A non-zero code means the scan as a whole is not trustworthy.
const (
	exitOK = 0
	// exitNoInventory: the inventory could not be built or is empty. Nothing
	// is pushed, so the previous scan's metrics stay current rather than being
	// replaced by an empty one.
	exitNoInventory = 3
	// exitAllScansFailed: every vulnerability scan failed. Metrics are pushed.
	exitAllScansFailed = 4
	// exitReportsFailed: the reports could not be written. Metrics are pushed.
	exitReportsFailed = 5
)

// RunStats is what the exit code is decided from.
type RunStats struct {
	InventoryErr  error
	ImagesTotal   int
	TrivyFailures int
	// VulnPassRan is false when no vulnerability scan was requested. Every
	// image then lacks a report, which is not the same as every scan failing.
	VulnPassRan bool
	ReportsErr  error
}

func exitCode(s RunStats) int {
	switch {
	case s.InventoryErr != nil || s.ImagesTotal == 0:
		return exitNoInventory
	case s.VulnPassRan && s.TrivyFailures == s.ImagesTotal:
		return exitAllScansFailed
	case s.ReportsErr != nil:
		return exitReportsFailed
	default:
		return exitOK
	}
}
