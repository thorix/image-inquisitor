package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/bartlettc22/image-inquisitor/internal/kubernetes"
)

func TestExitCode(t *testing.T) {
	cases := []struct {
		name string
		in   RunStats
		want int
	}{
		{"inventory error", RunStats{InventoryErr: errors.New("boom"), ImagesTotal: 5, VulnPassRan: true}, 3},
		{"every namespace list failed", RunStats{InventoryErr: fmt.Errorf("listing: %w", kubernetes.ErrAllListsFailed)}, 3},
		{"zero images", RunStats{ImagesTotal: 0, VulnPassRan: true}, 3},
		{"every trivy scan failed", RunStats{ImagesTotal: 5, TrivyFailures: 5, VulnPassRan: true}, 4},
		{"every trivy scan failed and reports failed", RunStats{ImagesTotal: 5, TrivyFailures: 5, VulnPassRan: true, ReportsErr: errors.New("w")}, 4},
		{"reports error", RunStats{ImagesTotal: 5, TrivyFailures: 1, VulnPassRan: true, ReportsErr: errors.New("write")}, 5},
		{"4 of 5 trivy failures", RunStats{ImagesTotal: 5, TrivyFailures: 4, VulnPassRan: true}, 0},
		// Per-namespace List failures are not an inventory error: the source
		// returns them as stats only, so they never reach InventoryErr.
		{"per-namespace list failures only", RunStats{ImagesTotal: 5, VulnPassRan: true}, 0},
		// With no vulnerability pass, every image lacks a report; that is not a
		// failed scan.
		{"vulnerability pass never ran", RunStats{ImagesTotal: 5, TrivyFailures: 5, VulnPassRan: false}, 0},
		{"vulnerability pass never ran, reports error", RunStats{ImagesTotal: 5, TrivyFailures: 5, ReportsErr: errors.New("w")}, 5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := exitCode(c.in); got != c.want {
				t.Errorf("exitCode(%+v) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}
