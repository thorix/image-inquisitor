package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
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

// TestBrokenStdoutPipeExitsReportsFailed runs a child process whose stdout is
// a pipe with no reader. The write must fail with an error, which maps to
// exitReportsFailed, rather than the process being killed by SIGPIPE.
func TestBrokenStdoutPipeExitsReportsFailed(t *testing.T) {
	if os.Getenv("II_BROKEN_PIPE_CHILD") == "1" {
		ignoreSIGPIPE()
		var err error
		for i := 0; i < 1000 && err == nil; i++ {
			_, err = fmt.Fprintln(os.Stdout, `{"report":"line"}`)
		}
		os.Exit(exitCode(RunStats{ImagesTotal: 1, VulnPassRan: true, ReportsErr: err}))
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestBrokenStdoutPipeExitsReportsFailed$")
	cmd.Env = append(os.Environ(), "II_BROKEN_PIPE_CHILD=1")
	cmd.Stdout = w
	err = cmd.Run()
	w.Close()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("child: %v, want exit status %d", err, exitReportsFailed)
	}
	if got := ee.ExitCode(); got != exitReportsFailed {
		t.Fatalf("child: %v (exit code %d), want exit status %d", err, got, exitReportsFailed)
	}
}
