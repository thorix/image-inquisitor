package main

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bartlettc22/image-inquisitor/internal/imageUtils"
	"github.com/bartlettc22/image-inquisitor/internal/registries"
	"github.com/bartlettc22/image-inquisitor/internal/trivy"
)

// t6fakeVuln returns a clean report for every image it is asked to scan.
func t6fakeVuln(_ context.Context, images []string) (trivy.TrivyReport, error) {
	out := trivy.TrivyReport{}
	for _, img := range images {
		out[img] = &trivy.TrivyImageReport{ImageIssues: &trivy.ImageIssues{Total: &trivy.ImageIssueSeverity{}}}
	}
	return out, nil
}

func TestRegistryPassDeadlineDegradesToUnknown(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	var calls atomic.Int32
	fetch := func(img *imageUtils.Image) (*registries.RegistryImageReport, error) {
		calls.Add(1)
		if img.Repository == "app" {
			return &registries.RegistryImageReport{Tag: img.Tag, LatestTag: img.Tag}, nil
		}
		// Simulates a registry stuck in rate-limit backoff.
		<-release
		return &registries.RegistryImageReport{Tag: img.Tag, LatestTag: "9"}, nil
	}

	inv := t6inventory(t)
	started := time.Now()
	res := runPasses(context.Background(), inv, passConfig{
		RunRegistry:     true,
		RunVuln:         true,
		RegistryTimeout: 50 * time.Millisecond,
		Fetch:           fetch,
		ScanVuln:        t6fakeVuln,
	})
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("pass did not honour its deadline: %v", elapsed)
	}

	// Sorted order: app is fetched first and succeeds; broken blocks, hits the
	// deadline, and db is never attempted.
	if n := calls.Load(); n != 2 {
		t.Errorf("want 2 fetch calls (app, broken), got %d", n)
	}
	if _, ok := res.Registry["example.lan/team/app:1"]; !ok || len(res.Registry) != 1 {
		t.Errorf("want only app's registry report, got %v", res.Registry)
	}
	if res.RegistryFailures != 2 {
		t.Errorf("want 2 registry failures (broken, db), got %d", res.RegistryFailures)
	}
	if !res.VulnPassRan || len(res.Vuln) != 3 {
		t.Fatalf("vulnerability pass must still complete: ran=%v reports=%d", res.VulnPassRan, len(res.Vuln))
	}

	enrich(res.Vuln, res.Registry)
	for img, want := range map[string]string{
		"example.lan/team/app:1":    trivy.UpgradeStateCurrent,
		"example.lan/team/broken:3": trivy.UpgradeStateUnknown,
		"example.lan/team/db:2":     trivy.UpgradeStateUnknown,
	} {
		if got := res.Vuln[img].UpgradeState; got != want {
			t.Errorf("%s: upgrade state %q, want %q", img, got, want)
		}
	}

	in := MetricsInput{Inventory: inv, Vuln: res.Vuln, Registry: res.Registry, RegistryFailures: res.RegistryFailures, Start: fixtureStart, Now: fixtureNow}
	p := buildMetrics(in).Payload()
	for _, want := range []string{
		`image_inquisitor_scan_failures{phase="registry"} 2`,
		`image="example.lan/team/db:2",image_repo="example.lan/team/db",latest_tag="",running_tag="",upgrade_state="unknown"} 1`,
		`image="example.lan/team/broken:3",image_repo="example.lan/team/broken",latest_tag="",running_tag="",upgrade_state="unknown"} 1`,
		`upgrade_state="current"`,
	} {
		if !strings.Contains(p, want) {
			t.Errorf("payload missing %q:\n%s", want, p)
		}
	}
	if got := exitCode(RunStats{ImagesTotal: len(inv.ImageDetails), TrivyFailures: trivyFailures(in), VulnPassRan: res.VulnPassRan}); got != 0 {
		t.Errorf("a registry deadline must not change the exit code, got %d", got)
	}
}

func TestRegistryPassExpiredContextAttemptsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fetch := func(*imageUtils.Image) (*registries.RegistryImageReport, error) {
		t.Error("no fetch may start once the deadline has passed")
		return nil, nil
	}
	reports, failures := runRegistryPass(ctx, t6inventory(t).ImageComponents(), fetch)
	if len(reports) != 0 || failures != 3 {
		t.Errorf("want 0 reports and 3 failures, got %d and %d", len(reports), failures)
	}
}

func TestRegistryPassCountsErrors(t *testing.T) {
	fetch := func(img *imageUtils.Image) (*registries.RegistryImageReport, error) {
		if img.Repository == "db" {
			return nil, errors.New("HTTP 500")
		}
		return &registries.RegistryImageReport{Tag: img.Tag}, nil
	}
	reports, failures := runRegistryPass(context.Background(), t6inventory(t).ImageComponents(), fetch)
	if len(reports) != 2 || failures != 1 {
		t.Errorf("want 2 reports and 1 failure, got %d and %d", len(reports), failures)
	}
}

func TestPassesSkippedWhenNotRequested(t *testing.T) {
	res := runPasses(context.Background(), t6inventory(t), passConfig{
		Fetch: func(*imageUtils.Image) (*registries.RegistryImageReport, error) {
			t.Error("registry pass must not run")
			return nil, nil
		},
		ScanVuln: func(context.Context, []string) (trivy.TrivyReport, error) {
			t.Error("vulnerability pass must not run")
			return nil, nil
		},
	})
	if res.VulnPassRan {
		t.Error("VulnPassRan must be false when the pass did not run")
	}
}

func TestVulnPassSetupErrorCountsAsRan(t *testing.T) {
	inv := t6inventory(t)
	res := runPasses(context.Background(), inv, passConfig{
		RunVuln: true,
		ScanVuln: func(context.Context, []string) (trivy.TrivyReport, error) {
			return nil, errors.New("no temp dir")
		},
	})
	in := MetricsInput{Inventory: inv, Vuln: res.Vuln}
	if got := exitCode(RunStats{ImagesTotal: 3, TrivyFailures: trivyFailures(in), VulnPassRan: res.VulnPassRan}); got != 4 {
		t.Errorf("a vulnerability pass that could not start scanned nothing: want 4, got %d", got)
	}
}
