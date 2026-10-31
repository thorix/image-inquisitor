package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/bartlettc22/image-inquisitor/internal/imageUtils"
	"github.com/bartlettc22/image-inquisitor/internal/registries"
	"github.com/bartlettc22/image-inquisitor/internal/sources"
	"github.com/bartlettc22/image-inquisitor/internal/trivy"
	log "github.com/sirupsen/logrus"
)

// defaultRegistryPassTimeout bounds the whole registry pass. It must sit well
// under the Job's own deadline: a registry that keeps rate-limiting would
// otherwise hold the pass open until the Job is killed, losing the
// vulnerability results and metrics along with it.
const defaultRegistryPassTimeout = 30 * time.Minute

type fetchFunc func(*imageUtils.Image) (*registries.RegistryImageReport, error)

type vulnScanFunc func(ctx context.Context, images []string) (trivy.TrivyReport, error)

type passConfig struct {
	RunRegistry     bool
	RunVuln         bool
	RegistryTimeout time.Duration
	Fetch           fetchFunc
	ScanVuln        vulnScanFunc
}

type passResults struct {
	Registry         map[string]*registries.RegistryImageReport
	RegistryFailures int
	Vuln             trivy.TrivyReport
	VulnPassRan      bool
}

// runPasses runs the requested registry and vulnerability passes concurrently
// and waits for both.
func runPasses(ctx context.Context, inv *sources.ImageInventory, pc passConfig) passResults {
	res := passResults{Registry: map[string]*registries.RegistryImageReport{}}
	var wg sync.WaitGroup
	var mu sync.Mutex

	if pc.RunRegistry {
		timeout := pc.RegistryTimeout
		if timeout <= 0 {
			timeout = defaultRegistryPassTimeout
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			regCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			reports, failures := runRegistryPass(regCtx, inv.ImageComponents(), pc.Fetch)
			mu.Lock()
			res.Registry = reports
			res.RegistryFailures = failures
			mu.Unlock()
		}()
	}

	if pc.RunVuln {
		res.VulnPassRan = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			report, err := pc.ScanVuln(ctx, inv.ImagesAsSlice())
			if err != nil {
				log.WithField("phase", "trivy").Errorf("vulnerability pass: %v", err)
				return
			}
			mu.Lock()
			res.Vuln = report
			mu.Unlock()
		}()
	}

	wg.Wait()
	return res
}

// runRegistryPass fetches a registry report for each image in sorted order.
// Failed images are counted and logged, never fatal. Once ctx is done, the
// in-flight lookup is abandoned and every image not yet answered counts as a
// failure; those images report upgrade_state "unknown".
func runRegistryPass(ctx context.Context, images imageUtils.ImagesList, fetch fetchFunc) (map[string]*registries.RegistryImageReport, int) {
	reports := map[string]*registries.RegistryImageReport{}
	failures := 0
	names := sortedKeys(images)

	type result struct {
		report *registries.RegistryImageReport
		err    error
	}
	for i, name := range names {
		if ctx.Err() != nil {
			failures += skipRemaining(ctx, names[i:])
			break
		}
		done := make(chan result, 1) // buffered: an abandoned lookup must not block forever
		go func(img *imageUtils.Image) {
			r, err := fetch(img)
			done <- result{r, err}
		}(images[name])

		select {
		case r := <-done:
			if r.err == nil && r.report == nil {
				r.err = errors.New("registry returned no report")
			}
			if r.err != nil {
				failures++
				log.WithFields(log.Fields{"image": name, "phase": "registry"}).Errorf("%v", r.err)
				continue
			}
			reports[name] = r.report
		case <-ctx.Done():
			failures += skipRemaining(ctx, names[i:])
			return reports, failures
		}
	}
	return reports, failures
}

func skipRemaining(ctx context.Context, names []string) int {
	for _, name := range names {
		log.WithFields(log.Fields{"image": name, "phase": "registry"}).
			Errorf("registry pass stopped before this image: %v", context.Cause(ctx))
	}
	return len(names)
}

// enrich copies each image's upgrade context into its vulnerability report.
// Run after both passes finish, never inside either: they are concurrent.
//
// The state is always set, even with no registry report. An ABSENT label and a
// label reading "unknown" are very different to a consumer: Loki drops records
// whose label does not exist from a label filter, so leaving it unset would
// silently hide exactly the images nothing is known about.
func enrich(vuln trivy.TrivyReport, registry map[string]*registries.RegistryImageReport) {
	for image, report := range vuln {
		running, latest, _ := upgradeContext(registry[image])
		report.SetUpgradeContext(running, latest)
	}
}

// scanVulnerabilities runs Trivy over images in a temporary output directory.
// The error is only for failing to start; per-image failures are logged by
// the runner and show up as images missing from the report.
func scanVulnerabilities(vulnerabilityDetail bool) vulnScanFunc {
	return func(ctx context.Context, images []string) (trivy.TrivyReport, error) {
		dir, err := os.MkdirTemp("/tmp", "trivy_*")
		if err != nil {
			return nil, fmt.Errorf("creating Trivy output directory: %w", err)
		}
		defer func() {
			if err := os.RemoveAll(dir); err != nil {
				log.Errorf("removing Trivy output directory: %v", err)
			}
		}()
		runner := trivy.NewTrivyRunner(trivy.TrivyRunnerConfig{
			VulnerabilityDetail: vulnerabilityDetail,
			NumWorkers:          5,
			Images:              images,
			OutputDir:           dir,
		})
		report, failures := runner.RunContext(ctx)
		if len(failures) > 0 {
			log.WithField("phase", "trivy").Warnf("%d of %d vulnerability scans failed", len(failures), len(images))
		}
		return report, nil
	}
}
