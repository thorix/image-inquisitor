package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	log "github.com/sirupsen/logrus"
)

const (
	defaultNumWorkers   = 10
	defaultScanTimeout  = 16 * time.Minute
	defaultTrivyTimeout = "15m"
)

type TrivyRunnerConfig struct {
	// See config.VulnerabilityDetail.
	VulnerabilityDetail bool
	Images              []string
	NumWorkers          int
	OutputDir           string
	// ScanTimeout is the backstop deadline for one trivy process.
	ScanTimeout time.Duration
	// TrivyTimeout is passed to trivy --timeout.
	TrivyTimeout string
}

type TrivyRunner struct {
	TrivyRunnerConfig
}

type RunResults map[string]*ScanResult

type ScanResult struct {
	Worker int
	Image  string
	Report *trivyTypes.Report
	Output string
	Err    error
}

func NewTrivyRunner(config TrivyRunnerConfig) *TrivyRunner {
	if config.NumWorkers == 0 {
		config.NumWorkers = defaultNumWorkers
	}
	if config.ScanTimeout == 0 {
		config.ScanTimeout = defaultScanTimeout
	}
	if config.TrivyTimeout == "" {
		config.TrivyTimeout = defaultTrivyTimeout
	}
	return &TrivyRunner{
		TrivyRunnerConfig: config,
	}
}

func (tr *TrivyRunner) Run() TrivyReport {
	r, _ := tr.RunContext(context.Background())
	return r
}

// RunContext scans every image and returns the report for the successful
// scans plus a map of image to error for every failed scan.
func (tr *TrivyRunner) RunContext(ctx context.Context) (TrivyReport, map[string]error) {
	runResults := tr.runScans(ctx)
	failures := make(map[string]error)
	for image, r := range runResults {
		if r.Err != nil {
			failures[image] = r.Err
		}
	}
	return formatReport(runResults, tr.VulnerabilityDetail), failures
}

func (tr *TrivyRunner) runScans(ctx context.Context) RunResults {
	numWorkers := tr.NumWorkers
	if numWorkers <= 0 {
		numWorkers = defaultNumWorkers
	}
	scanTimeout := tr.ScanTimeout
	if scanTimeout <= 0 {
		scanTimeout = defaultScanTimeout
	}
	trivyTimeout := tr.TrivyTimeout
	if trivyTimeout == "" {
		trivyTimeout = defaultTrivyTimeout
	}

	imageQueue := make(chan string, len(tr.Images))
	scanResultQueue := make(chan *ScanResult, len(tr.Images))

	for i := 0; i < numWorkers; i++ {
		go worker(ctx, i, tr.OutputDir, scanTimeout, trivyTimeout, imageQueue, scanResultQueue)
	}

	for _, image := range tr.Images {
		imageQueue <- image
	}
	close(imageQueue)

	runResults := make(RunResults)
	for range tr.Images {
		scanResult := <-scanResultQueue
		runResults[scanResult.Image] = scanResult
	}
	return runResults
}

func worker(ctx context.Context, id int, outputDir string, scanTimeout time.Duration, trivyTimeout string, images <-chan string, results chan<- *ScanResult) {
	for image := range images {
		results <- scanOne(ctx, id, outputDir, scanTimeout, trivyTimeout, image)
	}
}

func scanOne(ctx context.Context, id int, outputDir string, scanTimeout time.Duration, trivyTimeout, image string) *ScanResult {
	log.Debugf("running Trivy scan on: %s", image)

	result := &ScanResult{Worker: id, Image: image}

	f, err := os.CreateTemp(outputDir, "scan-*.json")
	if err != nil {
		result.Err = fmt.Errorf("failed creating Trivy output file: %w", err)
		return result
	}
	outputFile := f.Name()
	f.Close()
	defer os.Remove(outputFile)

	scanCtx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	cmd := exec.CommandContext(scanCtx, "trivy", "image", "--quiet", "--timeout", trivyTimeout, "--format", "json", "--output", outputFile, "--", image)
	// Do not wait forever on pipes held open by grandchildren after the kill.
	cmd.WaitDelay = 2 * time.Second

	output, err := cmd.CombinedOutput()
	result.Output = string(output)
	if err != nil {
		if scanCtx.Err() != nil {
			err = fmt.Errorf("%w: %v", scanCtx.Err(), err)
		}
		result.Err = fmt.Errorf("failed to run Trivy for image %s: %w", image, err)
		return result
	}

	scanContent, err := os.ReadFile(outputFile)
	if err != nil {
		result.Err = fmt.Errorf("failed reading Trivy output file (%s): %v", outputFile, err)
		return result
	}

	report := &trivyTypes.Report{}
	if err := json.Unmarshal(scanContent, report); err != nil {
		result.Err = fmt.Errorf("failed parsing Trivy output file: %v", err)
		return result
	}
	result.Report = report

	log.Debugf("DONE running Trivy scan on: %s", image)
	return result
}
