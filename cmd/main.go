package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"time"

	"github.com/bartlettc22/image-inquisitor/internal/config"
	"github.com/bartlettc22/image-inquisitor/internal/metrics"
	"github.com/bartlettc22/image-inquisitor/internal/registries/querier"
	"github.com/bartlettc22/image-inquisitor/internal/reports"
	"github.com/bartlettc22/image-inquisitor/internal/sources"
	exportsources "github.com/bartlettc22/image-inquisitor/internal/sources/export"
	importsources "github.com/bartlettc22/image-inquisitor/internal/sources/import"
	sourcetypes "github.com/bartlettc22/image-inquisitor/internal/sources/types"
	log "github.com/sirupsen/logrus"
)

// Registered here rather than in config so the deadline stays next to the pass
// it bounds; config.LoadConfig's flag.Parse picks it up.
var registryPassTimeout = flag.Duration("registry-pass-timeout", defaultRegistryPassTimeout,
	"Upper bound on the whole registry pass. Images not answered in time report upgrade state \"unknown\"; the rest of the scan continues. Keep it well under the Job deadline.")

func main() {
	ignoreSIGPIPE()

	start := time.Now()
	ctx := context.Background()

	cfg := config.LoadConfig()

	if cfg.LogJSON {
		log.SetFormatter(&log.JSONFormatter{})
	}
	logLevel, err := log.ParseLevel(cfg.LogLevel)
	if err != nil {
		log.Fatalf("failed to parse log level: %v", err)
	}
	log.SetLevel(logLevel)

	inventory, err := sources.GetInventoryFromSources(ctx, &sources.ImageSourcesConfig{
		SourceID:               cfg.SourceID,
		ImageSourceTypes:       cfg.ImageSources,
		ExcludeImageRegistries: cfg.ExcludeImageRegistries,
		KubernetesSourceConfig: &sources.KubernetesSourceConfig{
			IncludeNamespaces: cfg.KubernetesSourceIncludeNamespaces,
			ExcludeNamespaces: cfg.KubernetesSourceExcludeNamespaces,
		},
		FileSourceConfig: &sources.FileSourceConfig{
			SourceFilePath: cfg.ImageSourcesFilePath,
		},
		ImportSourcesConfig: &importsources.ImportSourcesConfig{
			ImportSourcesFrom:             cfg.ImportSourcesFrom,
			ImportSourcesFilePath:         cfg.ImportSourcesFilePath,
			ImportSourcesGCSBucket:        cfg.ImportSourcesGCSBucket,
			ImportSourcesGCSDirectoryPath: cfg.ImportSourcesGCSDirectoryPath,
		},
	})
	if err != nil || len(inventory.ImageDetails) == 0 {
		// Nothing is pushed: an empty or partial inventory would replace the
		// previous scan's metrics with a picture that is wrong.
		if err != nil {
			log.WithField("phase", "inventory").Errorf("building inventory: %v", err)
		} else {
			log.WithField("phase", "inventory").Error("inventory is empty")
		}
		os.Exit(exitCode(RunStats{InventoryErr: err}))
	}
	if st := inventory.Stats; st != nil && (st.ParseFailures > 0 || st.ListFailures > 0) {
		log.WithField("phase", "inventory").Warnf("inventory built with %d unparseable references and %d failed List calls", st.ParseFailures, st.ListFailures)
	}
	if len(cfg.ExportSourcesDestinations) > 0 {
		log.Infof("exporting primary sources to: %s", cfg.ExportSourcesDestinations.String())
		err := inventory.Export(ctx, &exportsources.ExporterConfig{
			SourceID:         cfg.SourceID,
			Destinations:     cfg.ExportSourcesDestinations,
			FilePath:         cfg.ExportSourcesFilePath,
			GCSBucket:        cfg.ExportSourcesGCSBucket,
			GCSDirectoryPath: cfg.ExportSourcesGCSDirectoryPath,
		})
		if err != nil {
			log.Fatalf("%v", err)
		}
	}

	masterSummaryReportList := reports.NewSummaryReportList(start)
	masterImageReportList := reports.NewImageReportList(start)

	// Maps each image to the Kubernetes workloads running it. This is what turns
	// a CVE list into a work queue -- "this image has 5 criticals" is far less
	// actionable than "this image has 5 criticals and 6 Deployments run it".
	if cfg.ReportOutputs.Contains(reports.ReportTypeImageKubernetes) {
		// The kubernetes source folds its data into the inventory as
		// ImageSourceDetails, keyed by source type; read it back out from there.
		for imageFullName, details := range inventory.ImageDetails {
			for _, sourceDetails := range details.ImageSourceDetailsByID {
				if sourceDetails == nil {
					continue
				}
				if kubeReport, ok := sourceDetails.SourcesByType[sourcetypes.ImageSourceTypeKubernetes]; ok {
					masterImageReportList.AddImageReport(reports.ReportTypeImageKubernetes, imageFullName, kubeReport)
				}
			}
		}
	}

	// Each pass runs when its report is asked for, or when metrics are on:
	// the metrics need both.
	metricsOn := cfg.MetricsEndpoint != ""
	wantRegistryReports := cfg.ReportOutputs.Contains(reports.ReportTypeImageRegistry) ||
		cfg.ReportOutputs.Contains(reports.ReportTypeSummaryRegistry)
	wantVulnReports := cfg.ReportOutputs.Contains(reports.ReportTypeImageVulnerabilities)

	registryQuerier := querier.NewRegistryQuerier(cfg.HarborRegistries)
	passes := runPasses(ctx, inventory, passConfig{
		RunRegistry:     wantRegistryReports || metricsOn,
		RunVuln:         wantVulnReports || metricsOn,
		RegistryTimeout: *registryPassTimeout,
		Fetch:           registryQuerier.FetchReport,
		ScanVuln:        scanVulnerabilities(cfg.VulnerabilityDetail),
	})

	// Enrich AFTER both passes, not inside either: they run concurrently, so
	// neither can read the other's results without racing. Images with no
	// registry report get upgrade state "unknown".
	enrich(passes.Vuln, passes.Registry)

	if wantRegistryReports {
		for imageFullName, registryReport := range passes.Registry {
			masterImageReportList.AddImageReport(reports.ReportTypeImageRegistry, imageFullName, registryReport)
		}
	}
	if wantVulnReports {
		for imageFullName, vulnReport := range passes.Vuln {
			masterImageReportList.AddImageReport(reports.ReportTypeImageVulnerabilities, imageFullName, vulnReport)
		}
	}

	// Reports are written BEFORE the metrics push. They are the system of
	// record, and a slow or failing metrics endpoint must not cost them.
	//
	// Summary reports are derived from the per-image reports, so only generate
	// them when a summary-type report was actually asked for.
	var reportErrs []error
	wantSummary := false
	for _, rt := range cfg.ReportOutputs {
		if rt.IsSummaryReportType() {
			wantSummary = true
			break
		}
	}
	if wantSummary {
		masterSummaryReportList.GenerateSummaryReports(inventory.ImageComponents(), masterImageReportList)
		if err := masterSummaryReportList.Output(); err != nil {
			reportErrs = append(reportErrs, err)
		}
	}
	// Always emit the per-image reports, whichever report types were asked for.
	if err := masterImageReportList.Output(); err != nil {
		reportErrs = append(reportErrs, err)
	}
	reportsErr := errors.Join(reportErrs...)
	if reportsErr != nil {
		log.WithField("phase", "reports").Errorf("writing reports: %v", reportsErr)
	}

	in := MetricsInput{
		Inventory:        inventory,
		Vuln:             passes.Vuln,
		Registry:         passes.Registry,
		RegistryFailures: passes.RegistryFailures,
		Start:            start,
		Now:              time.Now(),
		Cfg:              cfg,
	}

	// Publish the same findings as metrics: last-value semantics, so no
	// consumer has to work out which scan falls inside its time window.
	if metricsOn {
		endpoint := metrics.Redact(cfg.MetricsEndpoint)
		if err := buildMetrics(in).Push(30 * time.Second); err != nil {
			// Never fatal and never changes the exit code: the reports are
			// already written, and a metrics outage must not cost the scan.
			log.WithFields(log.Fields{"phase": "metrics", "endpoint": endpoint}).Errorf("publishing metrics: %v", err)
		} else {
			log.WithField("endpoint", endpoint).Infof("published metrics for %d images", len(passes.Vuln))
		}
	}

	code := exitCode(RunStats{
		ImagesTotal:   len(inventory.ImageDetails),
		TrivyFailures: trivyFailures(in),
		VulnPassRan:   passes.VulnPassRan,
		ReportsErr:    reportsErr,
	})
	log.WithField("exit_code", code).Infof("done")
	os.Exit(code)
}
