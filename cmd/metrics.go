package main

import (
	"path"
	"sort"
	"time"

	"github.com/bartlettc22/image-inquisitor/internal/config"
	"github.com/bartlettc22/image-inquisitor/internal/kubernetes"
	"github.com/bartlettc22/image-inquisitor/internal/metrics"
	"github.com/bartlettc22/image-inquisitor/internal/registries"
	"github.com/bartlettc22/image-inquisitor/internal/sources"
	"github.com/bartlettc22/image-inquisitor/internal/trivy"
)

// MetricsInput is everything buildMetrics reads. New inputs (for example the
// scan results of upgrade targets) are added as new fields, so existing
// callers keep compiling.
type MetricsInput struct {
	Inventory *sources.ImageInventory
	// Vuln holds one report per running image whose Trivy scan succeeded.
	Vuln trivy.TrivyReport
	// Registry holds one report per running image the registry pass answered.
	Registry map[string]*registries.RegistryImageReport
	// RegistryFailures counts images the registry pass could not answer.
	RegistryFailures int
	Start, Now       time.Time
	Cfg              config.Config
}

// Reserved for comparing a running image with its upgrade target. Not emitted
// yet; listed so nothing else takes the names and so the contract test can
// check they stay absent until the feature lands.
var reservedMetricNames = []string{
	"image_inquisitor_upgrade_target_info",
	"image_inquisitor_upgrade_cve_delta",
	"image_inquisitor_target_scan_failed",
}

// severities in a fixed order, so the payload is byte-stable.
var severities = []string{"critical", "high", "medium", "low", "unknown"}

func severityValues(s trivy.ImageIssueSeverity) []float64 {
	return []float64{float64(s.Critical), float64(s.High), float64(s.Medium), float64(s.Low), float64(s.Unknown)}
}

// trivyFailures is the number of inventory images with no vulnerability
// report: a scan that failed, or was never run.
func trivyFailures(in MetricsInput) int {
	if in.Inventory == nil {
		return 0
	}
	n := 0
	for image := range in.Inventory.ImageDetails {
		if _, ok := in.Vuln[image]; !ok {
			n++
		}
	}
	return n
}

// upgradeContext is the running tag, newest tag and upgrade state for one
// image. Shared by the report enrichment and the metrics so the two can never
// disagree about the same image.
func upgradeContext(reg *registries.RegistryImageReport) (running, latest, state string) {
	if reg != nil {
		running, latest = reg.Tag, reg.LatestTag
	}
	return running, latest, registries.CompareTags(running, latest)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// buildMetrics turns one scan into a metrics payload. It is pure: everything
// comes from in, and images are visited in sorted order so the same scan
// always produces the same bytes. Each metric's samples are written together.
//
// The image label is always the inventory key, FullyQualifiedName(false).
func buildMetrics(in MetricsInput) *metrics.Publisher {
	pub := metrics.NewPublisher(in.Cfg.MetricsEndpoint)

	var images []string
	var stats sources.InventoryStats
	if in.Inventory != nil {
		images = sortedKeys(in.Inventory.ImageDetails)
		if in.Inventory.Stats != nil {
			stats = *in.Inventory.Stats
		}
	}
	scanned := make([]string, 0, len(in.Vuln))
	for _, image := range images {
		if _, ok := in.Vuln[image]; ok {
			scanned = append(scanned, image)
		}
	}

	emitWorkloads(pub, in.Inventory, images)

	// Info series for every scanned image: the labels are the payload.
	for _, image := range scanned {
		running, latest, state := upgradeContext(in.Registry[image])
		c := in.Inventory.ImageDetails[image].ImageComponents
		repo := ""
		if c != nil {
			repo = path.Join(c.Registry, c.Owner, c.Repository)
		}
		pub.Gauge("image_inquisitor_image_info",
			"Always 1. Carries the running tag, newest known tag, upgrade state and repository as labels.",
			map[string]string{
				"image":         image,
				"running_tag":   running,
				"latest_tag":    latest,
				"upgrade_state": state,
				"image_repo":    repo,
			}, 1)
	}

	for _, image := range scanned {
		r := in.Vuln[image]
		if r.ImageIssues == nil || r.ImageIssues.Total == nil {
			continue
		}
		for i, v := range severityValues(*r.ImageIssues.Total) {
			pub.Gauge("image_inquisitor_vulnerabilities",
				"Vulnerabilities found in a running image, by severity.",
				map[string]string{"image": image, "severity": severities[i]}, v)
		}
	}

	for _, image := range scanned {
		for i, v := range severityValues(in.Vuln[image].FixableCounts()) {
			pub.Gauge("image_inquisitor_vulnerabilities_fixable",
				"Vulnerabilities in a running image that have a fixed version available, by severity.",
				map[string]string{"image": image, "severity": severities[i]}, v)
		}
	}

	// Age is only emitted when known. A missing series is a blank panel cell; a
	// zero would read as "built today", which is what the old int-valued field
	// wrongly claimed for epoch-pinned images.
	for _, image := range scanned {
		if age := in.Vuln[image].AgeDays; age != nil {
			pub.Gauge("image_inquisitor_build_age_days",
				"Days since the image was built, omitted when the created date is unusable.",
				map[string]string{"image": image}, float64(*age))
		}
	}

	// How long the newest known tag has been public.
	//
	// This is what separates "somebody needs to act" from "this fixes itself".
	// Renovate holds every update for minimumReleaseAge before it will even open
	// a PR, so criticals on an image whose newest tag shipped yesterday are
	// already handled -- the upgrade is queued behind a deliberate supply-chain
	// soak. Criticals on an image whose newest tag has been public for three
	// months are a different situation entirely.
	//
	// Skipped when the timestamp is unusable, on the same reasoning as
	// build_age_days: a zero would claim the release shipped today and put it
	// inside the soak window.
	for _, image := range sortedKeys(in.Registry) {
		reg := in.Registry[image]
		if reg == nil || reg.LatestTag == "" {
			continue
		}
		ts := reg.LatestTagTimestamp
		if ts.IsZero() || ts.Year() <= 2000 {
			continue
		}
		pub.Gauge("image_inquisitor_latest_tag_age_days",
			"Days since the newest known tag for this image was published. Below the Renovate soak window means an upgrade is queued rather than neglected.",
			map[string]string{"image": image}, in.Now.Sub(ts).Hours()/24)
	}

	// Every inventory image, so a failed scan is a 1 rather than a missing
	// series that looks the same as an image that is no longer running.
	for _, image := range images {
		v := 1.0
		if _, ok := in.Vuln[image]; ok {
			v = 0
		}
		pub.Gauge("image_inquisitor_scan_failed",
			"1 when the vulnerability scan of a running image failed, else 0.",
			map[string]string{"image": image}, v)
	}

	pub.Gauge("image_inquisitor_images_total",
		"Number of distinct images in the inventory.",
		nil, float64(len(images)))

	for _, f := range []struct {
		phase string
		n     int
	}{
		{"parse", stats.ParseFailures},
		{"list", stats.ListFailures},
		{"registry", in.RegistryFailures},
		{"trivy", trivyFailures(in)},
	} {
		pub.Gauge("image_inquisitor_scan_failures",
			"Failures in the completed scan, by phase.",
			map[string]string{"phase": f.phase}, float64(f.n))
	}

	emitInventoryFailures(pub, stats)

	// Liveness of the scan itself. A CronJob that stops running leaves no pod
	// to alert on; the data simply stops changing.
	pub.Gauge("image_inquisitor_scan_timestamp_seconds",
		"Unix time the scan completed. Alert on this going stale.",
		nil, float64(in.Now.Unix()))
	pub.Gauge("image_inquisitor_images_scanned",
		"Number of images in the completed scan.",
		nil, float64(len(in.Vuln)))
	pub.Gauge("image_inquisitor_scan_duration_seconds",
		"Wall-clock duration of the scan.",
		nil, in.Now.Sub(in.Start).Seconds())

	return pub
}

// emitWorkloads writes one series per distinct (image, namespace, kind,
// workload, container), across every source ID. Resources can repeat -- the
// same source merged twice, or two source IDs reporting one cluster -- and a
// workload must still count once.
func emitWorkloads(pub *metrics.Publisher, inv *sources.ImageInventory, images []string) {
	type key struct{ ns, kind, name, container string }
	for _, image := range images {
		seen := map[key]bool{}
		var keys []key
		details := inv.ImageDetails[image]
		for _, sourceID := range sortedKeys(details.ImageSourceDetailsByID) {
			sd := details.ImageSourceDetailsByID[sourceID]
			if sd == nil {
				continue
			}
			for _, v := range sd.SourcesByType {
				report, ok := v.(*kubernetes.KubernetesImageReport)
				if !ok || report == nil {
					continue
				}
				for _, r := range report.Resources {
					if r == nil {
						continue
					}
					k := key{r.Namespace, r.Kind, r.Name, r.Container}
					if !seen[k] {
						seen[k] = true
						keys = append(keys, k)
					}
				}
			}
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := keys[i], keys[j]
			if a.ns != b.ns {
				return a.ns < b.ns
			}
			if a.kind != b.kind {
				return a.kind < b.kind
			}
			if a.name != b.name {
				return a.name < b.name
			}
			return a.container < b.container
		})
		for _, k := range keys {
			pub.Gauge("image_inquisitor_image_workload",
				"Always 1. One series per Kubernetes workload container running the image.",
				map[string]string{
					"image":     image,
					"namespace": k.ns,
					"kind":      k.kind,
					"workload":  k.name,
					"container": k.container,
				}, 1)
		}
	}
}

// emitInventoryFailures writes the per-namespace inventory failure counts.
// Zeros are emitted for every namespace that was listed, so a namespace whose
// failure cleared reads 0 instead of going stale. Parse failures with no known
// namespace are emitted without a namespace label, always.
func emitInventoryFailures(pub *metrics.Publisher, stats sources.InventoryStats) {
	const help = "Inventory failures in the completed scan, by phase and namespace. No namespace label means the namespace is unknown."
	listed := sortedKeys(stats.NamespaceListFailures)
	for _, ns := range listed {
		pub.Gauge("image_inquisitor_inventory_failures", help,
			map[string]string{"phase": "list", "namespace": ns},
			float64(stats.NamespaceListFailures[ns]))
	}

	parseNS := map[string]bool{}
	for _, ns := range listed {
		parseNS[ns] = true
	}
	for ns := range stats.ParseFailuresByNamespace {
		if ns != "" {
			parseNS[ns] = true
		}
	}
	for _, ns := range sortedKeys(parseNS) {
		pub.Gauge("image_inquisitor_inventory_failures", help,
			map[string]string{"phase": "parse", "namespace": ns},
			float64(stats.ParseFailuresByNamespace[ns]))
	}
	pub.Gauge("image_inquisitor_inventory_failures", help,
		map[string]string{"phase": "parse"},
		float64(stats.ParseFailuresByNamespace[""]))
}
