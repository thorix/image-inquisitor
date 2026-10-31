package main

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bartlettc22/image-inquisitor/internal/config"
	"github.com/bartlettc22/image-inquisitor/internal/kubernetes"
	"github.com/bartlettc22/image-inquisitor/internal/registries"
	"github.com/bartlettc22/image-inquisitor/internal/sources"
	"github.com/bartlettc22/image-inquisitor/internal/sources/types"
	"github.com/bartlettc22/image-inquisitor/internal/trivy"
)

var update = flag.Bool("update", false, "rewrite cmd/testdata golden files")

var (
	fixtureStart = time.Date(2026, 10, 31, 6, 0, 0, 0, time.UTC)
	fixtureNow   = fixtureStart.Add(90 * time.Second)
)

func t6res(kind, ns, name, container string) *kubernetes.KubernetesResource {
	return &kubernetes.KubernetesResource{Kind: kind, Namespace: ns, Name: name, Container: container}
}

func t6kube(res ...*kubernetes.KubernetesResource) *types.ImageSourceDetails {
	return &types.ImageSourceDetails{
		SourcesByType: map[types.ImageSourceType]interface{}{
			types.ImageSourceTypeKubernetes: &kubernetes.KubernetesImageReport{Resources: res},
		},
	}
}

func t6inventory(t *testing.T) *sources.ImageInventory {
	t.Helper()
	inv := sources.NewImageInventory(&sources.ImageInventoryConfig{})
	err := inv.AddImageSourceDetails("src", map[string]*types.ImageSourceDetails{
		"example.lan/team/app:1": t6kube(
			t6res("Deployment", "ns-a", "app-one", "app"),
			t6res("Deployment", "ns-a", "app-two", "app"),
			t6res("Deployment", "ns-a", "app-one", "sidecar"),
		),
		"example.lan/team/db:2@sha256:" + strings.Repeat("d", 64): t6kube(
			t6res("StatefulSet", "ns-b", "db", "db"),
		),
		"example.lan/team/broken:3": t6kube(
			t6res("Deployment", "ns-b", "broken", "broken"),
		),
	})
	if err != nil {
		t.Fatalf("building fixture inventory: %v", err)
	}
	inv.Stats = &sources.InventoryStats{
		ParseFailures:            2,
		ParseFailuresByNamespace: map[string]int{"ns-a": 1, "": 1},
		ListFailures:             1,
		NamespaceListFailures:    map[string]int{"ns-a": 0, "ns-b": 1},
	}
	return inv
}

func t6vuln(total trivy.ImageIssueSeverity, age int, findings ...trivy.FindingKey) *trivy.TrivyImageReport {
	return &trivy.TrivyImageReport{
		AgeDays:     &age,
		ImageIssues: &trivy.ImageIssues{Total: &total},
		Findings:    findings,
	}
}

func t6input(t *testing.T) MetricsInput {
	t.Helper()
	return MetricsInput{
		Inventory: t6inventory(t),
		Vuln: trivy.TrivyReport{
			"example.lan/team/app:1": t6vuln(trivy.ImageIssueSeverity{Critical: 1, High: 2, Low: 1}, 40,
				trivy.FindingKey{VulnerabilityID: "CVE-0000-0001", PkgName: "libfoo", Severity: "CRITICAL", Fixable: true},
				trivy.FindingKey{VulnerabilityID: "CVE-0000-0002", PkgName: "libfoo", Severity: "HIGH", Fixable: true},
				trivy.FindingKey{VulnerabilityID: "CVE-0000-0003", PkgName: "libbar", Severity: "HIGH", Fixable: false},
				trivy.FindingKey{VulnerabilityID: "CVE-0000-0004", PkgName: "libbar", Severity: "LOW", Fixable: false},
			),
			"example.lan/team/db:2": t6vuln(trivy.ImageIssueSeverity{Medium: 1}, 5,
				trivy.FindingKey{VulnerabilityID: "CVE-0000-0005", PkgName: "libdb", Severity: "MEDIUM", Fixable: true},
			),
		},
		Registry: map[string]*registries.RegistryImageReport{
			"example.lan/team/app:1": {
				Registry: "example.lan", Owner: "team", Repository: "app",
				Tag: "1", LatestTag: "1.1", LatestTagTimestamp: fixtureNow.Add(-10 * 24 * time.Hour),
			},
			"example.lan/team/db:2": {
				Registry: "example.lan", Owner: "team", Repository: "db",
				Tag: "2", LatestTag: "2", LatestTagTimestamp: fixtureNow.Add(-3 * 24 * time.Hour),
			},
		},
		RegistryFailures: 2,
		Start:            fixtureStart,
		Now:              fixtureNow,
		Cfg:              config.Config{},
	}
}

func TestBuildMetricsGolden(t *testing.T) {
	got := buildMetrics(t6input(t)).Payload()
	golden := filepath.Join("testdata", "metrics.golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("reading golden (run with -update to create): %v", err)
	}
	if got != string(want) {
		t.Errorf("payload differs from %s (run with -update after reviewing):\n--- got ---\n%s", golden, got)
	}
	// The payload must not depend on map iteration order.
	for i := 0; i < 20; i++ {
		if again := buildMetrics(t6input(t)).Payload(); again != got {
			t.Fatalf("payload is not deterministic on run %d", i)
		}
	}
}

// t6lines returns the sample lines (no HELP/TYPE) for one metric name.
func t6lines(payload, name string) []string {
	var out []string
	for _, l := range strings.Split(payload, "\n") {
		if strings.HasPrefix(l, name+"{") || strings.HasPrefix(l, name+" ") {
			out = append(out, l)
		}
	}
	return out
}

var t6sample = regexp.MustCompile(`^([a-z_]+)(\{(.*)\})? (\S+)$`)

// t6values maps the label part of every sample of name to its value.
func t6values(t *testing.T, payload, name string) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, l := range t6lines(payload, name) {
		m := t6sample.FindStringSubmatch(l)
		if m == nil {
			t.Fatalf("malformed sample line: %q", l)
		}
		v, err := strconv.ParseFloat(m[4], 64)
		if err != nil {
			t.Fatalf("bad value in %q: %v", l, err)
		}
		out[m[3]] = v
	}
	return out
}

func TestMetricsContract(t *testing.T) {
	p := buildMetrics(t6input(t)).Payload()

	if !strings.Contains(p, `image_repo="example.lan/team/db"`) {
		t.Errorf("image_repo must be registry/owner/repository with no tag or digest:\n%s", strings.Join(t6lines(p, "image_inquisitor_image_info"), "\n"))
	}
	for _, l := range t6lines(p, "image_inquisitor_image_info") {
		if strings.Contains(l, "sha256") {
			t.Errorf("image_info must not carry a digest: %s", l)
		}
	}

	failed := t6values(t, p, "image_inquisitor_scan_failed")
	wantFailed := map[string]float64{
		`image="example.lan/team/app:1"`:    0,
		`image="example.lan/team/broken:3"`: 1,
		`image="example.lan/team/db:2"`:     0,
	}
	if len(failed) != len(wantFailed) {
		t.Errorf("scan_failed: want %v, got %v", wantFailed, failed)
	}
	for k, v := range wantFailed {
		if got, ok := failed[k]; !ok || got != v {
			t.Errorf("scan_failed{%s}: want %v, got %v (present %v)", k, v, got, ok)
		}
	}

	sf := t6values(t, p, "image_inquisitor_scan_failures")
	wantSF := map[string]float64{
		`phase="parse"`: 2, `phase="list"`: 1, `phase="registry"`: 2, `phase="trivy"`: 1,
	}
	if len(t6lines(p, "image_inquisitor_scan_failures")) != 4 {
		t.Errorf("scan_failures must have exactly 4 phase lines, got %v", sf)
	}
	for k, v := range wantSF {
		if got, ok := sf[k]; !ok || got != v {
			t.Errorf("scan_failures{%s}: want %v, got %v (present %v)", k, v, got, ok)
		}
	}

	vulns := t6values(t, p, "image_inquisitor_vulnerabilities")
	fixable := t6values(t, p, "image_inquisitor_vulnerabilities_fixable")
	if len(fixable) != 10 {
		t.Errorf("want 5 fixable severities for each of 2 scanned images, got %d", len(fixable))
	}
	for k, v := range fixable {
		total, ok := vulns[k]
		if !ok {
			t.Errorf("fixable series {%s} has no matching vulnerabilities series", k)
			continue
		}
		if v > total {
			t.Errorf("fixable {%s} = %v exceeds vulnerabilities %v", k, v, total)
		}
	}

	if got := t6lines(p, "image_inquisitor_images_total"); len(got) != 1 || got[0] != "image_inquisitor_images_total 3" {
		t.Errorf("images_total: want 3, got %v", got)
	}

	invLines := t6lines(p, "image_inquisitor_inventory_failures")
	wantInv := []string{
		`image_inquisitor_inventory_failures{namespace="ns-a",phase="list"} 0`,
		`image_inquisitor_inventory_failures{namespace="ns-b",phase="list"} 1`,
		`image_inquisitor_inventory_failures{namespace="ns-a",phase="parse"} 1`,
		`image_inquisitor_inventory_failures{namespace="ns-b",phase="parse"} 0`,
		`image_inquisitor_inventory_failures{phase="parse"} 1`,
	}
	if strings.Join(invLines, "\n") != strings.Join(wantInv, "\n") {
		t.Errorf("inventory_failures:\nwant\n%s\ngot\n%s", strings.Join(wantInv, "\n"), strings.Join(invLines, "\n"))
	}

	for _, name := range reservedMetricNames {
		if strings.Contains(p, name) {
			t.Errorf("reserved metric %s must not be emitted yet", name)
		}
	}
}

func TestImageWorkloadDedupAndMerge(t *testing.T) {
	workloads := func(t *testing.T, inv *sources.ImageInventory) []string {
		t.Helper()
		p := buildMetrics(MetricsInput{Inventory: inv, Start: fixtureStart, Now: fixtureNow}).Payload()
		return t6lines(p, "image_inquisitor_image_workload")
	}

	t.Run("identical resources collapse to one series", func(t *testing.T) {
		inv := sources.NewImageInventory(&sources.ImageInventoryConfig{})
		in := func() map[string]*types.ImageSourceDetails {
			return map[string]*types.ImageSourceDetails{
				"example.lan/team/app:1": t6kube(
					t6res("Deployment", "ns-a", "app", "app"),
					t6res("Deployment", "ns-a", "app", "app"),
				),
			}
		}
		// Adding the same sourceID twice appends the resources again.
		if err := inv.AddImageSourceDetails("src", in()); err != nil {
			t.Fatal(err)
		}
		if err := inv.AddImageSourceDetails("src", in()); err != nil {
			t.Fatal(err)
		}
		// Another sourceID reporting the same workload is still one workload.
		if err := inv.AddImageSourceDetails("other", in()); err != nil {
			t.Fatal(err)
		}
		got := workloads(t, inv)
		want := `image_inquisitor_image_workload{container="app",image="example.lan/team/app:1",kind="Deployment",namespace="ns-a",workload="app"} 1`
		if len(got) != 1 || got[0] != want {
			t.Errorf("want exactly\n%s\ngot\n%s", want, strings.Join(got, "\n"))
		}
	})

	t.Run("distinct namespaces and containers stay distinct", func(t *testing.T) {
		inv := sources.NewImageInventory(&sources.ImageInventoryConfig{})
		if err := inv.AddImageSourceDetails("src", map[string]*types.ImageSourceDetails{
			"example.lan/team/app:1": t6kube(
				t6res("Deployment", "ns-a", "app", "app"),
				t6res("Deployment", "ns-a", "app", "sidecar"),
				t6res("Deployment", "ns-b", "app", "app"),
			),
		}); err != nil {
			t.Fatal(err)
		}
		if got := workloads(t, inv); len(got) != 3 {
			t.Errorf("want 3 series, got %d:\n%s", len(got), strings.Join(got, "\n"))
		}
	})

	t.Run("two spellings of one image keep both namespaces", func(t *testing.T) {
		inv := sources.NewImageInventory(&sources.ImageInventoryConfig{})
		if err := inv.AddImageSourceDetails("src", map[string]*types.ImageSourceDetails{
			"nginx:1.25":                   t6kube(t6res("Deployment", "ns-a", "web", "nginx")),
			"docker.io/library/nginx:1.25": t6kube(t6res("Deployment", "ns-b", "web", "nginx")),
		}); err != nil {
			t.Fatal(err)
		}
		got := strings.Join(workloads(t, inv), "\n")
		for _, ns := range []string{`namespace="ns-a"`, `namespace="ns-b"`} {
			if !strings.Contains(got, ns) {
				t.Errorf("missing %s in:\n%s", ns, got)
			}
		}
		if strings.Count(got, `image="docker.io/library/nginx:1.25"`) != 2 {
			t.Errorf("both series must use the fully qualified image name:\n%s", got)
		}
	})

	t.Run("non-kubernetes sources are skipped", func(t *testing.T) {
		inv := sources.NewImageInventory(&sources.ImageInventoryConfig{})
		if err := inv.AddImageSourceDetails("src", map[string]*types.ImageSourceDetails{
			"example.lan/team/app:1": {SourcesByType: map[types.ImageSourceType]interface{}{types.ImageSourceTypeFile: struct{}{}}},
		}); err != nil {
			t.Fatal(err)
		}
		if got := workloads(t, inv); len(got) != 0 {
			t.Errorf("want no workload series, got:\n%s", strings.Join(got, "\n"))
		}
	})
}

func TestTrivyFailures(t *testing.T) {
	in := t6input(t)
	if got := trivyFailures(in); got != 1 {
		t.Errorf("want 1 (broken:3 has no report), got %d", got)
	}
	in.Vuln = nil
	if got := trivyFailures(in); got != 3 {
		t.Errorf("want 3 with no reports, got %d", got)
	}
}
