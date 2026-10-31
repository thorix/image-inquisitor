package trivy

import (
	"encoding/json"
	"strings"
	"testing"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
)

func t3FindingsFixture() RunResults {
	return RunResults{
		"img": &ScanResult{
			Image: "img",
			Report: &trivyTypes.Report{
				Results: trivyTypes.Results{{
					Vulnerabilities: []trivyTypes.DetectedVulnerability{
						{VulnerabilityID: "CVE-1", PkgName: "a", FixedVersion: "1.2", Vulnerability: dbTypes.Vulnerability{Severity: "CRITICAL"}},
						{VulnerabilityID: "CVE-2", PkgName: "b", Vulnerability: dbTypes.Vulnerability{Severity: "CRITICAL"}},
						{VulnerabilityID: "CVE-3", PkgName: "c", FixedVersion: "2.0", Vulnerability: dbTypes.Vulnerability{Severity: "HIGH"}},
					},
					Misconfigurations: []trivyTypes.DetectedMisconfiguration{{Severity: "CRITICAL"}},
					Secrets:           []trivyTypes.DetectedSecret{{Severity: "HIGH"}},
				}},
			},
		},
	}
}

func TestFindingsMatchVulnerabilityCounts(t *testing.T) {
	r := formatReport(t3FindingsFixture(), true)["img"]
	if len(r.Findings) != 3 {
		t.Fatalf("len(Findings) = %d, want 3", len(r.Findings))
	}
	var got ImageIssueSeverity
	for _, f := range r.Findings {
		got.AddSeverity(f.Severity)
	}
	if got != r.ImageIssues.Vulnerabilities.ImageIssueSeverity {
		t.Errorf("findings counts %+v != vulnerability counts %+v", got, r.ImageIssues.Vulnerabilities.ImageIssueSeverity)
	}
	if got.Critical != 2 || got.High != 1 {
		t.Errorf("counts = %+v, want critical 2 high 1", got)
	}
	fx := r.FixableCounts()
	if fx.Critical != 1 || fx.High != 1 {
		t.Errorf("FixableCounts = %+v, want critical 1 high 1", fx)
	}
	tot := r.ImageIssues.Total
	if fx.Critical > tot.Critical || fx.High > tot.High || fx.Medium > tot.Medium || fx.Low > tot.Low || fx.Unknown > tot.Unknown {
		t.Errorf("fixable %+v exceeds total %+v", fx, *tot)
	}
}

func TestFindingsNotSerialised(t *testing.T) {
	r := formatReport(t3FindingsFixture(), true)["img"]
	with, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"Findings", "findings", "FixedVersion"} {
		if strings.Contains(string(with), s) {
			t.Errorf("serialised report contains %q", s)
		}
	}
	r.Findings = nil
	without, _ := json.Marshal(r)
	if string(with) != string(without) {
		t.Error("marshal differs when Findings is nil")
	}
}

func TestVulnerabilityIDJSONTag(t *testing.T) {
	b, err := json.Marshal(ImageIssueVulnerability{VulnerabilityID: "CVE-9"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"vulnerabilityID":"CVE-9"`) {
		t.Errorf("got %s", b)
	}
	var back ImageIssueVulnerability
	if err := json.Unmarshal(b, &back); err != nil || back.VulnerabilityID != "CVE-9" {
		t.Errorf("round trip: %v %+v", err, back)
	}
}
