package trivy

import (
	"time"

	log "github.com/sirupsen/logrus"
)

type TrivyReport map[string]*TrivyImageReport

type TrivyImageReport struct {
	ImageCreated time.Time `json:"imageCreated"`
	// Age of the image in whole days at report time. Derived from ImageCreated,
	// but emitted as a number because consumers cannot threshold or sort on a
	// timestamp: Grafana compares thresholds against absolute values, so
	// colouring "older than N days" from a date would need a hardcoded cutoff
	// that goes stale. A plain integer is directly sortable and colourable.
	AgeDays     int          `json:"ageDays"`
	ImageIssues *ImageIssues `json:"imageIssues"`
}

type ImageIssues struct {
	Total             *ImageIssueSeverity          `json:"total"`
	Misconfigurations *ImageIssueMisconfigurations `json:"misconfigurations"`
	Vulnerabilities   *ImageIssueVulnerabilities   `json:"vulnerabilities"`
	Secrets           *ImageIssueSecrets           `json:"secrets"`
}

type ImageIssueMisconfigurations struct {
	ImageIssueSeverity
}

type ImageIssueVulnerabilities struct {
	ImageIssueSeverity
	Vulnerabilities []*ImageIssueVulnerability `json:"vulnerabilities"`
}

type ImageIssueVulnerability struct {
	VulnerabilityID string     `json:"registry"`
	Severity        string     `json:"severity"`
	PkgID           string     `json:"pkgID"`
	PrimaryURL      string     `json:"primaryURL"`
	Title           string     `json:"title"`
	Description     string     `json:"description"`
	NvdV3Score      float64    `json:"nvdV3Score"`
	PublishedDate   *time.Time `json:"publishedDate"`
}

type ImageIssueSecrets struct {
	ImageIssueSeverity
}

type IssueWithSeverity interface {
	AddSeverityUnknown()
	AddSeverityLow()
	AddSeverityMedium()
	AddSeverityHigh()
	AddSeverityCritical()
}

type ImageIssueSeverity struct {
	Unknown  int `json:"unknown"`
	Low      int `json:"low"`
	Medium   int `json:"medium"`
	High     int `json:"high"`
	Critical int `json:"critical"`
}

func (iis *ImageIssueSeverity) AddSeverity(severity string) {
	switch severity {
	case "LOW":
		iis.Low++
	case "MEDIUM":
		iis.Medium++
	case "HIGH":
		iis.High++
	case "CRITICAL":
		iis.Critical++
	default:
		iis.Unknown++
	}
}

func formatReport(runResults RunResults) TrivyReport {
	trivyReport := make(TrivyReport)
	for _, r := range runResults {
		if r.Err != nil {
			log.Errorf("%v; %s", r.Err, r.Output)
			continue
		}
		if r.Report != nil {
			issues := &ImageIssues{
				Misconfigurations: &ImageIssueMisconfigurations{},
				Vulnerabilities:   &ImageIssueVulnerabilities{},
				Secrets:           &ImageIssueSecrets{},
				Total:             &ImageIssueSeverity{},
			}

			for _, vulnResults := range r.Report.Results {
				for _, misconfiguration := range vulnResults.Misconfigurations {
					issues.Misconfigurations.AddSeverity(misconfiguration.Severity)
					issues.Total.AddSeverity(misconfiguration.Severity)
				}
				for _, vulnerability := range vulnResults.Vulnerabilities {
					issues.Vulnerabilities.AddSeverity(vulnerability.Severity)
					nvdScore := float64(0)
					if nvd, ok := vulnerability.CVSS["nvd"]; ok {
						nvdScore = nvd.V3Score
					}
					issues.Vulnerabilities.Vulnerabilities = append(issues.Vulnerabilities.Vulnerabilities, &ImageIssueVulnerability{
						VulnerabilityID: vulnerability.VulnerabilityID,
						Severity:        vulnerability.Severity,
						PkgID:           vulnerability.PkgID,
						PrimaryURL:      vulnerability.PrimaryURL,
						Title:           vulnerability.Title,
						Description:     vulnerability.Description,
						NvdV3Score:      nvdScore,
						PublishedDate:   vulnerability.PublishedDate,
					})
					issues.Total.AddSeverity(vulnerability.Severity)
				}
				for _, secret := range vulnResults.Secrets {
					issues.Secrets.AddSeverity(secret.Severity)
					issues.Total.AddSeverity(secret.Severity)
				}
			}

			created := r.Report.Metadata.ImageConfig.Created.Time
			ageDays := 0
			// A zero timestamp means the image config carried no created date;
			// reporting that as an age of ~20000 days would be worse than 0.
			if !created.IsZero() {
				ageDays = int(time.Since(created).Hours() / 24)
			}

			trivyReport[r.Image] = &TrivyImageReport{
				ImageCreated: created,
				AgeDays:      ageDays,
				ImageIssues:  issues,
			}
		}
	}

	return trivyReport
}
