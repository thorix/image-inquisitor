package reports

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

// stdout is where every report line is written. A variable so tests can
// inject a failing writer.
var stdout io.Writer = os.Stdout

type imageReportList struct {
	reportGenerated time.Time
	reportSets      map[ReportType]imageReportSet
}

type imageReportSet map[string]*imageReport

type imageReport struct {
	ReportGenerated time.Time   `json:"reportGenerated"`
	ReportType      ReportType  `json:"reportType"`
	Image           string      `json:"image"`
	Contents        interface{} `json:"report"`
}

func NewImageReportList(reportGenerated time.Time) *imageReportList {
	return &imageReportList{
		reportGenerated: reportGenerated,
		reportSets:      make(map[ReportType]imageReportSet),
	}
}

// Output writes every report, one JSON line each. It keeps going after a
// failure so one bad report does not cost the rest, and returns the first
// error: a report that was not written must not look like a clean run.
func (rl *imageReportList) Output() error {
	var first error
	for _, i := range rl.reportSets {
		for _, report := range i {
			if err := report.output(); err != nil && first == nil {
				first = err
			}
		}
	}
	return first
}

func (rl *imageReportList) AddImageReport(reportType ReportType, image string, reportContents interface{}) {
	if _, ok := rl.reportSets[reportType]; !ok {
		rl.reportSets[reportType] = make(imageReportSet)
	}
	rl.reportSets[reportType][image] = &imageReport{
		ReportGenerated: rl.reportGenerated,
		ReportType:      reportType,
		Image:           image,
		Contents:        reportContents,
	}
}

func (r *imageReport) output() error {
	return writeJSONLine(r.ReportType, r)
}

// writeJSONLine marshals v and writes it to stdout as one line.
func writeJSONLine(reportType ReportType, v interface{}) error {
	reportOut, err := json.Marshal(v)
	if err != nil {
		log.Errorf("error converting '%s' report to JSON; err: %v, out: %v", reportType, err, v)
		return fmt.Errorf("converting %s report to JSON: %w", reportType, err)
	}
	if _, err := fmt.Fprintln(stdout, string(reportOut)); err != nil {
		return fmt.Errorf("writing %s report: %w", reportType, err)
	}
	return nil
}
