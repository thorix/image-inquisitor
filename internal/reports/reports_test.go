package reports

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type failingWriter struct{ calls int }

func (w *failingWriter) Write([]byte) (int, error) {
	w.calls++
	return 0, errors.New("broken pipe")
}

func withStdout(t *testing.T, w io.Writer) {
	t.Helper()
	old := stdout
	stdout = w
	t.Cleanup(func() { stdout = old })
}

func TestImageOutputReturnsWriteError(t *testing.T) {
	fw := &failingWriter{}
	withStdout(t, fw)
	rl := NewImageReportList(time.Unix(0, 0))
	rl.AddImageReport(ReportTypeImageRegistry, "example.lan/team/app:1", map[string]string{"a": "b"})
	rl.AddImageReport(ReportTypeImageRegistry, "example.lan/team/db:2", map[string]string{"a": "b"})
	err := rl.Output()
	if err == nil || !strings.Contains(err.Error(), "broken pipe") {
		t.Fatalf("want the write error, got %v", err)
	}
	if fw.calls != 2 {
		t.Errorf("a failed write must not stop the remaining reports: %d writes", fw.calls)
	}
}

func TestSummaryOutputReturnsWriteError(t *testing.T) {
	withStdout(t, &failingWriter{})
	rl := NewSummaryReportList(time.Unix(0, 0))
	rl.Add(ReportTypeSummary, &summaryReport{ImageCount: 1})
	if err := rl.Output(); err == nil || !strings.Contains(err.Error(), "broken pipe") {
		t.Fatalf("want the write error, got %v", err)
	}
}

func TestOutputWritesOneLinePerReport(t *testing.T) {
	var buf bytes.Buffer
	withStdout(t, &buf)
	rl := NewImageReportList(time.Unix(0, 0))
	rl.AddImageReport(ReportTypeImageRegistry, "example.lan/team/app:1", map[string]string{"a": "b"})
	if err := rl.Output(); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); strings.Count(got, "\n") != 1 || !strings.Contains(got, `"image":"example.lan/team/app:1"`) {
		t.Errorf("unexpected output: %q", got)
	}
}

func TestOutputReturnsMarshalError(t *testing.T) {
	var buf bytes.Buffer
	withStdout(t, &buf)
	rl := NewImageReportList(time.Unix(0, 0))
	rl.AddImageReport(ReportTypeImageRegistry, "example.lan/team/app:1", make(chan int))
	if err := rl.Output(); err == nil {
		t.Fatal("a report that cannot be serialised was not written; Output must say so")
	}
}
