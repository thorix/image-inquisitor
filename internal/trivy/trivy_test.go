package trivy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// t2InstallFakeTrivy writes a fake trivy script and prepends it to PATH.
func t2InstallFakeTrivy(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
out=""
has_timeout=0
prev=""
last=""
for a in "$@"; do
  if [ "$prev" = "--output" ]; then out="$a"; fi
  if [ "$a" = "--timeout" ]; then has_timeout=1; fi
  prev2="$prev"
  prev="$a"
  last="$a"
done
# argument before the image must be --
n=$#
i=0
before=""
for a in "$@"; do
  i=$((i+1))
  if [ $i -eq $((n-1)) ]; then before="$a"; fi
done
if [ "$before" != "--" ] || [ $has_timeout -ne 1 ]; then exit 2; fi
case "$last" in
  example.lan/fail:1) exit 1 ;;
  example.lan/slow:1) exec sleep 30 ;;
  example.lan/badjson:1) echo "not json" > "$out" ;;
  *) printf '{"SchemaVersion":2,"ArtifactName":"%s","Results":[]}' "$last" > "$out" ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "trivy"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestFailuresAreCountedAndIsolated(t *testing.T) {
	t2InstallFakeTrivy(t)
	tr := NewTrivyRunner(TrivyRunnerConfig{
		Images:      []string{"example.lan/ok:1", "example.lan/fail:1", "example.lan/slow:1", "example.lan/badjson:1"},
		NumWorkers:  2,
		OutputDir:   t.TempDir(),
		ScanTimeout: 1 * time.Second,
	})
	start := time.Now()
	report, failures := tr.RunContext(context.Background())
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("took too long: %v", elapsed)
	}
	if len(report) != 1 {
		t.Fatalf("report has %d entries, want 1: %v", len(report), report)
	}
	if _, ok := report["example.lan/ok:1"]; !ok {
		t.Fatalf("report missing ok image: %v", report)
	}
	if len(failures) != 3 {
		t.Fatalf("got %d failures, want 3: %v", len(failures), failures)
	}
	for _, img := range []string{"example.lan/fail:1", "example.lan/slow:1", "example.lan/badjson:1"} {
		if failures[img] == nil {
			t.Errorf("missing failure for %s", img)
		}
	}
}

func TestOutputFilesDoNotCollide(t *testing.T) {
	t2InstallFakeTrivy(t)
	out := t.TempDir()
	images := []string{"example.lan/a_b/c:1", "example.lan/a/b_c:1"}
	tr := NewTrivyRunner(TrivyRunnerConfig{Images: images, NumWorkers: 2, OutputDir: out})
	results := tr.runScans(context.Background())
	for _, img := range images {
		r := results[img]
		if r == nil || r.Err != nil || r.Report == nil {
			t.Fatalf("bad result for %s: %+v", img, r)
		}
		if r.Report.ArtifactName != img {
			t.Errorf("ArtifactName %q, want %q", r.Report.ArtifactName, img)
		}
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("output dir not empty: %d entries", len(entries))
	}
}
