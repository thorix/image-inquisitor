package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var testNS = []string{"ns-a", "ns-b"}

func newTestK(cs *fakeCS) *Kubernetes {
	k := NewKubernetesWithClient(&KubernetesConfig{}, cs)
	k.Backoff = time.Millisecond
	return k
}

func TestTransientListErrorIsRetried(t *testing.T) {
	cs := newFakeCS(testNS, func(kind, ns string, attempt int) error {
		if kind == "cronjobs" && ns == "ns-a" && attempt == 1 {
			return errors.New("transient")
		}
		return nil
	})
	report, stats, err := newTestK(cs).GetReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := report["example.lan/cron/job:1"]; !ok {
		t.Fatalf("cronjob image missing: %v", report)
	}
	if stats.Total() != 0 {
		t.Fatalf("Total = %d, want 0", stats.Total())
	}
}

func TestForbiddenNamespaceIsCountedOthersKept(t *testing.T) {
	cs := newFakeCS(testNS, func(kind, ns string, attempt int) error {
		if kind == "pods" && ns == "ns-b" {
			return apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("no"))
		}
		return nil
	})
	report, stats, err := newTestK(cs).GetReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, img := range []string{"example.lan/ns-a/app:1", "example.lan/ns-b/app:1"} {
		if _, ok := report[img]; !ok {
			t.Errorf("%s missing", img)
		}
	}
	if stats.FailedLists["ns-b"] != 1 || stats.FailedLists["ns-a"] != 0 {
		t.Fatalf("FailedLists = %v", stats.FailedLists)
	}
	if cs.attempts["pods/ns-b"] != 1 {
		t.Errorf("forbidden was retried: %d attempts", cs.attempts["pods/ns-b"])
	}
}

func TestAllListsFailedIsError(t *testing.T) {
	cs := newFakeCS(testNS, func(kind, ns string, attempt int) error {
		if kind == "namespaces" {
			return nil
		}
		return errors.New("down")
	})
	_, stats, err := newTestK(cs).GetReport(context.Background())
	if !errors.Is(err, ErrAllListsFailed) {
		t.Fatalf("err = %v, want ErrAllListsFailed", err)
	}
	if stats.Total() != 12 {
		t.Fatalf("Total = %d, want 12", stats.Total())
	}
}

func TestNamespaceListFailureIsError(t *testing.T) {
	cs := newFakeCS(testNS, func(kind, ns string, attempt int) error {
		if kind == "namespaces" {
			return errors.New("down")
		}
		return nil
	})
	if _, _, err := newTestK(cs).GetReport(context.Background()); err == nil {
		t.Fatal("want error")
	}
}

func TestNothingHangs(t *testing.T) {
	cs := newFakeCS(testNS, func(kind, ns string, attempt int) error {
		if kind == "deployments" && ns == "ns-a" {
			return errBlock
		}
		return nil
	})
	k := newTestK(cs)
	k.CallTimeout = 50 * time.Millisecond
	type result struct {
		stats *ListStats
		err   error
	}
	done := make(chan result, 1)
	go func() {
		_, s, err := k.GetReport(context.Background())
		done <- result{s, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.stats.FailedLists["ns-a"] != 1 {
			t.Fatalf("FailedLists = %v", r.stats.FailedLists)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("GetReport hung")
	}
}

// TestEarlyListFailuresDoNotRaceNamespaceSetup has every List fail at once in
// many namespaces, so early namespaces record failures while later ones are
// still being set up. Run with -race.
func TestEarlyListFailuresDoNotRaceNamespaceSetup(t *testing.T) {
	out := log.StandardLogger().Out
	log.SetOutput(io.Discard)
	defer log.SetOutput(out)

	var names []string
	for i := 0; i < 200; i++ {
		names = append(names, fmt.Sprintf("ns-%03d", i))
	}
	cs := newFakeCS(names, func(kind, ns string, attempt int) error {
		if kind == "namespaces" {
			return nil
		}
		return apierrors.NewForbidden(schema.GroupResource{Resource: kind}, "", errors.New("no"))
	})
	_, stats, err := newTestK(cs).GetReport(context.Background())
	if !errors.Is(err, ErrAllListsFailed) {
		t.Fatalf("err = %v, want ErrAllListsFailed", err)
	}
	if len(stats.Namespaces) != len(names) || len(stats.FailedLists) != len(names) {
		t.Fatalf("got %d namespaces, %d FailedLists entries, want %d",
			len(stats.Namespaces), len(stats.FailedLists), len(names))
	}
	for _, ns := range names {
		if stats.FailedLists[ns] != listKindsPerNamespace {
			t.Fatalf("FailedLists[%s] = %d, want %d", ns, stats.FailedLists[ns], listKindsPerNamespace)
		}
	}
}
