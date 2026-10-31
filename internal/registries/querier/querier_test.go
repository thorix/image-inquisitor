package querier

import (
	"strings"
	"testing"

	"github.com/bartlettc22/image-inquisitor/internal/imageUtils"
	"github.com/bartlettc22/image-inquisitor/internal/registries"
)

type panicky struct{}

func (panicky) IsRegistry(string) bool { return true }
func (panicky) FetchReport(*imageUtils.Image) (*registries.RegistryImageReport, error) {
	panic("boom")
}

func TestPanicBecomesError(t *testing.T) {
	rq := &RegistryQuerier{registries: []Registry{panicky{}}}
	report, err := rq.FetchReport(&imageUtils.Image{Image: "example.lan/a/b:1", Registry: "example.lan"})
	if report != nil {
		t.Fatalf("expected nil report, got %v", report)
	}
	if err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("expected panicked error, got %v", err)
	}
}
