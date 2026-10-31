package sources

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/bartlettc22/image-inquisitor/internal/kubernetes"
	"github.com/bartlettc22/image-inquisitor/internal/sources/types"
)

func kube(ns, name, container string) *types.ImageSourceDetails {
	return &types.ImageSourceDetails{
		SourcesByType: map[types.ImageSourceType]interface{}{
			types.ImageSourceTypeKubernetes: &kubernetes.KubernetesImageReport{
				Resources: []*kubernetes.KubernetesResource{
					{Kind: "Deployment", Namespace: ns, Name: name, Container: container},
				},
			},
		},
	}
}

func fileShape() *types.ImageSourceDetails {
	return &types.ImageSourceDetails{
		SourcesByType: map[types.ImageSourceType]interface{}{
			types.ImageSourceTypeFile: struct{}{},
		},
	}
}

func resourcesOf(t *testing.T, d *types.ImageSourceDetails) []*kubernetes.KubernetesResource {
	t.Helper()
	r, ok := d.SourcesByType[types.ImageSourceTypeKubernetes].(*kubernetes.KubernetesImageReport)
	if !ok {
		t.Fatalf("no kubernetes report in %+v", d)
	}
	return r.Resources
}

func TestDuplicateSpellingsMergeResources(t *testing.T) {
	for i := 0; i < 50; i++ {
		inv := NewImageInventory(&ImageInventoryConfig{})
		in := map[string]*types.ImageSourceDetails{
			"nginx:1.25":                   kube("a", "web", "nginx"),
			"docker.io/library/nginx:1.25": kube("b", "web", "nginx"),
		}
		for n := 0; n < 8; n++ {
			in[fmt.Sprintf("example.lan/team/app%d:1", n)] = kube("a", "app", "app")
		}
		if err := inv.AddImageSourceDetails("src", in); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(inv.ImageDetails) != 9 {
			t.Fatalf("iteration %d: want 9 images, got %d", i, len(inv.ImageDetails))
		}
		d := inv.ImageDetails["docker.io/library/nginx:1.25"]
		if d == nil {
			t.Fatal("nginx entry missing")
		}
		res := resourcesOf(t, d.ImageSourceDetailsByID["src"])
		ns := map[string]bool{}
		for _, r := range res {
			ns[r.Namespace] = true
		}
		if len(res) != 2 || !ns["a"] || !ns["b"] {
			t.Fatalf("iteration %d: want resources from namespaces a and b, got %+v", i, res)
		}
	}
}

func TestTagAndTagDigestMerge(t *testing.T) {
	inv := NewImageInventory(&ImageInventoryConfig{})
	in := map[string]*types.ImageSourceDetails{
		"example.lan/team/app:1.0":                                   kube("a", "x", "c"),
		"example.lan/team/app:1.0@sha256:" + strings.Repeat("a", 64): kube("b", "y", "c"),
	}
	if err := inv.AddImageSourceDetails("src", in); err != nil {
		t.Fatal(err)
	}
	if len(inv.ImageDetails) != 1 {
		t.Fatalf("want 1 image, got %d", len(inv.ImageDetails))
	}
	d := inv.ImageDetails["example.lan/team/app:1.0"]
	if d == nil {
		t.Fatal("merged key missing")
	}
	if n := len(resourcesOf(t, d.ImageSourceDetailsByID["src"])); n != 2 {
		t.Fatalf("want 2 resources, got %d", n)
	}
}

func TestExcludedRegistrySkippedNoPanic(t *testing.T) {
	inv := NewImageInventory(&ImageInventoryConfig{
		ExcludeRegistries: map[string]struct{}{"excluded.example.lan": {}},
	})
	in := map[string]*types.ImageSourceDetails{
		"excluded.example.lan/x/y:1": kube("a", "x", "c"),
		"example.lan/x/y:1":          kube("a", "y", "c"),
	}
	if err := inv.AddImageSourceDetails("src", in); err != nil {
		t.Fatal(err)
	}
	if len(inv.ImageDetails) != 1 {
		t.Fatalf("want 1 image, got %d", len(inv.ImageDetails))
	}
	if _, ok := inv.ImageDetails["example.lan/x/y:1"]; !ok {
		t.Fatal("kept image missing")
	}
}

func TestBadRefDropsOnlyItself(t *testing.T) {
	inv := NewImageInventory(&ImageInventoryConfig{})
	bad := kube("ns-x", "d1", "c")
	r := resourcesOf(t, bad)
	r = append(r,
		&kubernetes.KubernetesResource{Kind: "Deployment", Namespace: "ns-x", Name: "d2", Container: "c"},
		&kubernetes.KubernetesResource{Kind: "Deployment", Namespace: "ns-y", Name: "d3", Container: "c"},
	)
	bad.SourcesByType[types.ImageSourceTypeKubernetes] = &kubernetes.KubernetesImageReport{Resources: r}
	in := map[string]*types.ImageSourceDetails{
		"example.lan/a/b:1":    kube("a", "x", "c"),
		"bad/three/segments:1": bad,
		"example.lan/c/d:1":    kube("a", "y", "c"),
	}
	err := inv.AddImageSourceDetails("src", in)
	if err == nil || !strings.Contains(err.Error(), "bad/three/segments:1") {
		t.Fatalf("want error naming the bad ref, got %v", err)
	}
	if len(inv.ImageDetails) != 2 {
		t.Fatalf("want 2 images, got %d", len(inv.ImageDetails))
	}
	if inv.Stats.ParseFailures != 1 {
		t.Fatalf("want 1 parse failure, got %d", inv.Stats.ParseFailures)
	}
	want := map[string]int{"ns-x": 1, "ns-y": 1}
	if !reflect.DeepEqual(inv.Stats.ParseFailuresByNamespace, want) {
		t.Fatalf("want %v, got %v", want, inv.Stats.ParseFailuresByNamespace)
	}
}

func TestBadRefWithoutNamespaceIsUnknown(t *testing.T) {
	inv := NewImageInventory(&ImageInventoryConfig{})
	err := inv.AddImageSourceDetails("src", map[string]*types.ImageSourceDetails{
		"bad/three/segments:1": fileShape(),
	})
	if err == nil {
		t.Fatal("want error")
	}
	want := map[string]int{"": 1}
	if !reflect.DeepEqual(inv.Stats.ParseFailuresByNamespace, want) {
		t.Fatalf("want %v, got %v", want, inv.Stats.ParseFailuresByNamespace)
	}
}
