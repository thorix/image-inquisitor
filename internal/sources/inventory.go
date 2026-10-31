package sources

import (
	"context"
	"errors"
	"fmt"

	"github.com/bartlettc22/image-inquisitor/internal/imageUtils"
	"github.com/bartlettc22/image-inquisitor/internal/kubernetes"
	exportsources "github.com/bartlettc22/image-inquisitor/internal/sources/export"
	"github.com/bartlettc22/image-inquisitor/internal/sources/types"
	log "github.com/sirupsen/logrus"
)

// ImageInventory represents a full list of images to be evaulated along
// with the full details for the images
type ImageInventory struct {
	*ImageInventoryConfig

	// ImageDetails contains all of the details we have on the image
	// Map key is the image's fully qualified name
	ImageDetails map[string]*ImageDetails `json:"images" yaml:"images"`

	// Stats counts inventory-building failures for later reporting
	Stats *InventoryStats `json:"-" yaml:"-"`
}

// InventoryStats counts failures seen while building the inventory.
type InventoryStats struct {
	// ParseFailures is the number of unparseable image references
	ParseFailures int
	// ParseFailuresByNamespace counts unparseable references per kubernetes
	// namespace; key "" means the namespace is unknown
	ParseFailuresByNamespace map[string]int
	// ListFailures is the number of failed kubernetes list calls
	ListFailures int
	// NamespaceListFailures counts failed list calls per namespace
	NamespaceListFailures map[string]int
}

type ImageInventoryConfig struct {
	ExcludeRegistries map[string]struct{}
}

// ImageDetails contains all of the details we have on a particular image
type ImageDetails struct {

	// ImageComponents are the components of the image (registry, tag, etc.)
	ImageComponents *imageUtils.Image `json:"components" yaml:"components"`

	// ImageSourceDetailsByID contains the source(s) details
	// Key is the sourceID
	ImageSourceDetailsByID map[string]*types.ImageSourceDetails `json:"sourceDetails" yaml:"sourceDetails"`

	// RegistryDetails {
	// 	CurrentTagTimestamp
	// 	LatestTag
	// 	LatestTagTimestamp
	// }

	// ImageIssues {
	// 	"Vulnerabilities" {
	// 		Source: "Trivy"
	// 		Vulns: []{
	// 			x
	// 		}
	// 	}
	// }
}

func NewImageInventory(config *ImageInventoryConfig) *ImageInventory {
	return &ImageInventory{
		ImageInventoryConfig: config,
		ImageDetails:         make(map[string]*ImageDetails),
		Stats: &InventoryStats{
			ParseFailuresByNamespace: make(map[string]int),
			NamespaceListFailures:    make(map[string]int),
		},
	}
}

func (inv *ImageInventory) qualifyImage(imageName string) (string, error) {
	// To ensure all image names are fully qualified, we'll parse each one
	// to the standard format
	parsedImage, err := imageUtils.ParseImage(imageName)
	if err != nil {
		return "", err
	}

	fullyQualifiedName := parsedImage.FullyQualifiedName(false)

	// Skip if part of the excluded registries list
	if _, ok := inv.ExcludeRegistries[parsedImage.Registry]; ok {
		return "", nil
	}

	if _, ok := inv.ImageDetails[fullyQualifiedName]; !ok {
		inv.ImageDetails[fullyQualifiedName] = &ImageDetails{
			ImageComponents:        parsedImage,
			ImageSourceDetailsByID: make(map[string]*types.ImageSourceDetails),
		}
	}

	return fullyQualifiedName, nil
}

// AddImageSourceDetails merges the per-image details of one source into the
// inventory. It never stops early: an unparseable reference drops only itself.
// The returned error joins every per-image parse error.
func (inv ImageInventory) AddImageSourceDetails(sourceID string, details map[string]*types.ImageSourceDetails) error {
	var errs []error
	for imageName, imageSourceDetails := range details {
		fullyQualifiedName, err := inv.qualifyImage(imageName)
		if err != nil {
			log.WithField("image", imageName).Warnf("skipping unparseable image reference: %v", err)
			inv.recordParseFailure(imageSourceDetails)
			errs = append(errs, fmt.Errorf("%s: %w", imageName, err))
			continue
		}
		if fullyQualifiedName == "" {
			continue
		}

		byID := inv.ImageDetails[fullyQualifiedName].ImageSourceDetailsByID
		current, ok := byID[sourceID]
		if !ok || current == nil {
			byID[sourceID] = imageSourceDetails
			continue
		}
		if imageSourceDetails == nil {
			continue
		}
		if current.SourcesByType == nil {
			current.SourcesByType = make(map[types.ImageSourceType]interface{})
		}
		for sourceType, incoming := range imageSourceDetails.SourcesByType {
			existing, exists := current.SourcesByType[sourceType]
			if !exists {
				current.SourcesByType[sourceType] = incoming
				continue
			}
			existingReport, ok1 := existing.(*kubernetes.KubernetesImageReport)
			incomingReport, ok2 := incoming.(*kubernetes.KubernetesImageReport)
			if ok1 && ok2 && existingReport != nil && incomingReport != nil {
				merged := &kubernetes.KubernetesImageReport{
					Resources: make([]*kubernetes.KubernetesResource, 0, len(existingReport.Resources)+len(incomingReport.Resources)),
				}
				merged.Resources = append(merged.Resources, existingReport.Resources...)
				merged.Resources = append(merged.Resources, incomingReport.Resources...)
				current.SourcesByType[sourceType] = merged
				continue
			}
			log.Warnf("attempting to merge two inventory lists with the same sourceID and type; image: %s, sourceID: %s, sourceType: %s", fullyQualifiedName, sourceID, sourceType)
		}
	}

	return errors.Join(errs...)
}

// recordParseFailure counts one unparseable reference, overall and once per
// distinct kubernetes namespace it was seen in ("" when no namespace is known).
func (inv ImageInventory) recordParseFailure(d *types.ImageSourceDetails) {
	inv.Stats.ParseFailures++
	namespaces := map[string]struct{}{}
	if d != nil {
		for _, v := range d.SourcesByType {
			if report, ok := v.(*kubernetes.KubernetesImageReport); ok && report != nil {
				for _, r := range report.Resources {
					if r != nil {
						namespaces[r.Namespace] = struct{}{}
					}
				}
			}
		}
	}
	if len(namespaces) == 0 {
		namespaces[""] = struct{}{}
	}
	for ns := range namespaces {
		inv.Stats.ParseFailuresByNamespace[ns]++
	}
}

func (inv ImageInventory) ImageComponents() imageUtils.ImagesList {
	results := make(imageUtils.ImagesList)
	for image, details := range inv.ImageDetails {
		results[image] = details.ImageComponents
	}
	return results
}

func (inv ImageInventory) Export(ctx context.Context, exporterConfig *exportsources.ExporterConfig) error {
	exporter := exportsources.NewExporter(exporterConfig)
	for fullyQualifiedImageName, imageDetails := range inv.ImageDetails {
		for sourceID, imageSourceDetails := range imageDetails.ImageSourceDetailsByID {
			// Only export if we match our primary source ID
			if sourceID == exporterConfig.SourceID {
				exporter.AddImageSourceDetails(fullyQualifiedImageName, imageSourceDetails.SourcesByType)
			}
		}
	}

	return exporter.Export(ctx)
}

// ImagesAsSlice returns a slice of fully qualified image names
func (inv ImageInventory) ImagesAsSlice() []string {
	result := []string{}
	for imageName := range inv.ImageDetails {
		result = append(result, imageName)
	}
	return result
}
