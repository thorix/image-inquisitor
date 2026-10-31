package sources

import (
	"context"
	"fmt"

	importsources "github.com/bartlettc22/image-inquisitor/internal/sources/import"
	"github.com/bartlettc22/image-inquisitor/internal/sources/types"
	log "github.com/sirupsen/logrus"
)

type ImageSourcesConfig struct {
	SourceID               string
	ImageSourceTypes       []types.ImageSourceType
	KubernetesSourceConfig *KubernetesSourceConfig
	FileSourceConfig       *FileSourceConfig
	ImportSourcesConfig    *importsources.ImportSourcesConfig
	ExcludeImageRegistries map[string]struct{}
}

func GetInventoryFromSources(ctx context.Context, config *ImageSourcesConfig) (*ImageInventory, error) {

	inventory := NewImageInventory(&ImageInventoryConfig{
		ExcludeRegistries: config.ExcludeImageRegistries,
	})

	// Collect primary source information before we do the import import.
	// We do this in case the same primary sourceID exists in data we try to import
	// as we will keep the first sourceID info (more update-to-date)
	for _, sourceType := range config.ImageSourceTypes {
		switch sourceType {
		case types.ImageSourceTypeKubernetes:
			kubernetesSource := NewKubernetesSource(config.KubernetesSourceConfig)
			kubernetesSourceReport, err := kubernetesSource.GetReport(ctx)
			if err != nil {
				return nil, err
			}
			if err := inventory.AddImageSourceDetails(config.SourceID, kubernetesSourceReport); err != nil {
				log.Warnf("some %s images could not be parsed: %v", sourceType, err)
			}
		case types.ImageSourceTypeFile:
			fileSource := NewFileSource(config.FileSourceConfig)
			fileSourceReport, err := fileSource.GetReport(ctx)
			if err != nil {
				return nil, err
			}
			if err := inventory.AddImageSourceDetails(config.SourceID, fileSourceReport); err != nil {
				log.Warnf("some %s images could not be parsed: %v", sourceType, err)
			}
		default:
			return nil, fmt.Errorf("image source unknown")
		}
	}

	if config.ImportSourcesConfig != nil {
		importedInventory, err := importsources.ImportSourcesInventory(ctx, config.ImportSourcesConfig)
		if err != nil {
			return nil, err
		}
		for sourceID, sourceDetailsByImage := range importedInventory {
			if err := inventory.AddImageSourceDetails(sourceID, sourceDetailsByImage); err != nil {
				log.Warnf("some imported images could not be parsed: %v", err)
			}
		}
	}

	return inventory, nil
}
