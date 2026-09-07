package harbor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/bartlettc22/image-inquisitor/internal/imageUtils"
	"github.com/bartlettc22/image-inquisitor/internal/registries"
	"github.com/bartlettc22/image-inquisitor/internal/utils"
)

// Harbor is self-hosted, so unlike quay/ghcr/docker there is no well-known
// hostname to match on. The hosts to treat as Harbor are supplied by the
// caller (--harbor-registries), which keeps IsRegistry a cheap string check
// rather than probing every unknown registry over the network.
type HarborRegistry struct {
	hosts    map[string]struct{}
	username string
	password string
}

type artifactsResponse []artifact

type artifact struct {
	PushTime time.Time `json:"push_time"`
	Tags     []tag     `json:"tags"`
}

type tag struct {
	Name     string    `json:"name"`
	PushTime time.Time `json:"push_time"`
}

func NewRegistry(hosts []string) *HarborRegistry {
	h := &HarborRegistry{
		hosts: make(map[string]struct{}),
		// Optional. Harbor serves public projects anonymously, so credentials
		// are only needed for private ones.
		username: os.Getenv("HARBOR_USERNAME"),
		password: os.Getenv("HARBOR_PASSWORD"),
	}
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host != "" {
			h.hosts[host] = struct{}{}
		}
	}
	return h
}

func (r *HarborRegistry) IsRegistry(registry string) bool {
	_, ok := r.hosts[registry]
	return ok
}

// splitProjectRepo maps a parsed image onto Harbor's project/repository model.
//
// Harbor addresses artifacts as {project}/{repository}, where repository may
// itself contain slashes (proxy-cache projects mirror the upstream path). The
// image parser puts everything but the last path segment into Owner, so:
//
//	harbor.example.com/library/vrestic          -> project "library",         repo "vrestic"
//	harbor.example.com/dockerhub-cache/library/busybox -> project "dockerhub-cache", repo "library/busybox"
func splitProjectRepo(image *imageUtils.Image) (string, string) {
	ownerParts := strings.Split(image.Owner, "/")
	project := ownerParts[0]
	repoParts := append(ownerParts[1:], image.Repository)
	return project, strings.Join(repoParts, "/")
}

func (r *HarborRegistry) FetchReport(image *imageUtils.Image) (*registries.RegistryImageReport, error) {
	project, repo := splitProjectRepo(image)

	tags, err := r.fetchTags(image.Registry, project, repo)
	if err != nil {
		return nil, err
	}

	report := &registries.RegistryImageReport{
		Tag: image.Tag,
	}

	for _, t := range tags {
		if t.Tag == image.Tag {
			report.TagTimestamp = t.TagTimestamp
			break
		}
	}

	// KNOWN LIMITATION -- proxy-cache projects.
	//
	// Harbor's pull-through cache stores artifacts by digest with an EMPTY tags
	// array, so there is no tag->timestamp mapping to read. Verified against a
	// live Harbor 2.14: a cached artifact reports push_time correctly but
	// "tags": []. Repositories whose cached content has since been evicted go
	// further and report artifact_count=0 while still showing a pull_count.
	//
	// The effect is that a proxy-cached image yields its tag but a zero
	// timestamp. That is honest -- Harbor genuinely does not know -- but the
	// more useful answer for those images is the UPSTREAM registry's data
	// (ghcr.io, docker.io), since what you want to know is how far behind
	// upstream you are, not when the cache happened to fill. Harbor exposes the
	// mapping via project.registry_id -> /api/v2.0/registries/{id}, so a future
	// pass can resolve proxy projects to their upstream and delegate.
	//
	// Local (non-proxy) projects are unaffected and report full tag timestamps.
	if latest, err := utils.LatestSemanticVersion(tags); err == nil && latest != nil {
		report.LatestTag = latest.Tag
		report.LatestTagTimestamp = latest.TagTimestamp
	}

	return report, nil
}

func (r *HarborRegistry) fetchTags(host, project, repo string) ([]*registries.Tag, error) {
	// Harbor's path segment for a repository is URL-escaped, so a nested repo
	// name arrives double-encoded (a literal "/" becomes "%252F").
	escapedRepo := url.PathEscape(url.PathEscape(repo))

	var tags []*registries.Tag
	page := 1

	for {
		endpoint := fmt.Sprintf(
			"https://%s/api/v2.0/projects/%s/repositories/%s/artifacts?with_tag=true&page=%d&page_size=100",
			host, url.PathEscape(project), escapedRepo, page)

		req, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		if r.username != "" {
			req.SetBasicAuth(r.username, r.password)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to get artifacts for %s/%s: %s", project, repo, resp.Status)
		}

		var artifacts artifactsResponse
		if err := json.NewDecoder(resp.Body).Decode(&artifacts); err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()

		if len(artifacts) == 0 {
			break
		}

		for _, a := range artifacts {
			for _, t := range a.Tags {
				ts := t.PushTime
				if ts.IsZero() {
					ts = a.PushTime
				}
				tags = append(tags, &registries.Tag{
					Tag:          t.Name,
					TagTimestamp: ts,
				})
			}
		}

		page++
	}

	return tags, nil
}
