package docker

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/bartlettc22/image-inquisitor/internal/registries"
	log "github.com/sirupsen/logrus"
)

const (
	// maxRateLimitRetries bounds how many times one request is retried after
	// being rate limited before the worker reports an error.
	maxRateLimitRetries = 5

	minRetryWait = 2 * time.Second
	maxRetryWait = 5 * time.Minute
	defaultWait  = 60 * time.Second

	// Retry-After integers at or above this are Unix epoch seconds rather than
	// a delay in seconds.
	epochThreshold = 1_000_000_000
)

// sleep is a variable so tests can replace it.
var sleep = time.Sleep

type WorkerRequest struct {
	url          string
	responseChan chan *WorkerResponse
}

type WorkerResponse struct {
	err       error
	bodyBytes []byte
}

func (r *DockerIORegistry) Run() {

	numWorkers := 5

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		go r.worker()
	}
}

func (r *DockerIORegistry) worker() {
	for request := range r.workerRequestChan {
		request.responseChan <- r.fetch(request.url)
	}
}

// fetch performs one GET, retrying while rate limited (at most
// maxRateLimitRetries times). Every response body is drained and closed.
func (r *DockerIORegistry) fetch(url string) *WorkerResponse {
	retries := 0
	for {
		resp, err := r.client.Get(url)
		if err != nil {
			return &WorkerResponse{err: err}
		}

		// If we're being throttled, wait until the limit resets
		if resp.StatusCode == http.StatusTooManyRequests {
			wait := retryAfter(resp.Header, time.Now())
			registries.DrainClose(resp)
			if retries >= maxRateLimitRetries {
				return &WorkerResponse{err: fmt.Errorf("rate limited by docker hub: gave up after %d retries", maxRateLimitRetries)}
			}
			retries++
			log.Debugf("waiting %s for hub.docker.com rate limit", wait)
			sleep(wait)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			registries.DrainClose(resp)
			return &WorkerResponse{err: fmt.Errorf("failed to get tags for '%s': %s", url, resp.Status)}
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		registries.DrainClose(resp)
		if err != nil {
			return &WorkerResponse{err: fmt.Errorf("failed to read http body for '%s': %v", url, err)}
		}
		return &WorkerResponse{bodyBytes: bodyBytes}
	}
}

// retryAfter interprets a Retry-After header: an integer below 1e9 is a delay in
// seconds, a larger integer is a Unix epoch, anything else is tried as an
// HTTP-date. Missing or unparseable values wait 60 s. The result is floored at
// 2 s and clamped at 5 min.
func retryAfter(h http.Header, now time.Time) time.Duration {
	wait := defaultWait
	if v := h.Get("Retry-After"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			if n >= epochThreshold {
				wait = time.Unix(n, 0).Sub(now)
			} else {
				wait = time.Duration(n) * time.Second
			}
		} else if t, err := http.ParseTime(v); err == nil {
			wait = t.Sub(now)
		}
	}
	if wait < minRetryWait {
		wait = minRetryWait
	}
	if wait > maxRetryWait {
		wait = maxRetryWait
	}
	return wait
}
