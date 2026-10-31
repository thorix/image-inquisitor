package docker

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func recordSleeps(t *testing.T) *[]time.Duration {
	t.Helper()
	var mu sync.Mutex
	var got []time.Duration
	old := sleep
	sleep = func(d time.Duration) { mu.Lock(); got = append(got, d); mu.Unlock() }
	t.Cleanup(func() { sleep = old })
	return &got
}

const tagBody = `{"name":"1.0","last_updated":"2024-01-02T03:04:05Z"}`

func TestRetryAfter(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cases := []struct {
		name, val string
		want      time.Duration
	}{
		{"seconds", "60", 60 * time.Second},
		{"floor", "1", 2 * time.Second},
		{"clamp", "600", 5 * time.Minute},
		{"http-date", now.Add(30 * time.Second).UTC().Format(http.TimeFormat), 30 * time.Second},
		{"epoch", strconv.FormatInt(now.Unix()+45, 10), 45 * time.Second},
		{"missing", "", 60 * time.Second},
		{"garbage", "soon", 60 * time.Second},
	}
	for _, c := range cases {
		h := http.Header{}
		if c.val != "" {
			h.Set("Retry-After", c.val)
		}
		if got := retryAfter(h, now); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func TestPermanent429GivesUp(t *testing.T) {
	sleeps := recordSleeps(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(429)
	}))
	defer srv.Close()
	_, err := newRegistryWith(srv.URL, srv.Client()).getTag("o", "r", "1.0")
	if err == nil || !strings.Contains(err.Error(), "gave up after 5 retries") {
		t.Fatalf("got %v", err)
	}
	if len(*sleeps) != 5 {
		t.Fatalf("sleeps = %v, want 5", *sleeps)
	}
}

func retryServer(conns *int32) *httptest.Server {
	var n int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) <= 2 {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(429)
			_, _ = w.Write([]byte("slow down"))
			return
		}
		_, _ = w.Write([]byte(tagBody))
	}))
	if conns != nil {
		srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
			if st == http.StateNew {
				atomic.AddInt32(conns, 1)
			}
		}
	}
	return srv
}

func TestRetryAfterThenSuccess(t *testing.T) {
	sleeps := recordSleeps(t)
	srv := retryServer(nil)
	srv.Start()
	defer srv.Close()
	tag, err := newRegistryWith(srv.URL, srv.Client()).getTag("o", "r", "1.0")
	if err != nil || tag.Tag != "1.0" {
		t.Fatalf("got %v, %v", tag, err)
	}
	if len(*sleeps) != 2 || (*sleeps)[0] != 3*time.Second || (*sleeps)[1] != 3*time.Second {
		t.Fatalf("sleeps = %v", *sleeps)
	}
}

func TestBodiesClosedConnectionReused(t *testing.T) {
	recordSleeps(t)
	var conns int32
	srv := retryServer(&conns)
	srv.Start()
	defer srv.Close()
	// Dedicated transport so the test does not depend on shared pool state.
	client := &http.Client{Transport: &http.Transport{}, Timeout: 5 * time.Second}
	if _, err := newRegistryWith(srv.URL, client).getTag("o", "r", "1.0"); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&conns); got != 1 {
		t.Fatalf("connections opened = %d, want 1", got)
	}
}

func TestNotFoundSurfacesStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	_, err := newRegistryWith(srv.URL, srv.Client()).getTag("o", "r", "1.0")
	if err == nil || !strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "unexpected end of JSON") {
		t.Fatalf("got %v", err)
	}
}

func TestHungServerTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()
	defer close(release)
	client := &http.Client{Timeout: 200 * time.Millisecond}
	start := time.Now()
	_, err := newRegistryWith(srv.URL, client).getTag("o", "r", "1.0")
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("err=%v elapsed=%s", err, time.Since(start))
	}
}

func TestStalledBodyTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()
	defer close(release)
	client := &http.Client{Timeout: 200 * time.Millisecond}
	start := time.Now()
	_, err := newRegistryWith(srv.URL, client).getTag("o", "r", "1.0")
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("err=%v elapsed=%s", err, time.Since(start))
	}
}
