package registries

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type closeSpy struct {
	io.Reader
	closed bool
}

func (c *closeSpy) Close() error { c.closed = true; return nil }

func TestDrainClose(t *testing.T) {
	DrainClose(nil)
	DrainClose(&http.Response{})
	spy := &closeSpy{Reader: io.LimitReader(zeroReader{}, 100)}
	DrainClose(&http.Response{Body: spy})
	if !spy.closed {
		t.Fatal("body not closed")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { return len(p), nil }

func TestHTTPClientHasTimeout(t *testing.T) {
	if HTTPClient.Timeout == 0 {
		t.Fatal("HTTPClient must have a timeout")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	resp, err := HTTPClient.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	DrainClose(resp)
}
