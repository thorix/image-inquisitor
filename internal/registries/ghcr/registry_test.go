package ghcr

import (
	"encoding/json"
	"testing"
)

func TestParseLinkHeader(t *testing.T) {

	testCases := []struct {
		header   string
		expected string
	}{
		{`<https://example.com/api/items?page=2>; rel="next"`, "https://example.com/api/items?page=2"},
		{`<https://example.com/styles.css>; rel="preload"; as="style"`, ""},
		{`<https://example.com/article/123>; rel="canonical"`, ""},
		{`<https://m.example.com/article/123>; rel="alternate"; media="only screen and (max-width: 600px)"`, ""},
		{`<https://example.com/api/items?page=2>; rel="next", <https://example.com/api/items?page=1>; rel="prev", <https://example.com/styles.css>; rel="preload"; as="style"`,
			"https://example.com/api/items?page=2"},
	}

	for _, tc := range testCases {
		result := parseLinkHeaderRelNext(tc.header)

		if result != tc.expected {
			t.Errorf("link for `%s` not correct; want `%s`, got `%s`", tc.header, tc.expected, result)
		}
	}
}

func TestSelectPlatformManifestNilPlatform(t *testing.T) {
	var idx manifestIndexResponse
	if err := json.Unmarshal([]byte(`{"manifests":[{"digest":"a"},{"digest":"b","platform":{"architecture":"amd64"}}]}`), &idx); err != nil {
		t.Fatal(err)
	}
	m, err := selectPlatformManifest(&idx)
	if err != nil || m.Digest != "b" {
		t.Fatalf("got %v, %v; want digest b", m, err)
	}

	var only manifestIndexResponse
	if err := json.Unmarshal([]byte(`{"manifests":[{"digest":"a"}]}`), &only); err != nil {
		t.Fatal(err)
	}
	if _, err := selectPlatformManifest(&only); err == nil {
		t.Fatal("expected error for index with no platform entries")
	}
}

func TestConfigDigestNil(t *testing.T) {
	var m manifestResponse
	if err := json.Unmarshal([]byte(`{}`), &m); err != nil {
		t.Fatal(err)
	}
	if _, err := configDigestOf(m.Config, "u"); err == nil {
		t.Fatal("expected error for manifest without config")
	}
	if d, err := configDigestOf(&manifestResponseConfig{Digest: "x"}, "u"); err != nil || d != "x" {
		t.Fatalf("got %q, %v", d, err)
	}
}
