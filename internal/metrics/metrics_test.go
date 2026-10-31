package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEscapesLabelValues(t *testing.T) {
	p := NewPublisher("")
	// Image refs come from cluster specs; an unescaped quote or backslash would
	// produce a malformed payload and the whole push would be rejected, silently
	// losing an entire scan.
	p.Gauge("m", "h", map[string]string{"image": `we"ird\path`}, 1)
	got := p.Payload()
	if !strings.Contains(got, `image="we\"ird\\path"`) {
		t.Errorf("label value not escaped:\n%s", got)
	}
}

func TestLabelsSortedAndHelpEmittedOnce(t *testing.T) {
	p := NewPublisher("")
	p.Gauge("m", "h", map[string]string{"z": "1", "a": "2"}, 1)
	p.Gauge("m", "h", map[string]string{"z": "3", "a": "4"}, 2)
	got := p.Payload()
	if strings.Count(got, "# HELP m") != 1 {
		t.Errorf("HELP should appear once:\n%s", got)
	}
	if !strings.Contains(got, `m{a="2",z="1"} 1`) {
		t.Errorf("labels should be sorted:\n%s", got)
	}
}

func TestNoLabelsFormsBareSample(t *testing.T) {
	p := NewPublisher("")
	p.Gauge("scan_ts", "h", nil, 1789187833)
	if !strings.Contains(p.Payload(), "scan_ts 1.789187833e+09") {
		t.Errorf("bare sample malformed:\n%s", p.Payload())
	}
}

func TestEmptyPayloadIsRefused(t *testing.T) {
	// Pushing nothing would look like a successful scan that found no images.
	p := NewPublisher("http://example.invalid")
	if err := p.Push(0); err == nil {
		t.Error("an empty payload must be refused, not pushed")
	}
}

func TestNoEndpointIsNotAnError(t *testing.T) {
	p := NewPublisher("")
	p.Gauge("m", "h", nil, 1)
	if err := p.Push(0); err != nil {
		t.Errorf("publishing should be a no-op when disabled, got %v", err)
	}
}

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"http://u:p@vm.example.lan:8428/api": "http://u:xxxxx@vm.example.lan:8428/api", // trufflehog:ignore
		"http://vm.example.lan:8428/api":     "http://vm.example.lan:8428/api",
		"http://[::1%zz/":                    "<unparseable url>",
		// Query values and fragments can carry tokens too.
		"http://vm.example.lan/api?authKey=s3cret&extra_label=job%3Dx": "http://vm.example.lan/api?authKey=xxxxx&extra_label=xxxxx",        // trufflehog:ignore
		"http://u:p@vm.example.lan/api?access_token=t&token=t2":        "http://u:xxxxx@vm.example.lan/api?access_token=xxxxx&token=xxxxx", // trufflehog:ignore
		"http://vm.example.lan/api?password=a&password=b":              "http://vm.example.lan/api?password=xxxxx",                         // trufflehog:ignore
		"http://vm.example.lan/api?key":                                "http://vm.example.lan/api?key=xxxxx",
		"http://vm.example.lan/api?token=%zz&a=1":                      "http://vm.example.lan/api?a=xxxxx",
		"http://vm.example.lan/api#key=s3cret":                         "http://vm.example.lan/api",
	}
	for in, want := range cases {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPushErrorRedactsCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer srv.Close()
	endpoint := strings.Replace(srv.URL, "http://", "http://u:s3cret@", 1) + "/api?authKey=t0ken" // trufflehog:ignore
	for _, ep := range []string{endpoint, strings.Replace(endpoint, srv.URL[len("http://"):], "127.0.0.1:1", 1)} {
		p := NewPublisher(ep)
		p.Gauge("m", "h", nil, 1)
		err := p.Push(2 * time.Second)
		if err == nil {
			t.Fatalf("push to %s should fail", Redact(ep))
		}
		if strings.Contains(err.Error(), "s3cret") {
			t.Errorf("push error leaks the password: %v", err)
		}
		if strings.Contains(err.Error(), "t0ken") {
			t.Errorf("push error leaks the query token: %v", err)
		}
	}
}
