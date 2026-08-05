package proxy

import (
	"net/http"
	"strings"
	"testing"
)

func TestIsWebSocketRequest(t *testing.T) {
	cases := []struct {
		name string
		h    http.Header
		want bool
	}{
		{"plain http", http.Header{}, false},
		{"upgrade only", http.Header{"Upgrade": {"websocket"}}, false},
		{"connection only", http.Header{"Connection": {"Upgrade"}}, false},
		{"both", http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}}, true},
		{"connection with multiple tokens", http.Header{"Upgrade": {"websocket"}, "Connection": {"keep-alive, Upgrade"}}, true},
		{"wrong upgrade", http.Header{"Upgrade": {"h2c"}, "Connection": {"Upgrade"}}, false},
		{"case-insensitive", http.Header{"Upgrade": {"WebSocket"}, "Connection": {"upgrade"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{Header: tc.h}
			got := IsWebSocketRequest(r)
			if got != tc.want {
				t.Fatalf("IsWebSocketRequest() = %v, want %v (headers=%v)", got, tc.want, tc.h)
			}
		})
	}
}

func TestIsOriginAllowed(t *testing.T) {
	cases := []struct {
		name    string
		origin  string
		allowed []string
		host    string
		want    bool
	}{
		{"empty list, no origin", "", nil, "example.com", true},
		{"empty list, same origin http", "http://example.com", nil, "example.com", true},
		{"empty list, cross origin", "http://evil.com", nil, "example.com", false},
		{"empty list, mismatched scheme", "http://example.com", nil, "example.com:443", false},
		{"empty list, tls same origin", "https://example.com", nil, "example.com:443", true},
		{"wildcard allows any", "https://x.com", []string{"*"}, "example.com", true},
		{"explicit allow", "https://app.example.com", []string{"https://app.example.com"}, "example.com", true},
		{"wildcard subdomain", "https://x.example.com", []string{"*.example.com"}, "example.com", true},
		{"wildcard subdomain no match", "https://example.com", []string{"*.example.com"}, "example.com", false},
		{"deny list", "https://x.com", []string{"https://y.com"}, "example.com", false},
		{"empty list, wrong scheme", "ftp://example.com", nil, "example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isOriginAllowed(tc.origin, tc.allowed, tc.host)
			if got != tc.want {
				t.Fatalf("isOriginAllowed(%q, %v, %q) = %v, want %v", tc.origin, tc.allowed, tc.host, got, tc.want)
			}
		})
	}
}

func TestComputeAcceptKey(t *testing.T) {
	// Known-vector from RFC 6455 §1.3.
	got := computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==")
	want := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	if got != want {
		t.Fatalf("computeAcceptKey = %q, want %q", got, want)
	}
}

func TestSingleJoinPath(t *testing.T) {
	cases := []struct {
		base, req, want string
	}{
		{"", "/foo", "/foo"},
		{"/api", "/foo", "/api/foo"},
		{"/api/", "/foo", "/api/foo"},
		{"/api", "/", "/api/"},
		{"/api/", "/", "/api/"},
		{"/", "/foo", "/foo"},
		{"/api", "", "/api"},
	}
	for _, tc := range cases {
		got := singleJoinPath(tc.base, tc.req)
		if got != tc.want {
			t.Errorf("singleJoinPath(%q, %q) = %q, want %q", tc.base, tc.req, got, tc.want)
		}
	}
}

func TestRandomKey(t *testing.T) {
	a := randomKey()
	b := randomKey()
	if a == "" || b == "" {
		t.Fatal("randomKey returned empty string")
	}
	if a == b {
		t.Fatal("randomKey returned same value twice")
	}
	if !strings.HasSuffix(a, "=") || !strings.HasSuffix(b, "=") {
		t.Fatal("randomKey is not base64 padded")
	}
}
