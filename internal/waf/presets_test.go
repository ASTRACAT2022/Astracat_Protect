package waf

import (
	"net/http/httptest"
	"testing"
)

func TestWAFPresetsWordPress(t *testing.T) {
	e, err := New(Config{
		Enabled:          true,
		Mode:             "block",
		InboundThreshold: 7,
		ParanoiaLevel:    3,
		Presets:          []string{"wordpress"},
	})
	if err != nil {
		t.Fatalf("new waf: %v", err)
	}

	req := httptest.NewRequest("GET", "https://example.com/wp-content/uploads/shell.php", nil)
	d, err := e.Inspect(req, nil)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if !d.Matched || d.Action != "block" {
		t.Fatalf("unexpected decision: %+v", d)
	}
	if !contains(d.RuleIDs, "waf-preset-wp-php-upload-exec") {
		t.Fatalf("missing wordpress preset rule in decision: %+v", d)
	}
}

func TestWAFPresetsLaravel(t *testing.T) {
	e, err := New(Config{
		Enabled:          true,
		Mode:             "block",
		InboundThreshold: 7,
		ParanoiaLevel:    2,
		Presets:          []string{"laravel"},
	})
	if err != nil {
		t.Fatalf("new waf: %v", err)
	}

	req := httptest.NewRequest("GET", "https://example.com/.env", nil)
	d, err := e.Inspect(req, nil)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if !d.Matched || d.Action != "block" {
		t.Fatalf("unexpected decision: %+v", d)
	}
	if !contains(d.RuleIDs, "waf-preset-laravel-env-exposure") {
		t.Fatalf("missing laravel preset rule in decision: %+v", d)
	}
}

func TestWAFPresetsNextJSAlias(t *testing.T) {
	e, err := New(Config{
		Enabled:          true,
		Mode:             "block",
		InboundThreshold: 7,
		ParanoiaLevel:    2,
		Presets:          []string{"next"},
	})
	if err != nil {
		t.Fatalf("new waf: %v", err)
	}

	req := httptest.NewRequest("GET", "https://example.com/_next/image?url=http://169.254.169.254/latest/meta-data", nil)
	d, err := e.Inspect(req, nil)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if !d.Matched || d.Action != "block" {
		t.Fatalf("unexpected decision: %+v", d)
	}
	if !contains(d.RuleIDs, "waf-preset-nextjs-image-ssrf") {
		t.Fatalf("missing nextjs preset rule in decision: %+v", d)
	}
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
