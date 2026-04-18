package threatintel

import (
	"testing"

	"astracat-protect/internal/config"
)

func TestEngineCheckInlineIndicators(t *testing.T) {
	e, err := New(config.ThreatIntelConfig{
		Enabled: true,
		Action:  "block",
		IPs: []string{
			"1.2.3.4",
			"10.0.0.0/8,corp-net",
		},
		ASNs: []string{
			"AS13335",
			"AS15169,1.1.1.0/24",
			"1.0.0.0/24,AS64500",
		},
		JA3: []string{"abcd1234"},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	defer e.Close()

	t.Run("ip exact", func(t *testing.T) {
		d := e.Check(CheckInput{IP: "1.2.3.4"})
		if !d.Matched || d.Category != "ip" || d.Action != "block" {
			t.Fatalf("unexpected decision: %+v", d)
		}
	})

	t.Run("ip cidr", func(t *testing.T) {
		d := e.Check(CheckInput{IP: "10.10.10.10"})
		if !d.Matched || d.Category != "ip" {
			t.Fatalf("unexpected decision: %+v", d)
		}
		if d.Indicator != "10.0.0.0/8" {
			t.Fatalf("expected cidr indicator, got %q", d.Indicator)
		}
	})

	t.Run("asn direct", func(t *testing.T) {
		d := e.Check(CheckInput{IP: "9.9.9.9", ASN: "as13335"})
		if !d.Matched || d.Category != "asn" || d.Indicator != "AS13335" {
			t.Fatalf("unexpected decision: %+v", d)
		}
	})

	t.Run("asn by ip range", func(t *testing.T) {
		d := e.Check(CheckInput{IP: "1.1.1.8"})
		if !d.Matched || d.Category != "asn" || d.Indicator != "AS15169" {
			t.Fatalf("unexpected decision: %+v", d)
		}
	})

	t.Run("ja3 direct", func(t *testing.T) {
		d := e.Check(CheckInput{IP: "8.8.8.8", JA3: "ABCD1234"})
		if !d.Matched || d.Category != "ja3" || d.Indicator != "abcd1234" {
			t.Fatalf("unexpected decision: %+v", d)
		}
	})
}

func TestEngineCheckPseudoJA3Fallback(t *testing.T) {
	tlsIn := &TLSFingerprintInput{
		Version:    0x0304,
		Cipher:     0x1301,
		ServerName: "api.example.com",
		ALPN:       "h2",
	}
	ja3 := pseudoJA3(tlsIn)
	if ja3 == "" {
		t.Fatal("pseudoJA3 is empty")
	}

	e, err := New(config.ThreatIntelConfig{
		Enabled: true,
		Action:  "challenge",
		JA3:     []string{ja3},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	defer e.Close()

	d := e.Check(CheckInput{IP: "2.2.2.2", TLS: tlsIn})
	if !d.Matched || d.Category != "ja3" || d.Action != "challenge" {
		t.Fatalf("unexpected decision: %+v", d)
	}
}

func TestParseASNLineVariants(t *testing.T) {
	snap := snapshot{asnSet: map[string]iocItem{}}
	parseASNLine("AS13335", "feed-a", &snap)
	parseASNLine("AS15169,1.1.1.0/24", "feed-b", &snap)
	parseASNLine("1.0.0.0/24,AS64500", "feed-c", &snap)
	parseASNLine("AS4242,custom reason", "feed-d", &snap)

	if _, ok := snap.asnSet["AS13335"]; !ok {
		t.Fatal("AS13335 is missing")
	}
	if _, ok := snap.asnSet["AS15169"]; !ok {
		t.Fatal("AS15169 is missing")
	}
	if _, ok := snap.asnSet["AS64500"]; !ok {
		t.Fatal("AS64500 is missing")
	}
	if item, ok := snap.asnSet["AS4242"]; !ok || item.reason != "custom reason" {
		t.Fatalf("AS4242 reason mismatch: %+v", item)
	}
	if len(snap.asnRanges) < 2 {
		t.Fatalf("expected at least 2 asn ranges, got %d", len(snap.asnRanges))
	}
}
