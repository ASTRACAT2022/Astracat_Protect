package bot

import (
	"testing"

	"astracat-protect/internal/config"
)

func TestGoodBotDefaultProfile(t *testing.T) {
	e, err := New(config.BotManagementConfig{Enabled: true})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	d := e.Evaluate("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	if !d.Matched || d.Kind != KindGood || d.Action != "allow" {
		t.Fatalf("unexpected decision: %+v", d)
	}
}

func TestBadBotPolicyAndPriority(t *testing.T) {
	e, err := New(config.BotManagementConfig{
		Enabled:      true,
		BadAction:    "block",
		GoodPatterns: []string{"curl"},
		BadPatterns:  []string{"curl"},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	d := e.Evaluate("curl/8.4.0")
	if !d.Matched || d.Kind != KindBad {
		t.Fatalf("expected bad decision, got: %+v", d)
	}
	if d.Action != "block" {
		t.Fatalf("expected block action, got %q", d.Action)
	}
}

func TestBadProfileActionFallbackToGlobal(t *testing.T) {
	e, err := New(config.BotManagementConfig{
		Enabled:   true,
		BadAction: "rate_limit",
		Profiles: []config.BotProfile{
			{Name: "bad-evil", Kind: KindBad, Pattern: `evilbot`, Priority: 100},
		},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	d := e.Evaluate("EvilBot/1.0")
	if !d.Matched || d.Kind != KindBad {
		t.Fatalf("unexpected decision: %+v", d)
	}
	if d.Action != "rate_limit" {
		t.Fatalf("expected rate_limit, got %q", d.Action)
	}
}

func TestInvalidRegexFailsConfig(t *testing.T) {
	_, err := New(config.BotManagementConfig{
		Enabled:  true,
		Profiles: []config.BotProfile{{Name: "bad", Kind: KindBad, Pattern: "("}},
	})
	if err == nil {
		t.Fatal("expected regex compile error")
	}
}
