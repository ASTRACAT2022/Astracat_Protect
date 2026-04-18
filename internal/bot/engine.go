package bot

import (
	"regexp"
	"sort"
	"strings"

	"astracat-protect/internal/config"
)

const (
	KindGood = "good"
	KindBad  = "bad"
)

type Decision struct {
	Matched bool
	Kind    string
	Profile string
	Action  string
	Reason  string
}

type Engine struct {
	enabled          bool
	badAction        string
	bypassWAFForGood bool
	profiles         []compiledProfile
}

type compiledProfile struct {
	name     string
	kind     string
	action   string
	priority int
	regex    *regexp.Regexp
}

func New(cfg config.BotManagementConfig) (*Engine, error) {
	e := &Engine{
		enabled:          cfg.Enabled,
		badAction:        normalizedBadActionOrDefault(cfg.BadAction),
		bypassWAFForGood: cfg.BypassWAFForGood,
	}
	if !e.enabled {
		return e, nil
	}

	items := make([]config.BotProfile, 0, len(cfg.Profiles)+len(cfg.GoodPatterns)+len(cfg.BadPatterns)+16)
	items = append(items, defaultProfiles()...)
	for i, pat := range cfg.GoodPatterns {
		items = append(items, config.BotProfile{
			Name:     "good-custom-" + intToString(i+1),
			Kind:     KindGood,
			Pattern:  pat,
			Priority: 50,
		})
	}
	for i, pat := range cfg.BadPatterns {
		items = append(items, config.BotProfile{
			Name:     "bad-custom-" + intToString(i+1),
			Kind:     KindBad,
			Pattern:  pat,
			Action:   e.badAction,
			Priority: 90,
		})
	}
	items = append(items, cfg.Profiles...)

	out := make([]compiledProfile, 0, len(items))
	for _, p := range items {
		kind := normalizeKind(p.Kind)
		if kind == "" {
			continue
		}
		pattern := strings.TrimSpace(p.Pattern)
		if pattern == "" {
			continue
		}
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			return nil, err
		}
		action := ""
		if kind == KindBad {
			action = normalizeBadAction(p.Action)
			if action == "" {
				action = e.badAction
			}
		}
		out = append(out, compiledProfile{
			name:     strings.TrimSpace(p.Name),
			kind:     kind,
			action:   action,
			priority: p.Priority,
			regex:    re,
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].priority != out[j].priority {
			return out[i].priority > out[j].priority
		}
		// Prefer bad matches when priorities are equal.
		if out[i].kind != out[j].kind {
			return out[i].kind == KindBad
		}
		return out[i].name < out[j].name
	})
	e.profiles = out
	return e, nil
}

func (e *Engine) Enabled() bool {
	return e != nil && e.enabled
}

func (e *Engine) BypassWAFForGood() bool {
	return e != nil && e.bypassWAFForGood
}

func (e *Engine) Evaluate(userAgent string) Decision {
	if !e.Enabled() {
		return Decision{}
	}
	ua := strings.TrimSpace(userAgent)
	if ua == "" {
		return Decision{}
	}
	for _, p := range e.profiles {
		if p.regex == nil || !p.regex.MatchString(ua) {
			continue
		}
		if p.kind == KindGood {
			return Decision{
				Matched: true,
				Kind:    KindGood,
				Profile: p.name,
				Action:  "allow",
				Reason:  "good bot profile",
			}
		}
		return Decision{
			Matched: true,
			Kind:    KindBad,
			Profile: p.name,
			Action:  p.action,
			Reason:  "bad bot profile",
		}
	}
	return Decision{}
}

func normalizeKind(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case KindGood:
		return KindGood
	case KindBad:
		return KindBad
	default:
		return ""
	}
}

func normalizeBadAction(v string) string {
	switch strings.ToLower(strings.TrimSpace(strings.ReplaceAll(v, "-", "_"))) {
	case "block":
		return "block"
	case "challenge":
		return "challenge"
	case "rate_limit", "ratelimit":
		return "rate_limit"
	default:
		return ""
	}
}

func normalizedBadActionOrDefault(v string) string {
	if out := normalizeBadAction(v); out != "" {
		return out
	}
	return "challenge"
}

func defaultProfiles() []config.BotProfile {
	return []config.BotProfile{
		// Verified/common crawlers (UA-level profile, optional extra verification can be added later).
		{Name: "good-googlebot", Kind: KindGood, Pattern: `\bgooglebot\b`, Priority: 30},
		{Name: "good-bingbot", Kind: KindGood, Pattern: `\bbingbot\b`, Priority: 30},
		{Name: "good-yandexbot", Kind: KindGood, Pattern: `\byandex(bot|images|news)\b`, Priority: 30},
		{Name: "good-duckduckbot", Kind: KindGood, Pattern: `\bduckduckbot\b`, Priority: 30},
		{Name: "good-applebot", Kind: KindGood, Pattern: `\bapplebot\b`, Priority: 30},
		{Name: "good-twitterbot", Kind: KindGood, Pattern: `\btwitterbot\b`, Priority: 30},
		{Name: "good-facebook", Kind: KindGood, Pattern: `\bfacebookexternalhit\b`, Priority: 30},
		{Name: "good-linkedin", Kind: KindGood, Pattern: `\blinkedin(bot|preview)\b`, Priority: 30},
		{Name: "good-slack", Kind: KindGood, Pattern: `\bslackbot\b`, Priority: 30},
		{Name: "good-telegram", Kind: KindGood, Pattern: `\btelegrambot\b`, Priority: 30},

		// Known attack/scanner automation.
		{Name: "bad-scan-suite", Kind: KindBad, Pattern: `\b(sqlmap|nikto|acunetix|nessus|nmap|masscan|zgrab|nuclei|dirbuster|gobuster)\b`, Action: "block", Priority: 100},
		{Name: "bad-cli-http", Kind: KindBad, Pattern: `\b(curl|wget|httpie|python-requests|aiohttp|okhttp|libwww-perl|java/)\b`, Action: "challenge", Priority: 60},
		{Name: "bad-headless", Kind: KindBad, Pattern: `\b(headlesschrome|phantomjs|selenium|playwright|puppeteer)\b`, Action: "rate_limit", Priority: 70},
	}
}

func intToString(v int) string {
	if v == 0 {
		return "0"
	}
	buf := [20]byte{}
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + (v % 10))
		v /= 10
	}
	return string(buf[i:])
}
