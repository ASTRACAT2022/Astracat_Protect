package autoshield

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	defaultWindowSeconds           = 60
	defaultMinRequests             = 25
	defaultProbePathThreshold      = 18
	defaultHighErrorRatioPct       = 70
	defaultHighRateLimitedRatioPct = 35
	defaultScoreThreshold          = 7
	defaultBanSeconds              = 900
)

type Config struct {
	Enabled                 bool
	WindowSeconds           int
	MinRequests             int
	ProbePathThreshold      int
	HighErrorRatioPct       int
	HighRateLimitedRatioPct int
	ScoreThreshold          int
	BanSeconds              int
}

type ObserveInput struct {
	IP                string
	Path              string
	Status            int
	Blocked           bool
	RateLimited       bool
	WAFBlocked        bool
	HasUserAgent      bool
	HasAccept         bool
	HasAcceptLanguage bool
}

type BanDecision struct {
	Banned bool
	Until  time.Time
	Score  int
	Reason string
}

type Engine struct {
	mu sync.Mutex

	enabled                 bool
	window                  time.Duration
	minRequests             int
	probePathThreshold      int
	highErrorRatioPct       int
	highRateLimitedRatioPct int
	scoreThreshold          int
	banFor                  time.Duration

	entries map[string]*entry
}

type entry struct {
	windowFrom time.Time
	lastSeen   time.Time

	requests      int
	errors        int
	blocked       int
	rateLimited   int
	wafBlocked    int
	missingUA     int
	missingAccept int

	uniquePaths map[string]struct{}
	bannedUntil time.Time
}

func New(cfg Config) *Engine {
	windowSeconds := cfg.WindowSeconds
	if windowSeconds <= 0 {
		windowSeconds = defaultWindowSeconds
	}
	minRequests := cfg.MinRequests
	if minRequests <= 0 {
		minRequests = defaultMinRequests
	}
	probeThreshold := cfg.ProbePathThreshold
	if probeThreshold <= 0 {
		probeThreshold = defaultProbePathThreshold
	}
	highErr := cfg.HighErrorRatioPct
	if highErr <= 0 {
		highErr = defaultHighErrorRatioPct
	}
	highRL := cfg.HighRateLimitedRatioPct
	if highRL <= 0 {
		highRL = defaultHighRateLimitedRatioPct
	}
	scoreThreshold := cfg.ScoreThreshold
	if scoreThreshold <= 0 {
		scoreThreshold = defaultScoreThreshold
	}
	banSeconds := cfg.BanSeconds
	if banSeconds <= 0 {
		banSeconds = defaultBanSeconds
	}

	return &Engine{
		enabled:                 cfg.Enabled,
		window:                  time.Duration(windowSeconds) * time.Second,
		minRequests:             minRequests,
		probePathThreshold:      probeThreshold,
		highErrorRatioPct:       highErr,
		highRateLimitedRatioPct: highRL,
		scoreThreshold:          scoreThreshold,
		banFor:                  time.Duration(banSeconds) * time.Second,
		entries:                 map[string]*entry{},
	}
}

func (e *Engine) Enabled() bool {
	return e != nil && e.enabled
}

func (e *Engine) IsBanned(ip string) (bool, time.Time, string) {
	if !e.Enabled() || strings.TrimSpace(ip) == "" {
		return false, time.Time{}, ""
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	ent := e.entries[ip]
	if ent == nil || now.After(ent.bannedUntil) {
		return false, time.Time{}, ""
	}
	return true, ent.bannedUntil, "auto-shield adaptive ban"
}

func (e *Engine) Observe(in ObserveInput) BanDecision {
	if !e.Enabled() {
		return BanDecision{}
	}
	ip := strings.TrimSpace(in.IP)
	if ip == "" {
		return BanDecision{}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	ent := e.get(ip, now)

	if now.Sub(ent.windowFrom) > e.window {
		ent.windowFrom = now
		ent.requests = 0
		ent.errors = 0
		ent.blocked = 0
		ent.rateLimited = 0
		ent.wafBlocked = 0
		ent.missingUA = 0
		ent.missingAccept = 0
		ent.uniquePaths = map[string]struct{}{}
	}

	ent.lastSeen = now
	ent.requests++

	if in.Status >= 400 {
		ent.errors++
	}
	if in.Blocked {
		ent.blocked++
	}
	if in.RateLimited {
		ent.rateLimited++
	}
	if in.WAFBlocked {
		ent.wafBlocked++
	}
	if !in.HasUserAgent {
		ent.missingUA++
	}
	if !in.HasAccept || !in.HasAcceptLanguage {
		ent.missingAccept++
	}
	if p := normalizePath(in.Path); p != "" {
		ent.uniquePaths[p] = struct{}{}
	}

	if now.Before(ent.bannedUntil) {
		return BanDecision{Banned: true, Until: ent.bannedUntil}
	}

	if ent.requests < e.minRequests {
		return BanDecision{}
	}

	score := 0
	reasons := make([]string, 0, 6)

	if ent.wafBlocked >= 2 {
		score += 4
		reasons = append(reasons, "waf_blocked>=2")
	}

	errorRatioPct := pct(ent.errors, ent.requests)
	if errorRatioPct >= e.highErrorRatioPct && ent.errors >= max(8, e.minRequests/2) {
		score += 3
		reasons = append(reasons, fmt.Sprintf("high_error_ratio=%d%%", errorRatioPct))
	}

	rateLimitRatioPct := pct(ent.rateLimited, ent.requests)
	if rateLimitRatioPct >= e.highRateLimitedRatioPct && ent.rateLimited >= 4 {
		score += 3
		reasons = append(reasons, fmt.Sprintf("high_429_ratio=%d%%", rateLimitRatioPct))
	}

	uniqueCount := len(ent.uniquePaths)
	if uniqueCount >= e.probePathThreshold {
		score += 3
		reasons = append(reasons, fmt.Sprintf("path_probe=%d", uniqueCount))
	}
	if uniqueCount >= e.probePathThreshold*2 {
		score += 2
	}

	if pct(ent.missingUA, ent.requests) >= 60 {
		score++
		reasons = append(reasons, "missing_ua")
	}
	if pct(ent.missingAccept, ent.requests) >= 60 {
		score++
		reasons = append(reasons, "missing_accept_headers")
	}

	if ent.blocked >= 8 {
		score++
		reasons = append(reasons, "repeated_blocked_requests")
	}

	if score < e.scoreThreshold {
		return BanDecision{Score: score}
	}

	ent.bannedUntil = now.Add(e.banFor)
	ent.windowFrom = now
	ent.requests = 0
	ent.errors = 0
	ent.blocked = 0
	ent.rateLimited = 0
	ent.wafBlocked = 0
	ent.missingUA = 0
	ent.missingAccept = 0
	ent.uniquePaths = map[string]struct{}{}

	return BanDecision{
		Banned: true,
		Until:  ent.bannedUntil,
		Score:  score,
		Reason: strings.Join(reasons, ","),
	}
}

func (e *Engine) Cleanup() {
	if e == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	idleFor := e.window * 3
	for ip, ent := range e.entries {
		if now.Before(ent.bannedUntil) {
			continue
		}
		if now.Sub(ent.lastSeen) > idleFor {
			delete(e.entries, ip)
		}
	}
}

func (e *Engine) get(ip string, now time.Time) *entry {
	ent := e.entries[ip]
	if ent == nil {
		ent = &entry{
			windowFrom:  now,
			lastSeen:    now,
			uniquePaths: map[string]struct{}{},
		}
		e.entries[ip] = ent
	}
	return ent
}

func pct(part, total int) int {
	if total <= 0 || part <= 0 {
		return 0
	}
	return (part * 100) / total
}

func normalizePath(p string) string {
	v := strings.TrimSpace(strings.ToLower(p))
	if v == "" {
		return "/"
	}
	if len(v) > 96 {
		v = v[:96]
	}
	var out []rune
	lastDigit := false
	for _, r := range v {
		if r >= '0' && r <= '9' {
			if lastDigit {
				continue
			}
			out = append(out, '#')
			lastDigit = true
			continue
		}
		lastDigit = false
		out = append(out, r)
	}
	return string(out)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
