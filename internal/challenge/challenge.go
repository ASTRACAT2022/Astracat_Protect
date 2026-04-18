package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"net/http"
	"strings"
	"sync"
	"time"
)

type RiskEntry struct {
	Score            int
	Last             time.Time
	ErrorCount       int
	ErrorWindowStart time.Time
	LimitViolations  int
	ViolationLast    time.Time
	BannedUntil      time.Time
}

type RiskTracker struct {
	mu           sync.Mutex
	entries      map[string]*RiskEntry
	threshold    int
	statusWindow time.Duration
	ttl          time.Duration
	banAfter     int
	banFor       time.Duration
}

func NewRiskTracker(threshold int, statusWindow, ttl time.Duration, banAfter int, banFor time.Duration) *RiskTracker {
	return &RiskTracker{
		entries:      map[string]*RiskEntry{},
		threshold:    threshold,
		statusWindow: statusWindow,
		ttl:          ttl,
		banAfter:     banAfter,
		banFor:       banFor,
	}
}

func (rt *RiskTracker) UpdateRequest(ip string, r *http.Request) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	e := rt.get(ip)
	e.Last = time.Now()
	if r.UserAgent() == "" {
		e.Score++
	}
	if r.Header.Get("Accept") == "" || r.Header.Get("Accept-Language") == "" {
		e.Score++
	}
}

func (rt *RiskTracker) UpdateStatus(ip string, status int) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	e := rt.get(ip)
	now := time.Now()
	if e.ErrorWindowStart.IsZero() || now.Sub(e.ErrorWindowStart) > rt.statusWindow {
		e.ErrorWindowStart = now
		e.ErrorCount = 0
	}
	if status >= 400 {
		e.ErrorCount++
	}
	if e.ErrorCount > 10 {
		e.Score++
	}
	e.Last = now
}

func (rt *RiskTracker) Penalize(ip string, score int) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	e := rt.get(ip)
	e.Score += score
	e.Last = time.Now()
}

func (rt *RiskTracker) Allowed(ip string) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	e := rt.entries[ip]
	if e == nil {
		return true
	}
	if !e.BannedUntil.IsZero() && time.Now().Before(e.BannedUntil) {
		return false
	}
	return e.Score < rt.threshold
}

func (rt *RiskTracker) RegisterLimitViolation(ip string) (bool, time.Time) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	e := rt.get(ip)
	now := time.Now()
	e.Last = now
	e.Score++

	if !e.BannedUntil.IsZero() && now.Before(e.BannedUntil) {
		return true, e.BannedUntil
	}

	if e.ViolationLast.IsZero() || now.Sub(e.ViolationLast) > rt.ttl {
		e.LimitViolations = 0
	}
	e.ViolationLast = now
	e.LimitViolations++

	if rt.banAfter > 0 && rt.banFor > 0 && e.LimitViolations >= rt.banAfter {
		e.BannedUntil = now.Add(rt.banFor)
		e.LimitViolations = 0
		return true, e.BannedUntil
	}

	return false, time.Time{}
}

func (rt *RiskTracker) IsBanned(ip string) (bool, time.Time) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	e := rt.entries[ip]
	if e == nil || e.BannedUntil.IsZero() {
		return false, time.Time{}
	}
	if time.Now().Before(e.BannedUntil) {
		return true, e.BannedUntil
	}
	return false, time.Time{}
}

func (rt *RiskTracker) Cleanup() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	for k, v := range rt.entries {
		if now.Sub(v.Last) > rt.ttl && (v.BannedUntil.IsZero() || now.After(v.BannedUntil)) {
			delete(rt.entries, k)
		}
	}
}

func (rt *RiskTracker) get(ip string) *RiskEntry {
	e := rt.entries[ip]
	if e == nil {
		e = &RiskEntry{Last: time.Now()}
		rt.entries[ip] = e
	}
	return e
}

type Manager struct {
	Secret          []byte
	CookieName      string
	CookieTTL       time.Duration
	BindIP          bool
	BindUA          bool
	VerifyPath      string
	InterstitialURI string
	CaptchaTTL      time.Duration

	mu       sync.Mutex
	captchas map[string]*captchaEntry
}

type captchaEntry struct {
	Answer    string
	ReturnURL string
	IP        string
	UA        string
	ExpiresAt time.Time
}

func NewManager(secret []byte, ttl time.Duration) *Manager {
	return &Manager{
		Secret:          secret,
		CookieName:      "astracat_clearance",
		CookieTTL:       ttl,
		VerifyPath:      "/__challenge/verify",
		InterstitialURI: "/__challenge",
		CaptchaTTL:      10 * time.Minute,
		captchas:        map[string]*captchaEntry{},
	}
}

func (m *Manager) CookieValue(ip, ua string, expiry time.Time) string {
	payload := fmt.Sprintf("%d", expiry.Unix())
	if m.BindIP {
		payload += "|" + ip
	}
	if m.BindUA {
		payload += "|" + ua
	}

	mac := hmac.New(sha256.New, m.Secret)
	mac.Write([]byte(payload))
	sig := mac.Sum(nil)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func (m *Manager) VerifyCookie(ip, ua string, value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, m.Secret)
	mac.Write(payloadBytes)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return false
	}
	payload := string(payloadBytes)
	fields := strings.Split(payload, "|")
	if len(fields) == 0 {
		return false
	}
	exp, err := parseInt64(fields[0])
	if err != nil {
		return false
	}
	if time.Now().Unix() > exp {
		return false
	}
	idx := 1
	if m.BindIP {
		if idx >= len(fields) || fields[idx] != ip {
			return false
		}
		idx++
	}
	if m.BindUA {
		if idx >= len(fields) || fields[idx] != ua {
			return false
		}
	}
	return true
}

func (m *Manager) InterstitialHTML(ip, ua, original string) string {
	token, prompt, err := m.newCaptcha(ip, ua, original)
	if err != nil {
		return `<!doctype html><html><head><meta charset="utf-8"><title>Checking your browser...</title></head><body>Checking your browser...<br>Protect by ASTRACAT</body></html>`
	}

	verifyPath := html.EscapeString(m.VerifyPath)
	token = html.EscapeString(token)
	original = html.EscapeString(original)
	prompt = html.EscapeString(prompt)

	return fmt.Sprintf(`<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<title>Checking your browser...</title>
<style>
body{font-family:Arial,sans-serif;background:#0b0c10;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#1f2833;padding:24px 32px;border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,.3);min-width:280px}
.spinner{width:26px;height:26px;border:3px solid #45a29e;border-top-color:transparent;border-radius:50%%;animation:spin 1s linear infinite;display:inline-block;margin-right:12px;vertical-align:middle}
.status{margin-bottom:16px}
.captcha-label{display:block;margin-bottom:8px}
.input{width:100%%;padding:10px;border-radius:8px;border:1px solid #3a4a5a;background:#0f141a;color:#fff;box-sizing:border-box}
.btn{width:100%%;margin-top:10px;padding:10px;border:0;border-radius:8px;background:#45a29e;color:#0b0c10;font-weight:bold;cursor:pointer}
.btn[disabled]{opacity:.5;cursor:not-allowed}
.brand{margin-top:12px;font-size:12px;color:#9aa7b5;text-align:center;letter-spacing:.4px}
.hint{margin:8px 0 12px 0;font-size:12px;color:#c6d0db}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="card">
  <div class="status"><span class="spinner"></span>Checking your browser... <span id="countdown">3</span>s</div>
  <div class="hint">Wait 3 seconds, then solve the captcha.</div>
  <form method="POST" action="%s">
    <input type="hidden" name="token" value="%s" />
    <input type="hidden" name="url" value="%s" />
    <label class="captcha-label" for="captcha_answer">Solve: %s</label>
    <input id="captcha_answer" class="input" type="text" inputmode="numeric" name="answer" autocomplete="off" required />
    <button id="verify_btn" class="btn" type="submit">Verify</button>
  </form>
  <div class="brand">Protect by ASTRACAT</div>
</div>
<script>
var left = 3;
var btn = document.getElementById("verify_btn");
var label = document.getElementById("countdown");
btn.disabled = true;
var t = setInterval(function(){
  left -= 1;
  if (left <= 0) {
    clearInterval(t);
    label.textContent = "0";
    btn.disabled = false;
    return;
  }
  label.textContent = String(left);
}, 1000);
</script>
</body>
</html>`, verifyPath, token, original, prompt)
}

func (m *Manager) VerifyCaptcha(token, answer, ip, ua string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	e := m.captchas[token]
	if e == nil {
		return "", false
	}
	delete(m.captchas, token)

	if time.Now().After(e.ExpiresAt) {
		return "", false
	}
	if m.BindIP && e.IP != ip {
		return "", false
	}
	if m.BindUA && e.UA != ua {
		return "", false
	}
	if strings.TrimSpace(answer) != e.Answer {
		return "", false
	}

	return e.ReturnURL, true
}

func (m *Manager) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for token, entry := range m.captchas {
		if now.After(entry.ExpiresAt) {
			delete(m.captchas, token)
		}
	}
}

func (m *Manager) newCaptcha(ip, ua, original string) (string, string, error) {
	token, err := randomToken()
	if err != nil {
		return "", "", err
	}

	a, err := randomSmallInt()
	if err != nil {
		return "", "", err
	}
	b, err := randomSmallInt()
	if err != nil {
		return "", "", err
	}

	if !strings.HasPrefix(original, "/") {
		original = "/"
	}

	m.mu.Lock()
	m.captchas[token] = &captchaEntry{
		Answer:    fmt.Sprintf("%d", a+b),
		ReturnURL: original,
		IP:        ip,
		UA:        ua,
		ExpiresAt: time.Now().Add(m.CaptchaTTL),
	}
	m.mu.Unlock()

	return token, fmt.Sprintf("%d + %d = ?", a, b), nil
}

func randomToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomSmallInt() (int, error) {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return int(b[0]%9) + 1, nil
}

func parseInt64(s string) (int64, error) {
	if s == "" {
		return 0, errors.New("empty int")
	}
	var v int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid int")
		}
		v = v*10 + int64(r-'0')
	}
	return v, nil
}
