package server

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"astracat-protect/internal/challenge"
	"astracat-protect/internal/config"
	"astracat-protect/internal/limits"
	"astracat-protect/internal/logging"
	"astracat-protect/internal/metrics"
	"astracat-protect/internal/proxy"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type Options struct {
	ConfigPath  string
	HTTPListen  string
	HTTPSListen string
	AdminListen string
}

type runtime struct {
	handler atomic.Value
	cfg     atomic.Value
}

func Run(cfg *config.Config, opts Options) error {
	applyEnv(cfg)
	logr := logging.New(cfg.Log.Format, cfg.Log.Output)
	metricsReg := metrics.NewRegistry()

	rt := &runtime{}
	if err := rt.reload(cfg, opts, logr, metricsReg); err != nil {
		return err
	}

	httpsSrv := &http.Server{
		Addr:              opts.HTTPSListen,
		Handler:           rt.publicHandler(logr, metricsReg),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    cfg.Limits.MaxHeaderBytes,
	}

	autocertMgr, err := newAutocert(cfg)
	if err != nil {
		return err
	}
	httpsSrv.TLSConfig = autocertMgr.TLSConfig()

	httpSrv := &http.Server{
		Addr:              opts.HTTPListen,
		Handler:           autocertMgr.HTTPHandler(http.HandlerFunc(redirectToHTTPS(opts.HTTPSListen))),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    cfg.Limits.MaxHeaderBytes,
	}

	adminSrv := &http.Server{
		Addr:              opts.AdminListen,
		Handler:           rt.adminHandler(opts.ConfigPath, logr, metricsReg),
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go handleSignals(rt, opts, logr, metricsReg)

	errCh := make(chan error, 3)
	go func() {
		log.Printf("https listening on %s", opts.HTTPSListen)
		errCh <- httpsSrv.ListenAndServeTLS("", "")
	}()
	go func() {
		log.Printf("http listening on %s", opts.HTTPListen)
		errCh <- httpSrv.ListenAndServe()
	}()
	go func() {
		log.Printf("admin listening on %s", opts.AdminListen)
		errCh <- adminSrv.ListenAndServe()
	}()

	err = <-errCh
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpsSrv.Shutdown(ctx)
	_ = httpSrv.Shutdown(ctx)
	_ = adminSrv.Shutdown(ctx)
	return err
}

func handleSignals(rt *runtime, opts Options, logr *logging.Logger, metricsReg *metrics.Registry) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	for range ch {
		cfg, err := config.LoadConfig(opts.ConfigPath)
		if err != nil {
			logr.Write(logging.Entry{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Status: 500, URI: "reload", Route: "sighup", Blocked: true})
			continue
		}
		applyEnv(cfg)
		if err := rt.reload(cfg, opts, logr, metricsReg); err != nil {
			logr.Write(logging.Entry{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Status: 500, URI: "reload", Route: "sighup", Blocked: true})
		}
	}
}

func (rt *runtime) reload(cfg *config.Config, opts Options, logr *logging.Logger, metricsReg *metrics.Registry) error {
	h, err := newHandler(cfg, logr, metricsReg)
	if err != nil {
		return err
	}
	rt.handler.Store(h)
	rt.cfg.Store(cfg)
	return nil
}

func (rt *runtime) publicHandler(logr *logging.Logger, metricsReg *metrics.Registry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := rt.handler.Load().(*handler)
		h.ServeHTTP(w, r)
	})
}

func (rt *runtime) adminHandler(configPath string, logr *logging.Logger, metricsReg *metrics.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		metricsReg.WritePrometheus(w)
	})
	mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		cfg, err := config.LoadConfig(configPath)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		applyEnv(cfg)
		if err := rt.reload(cfg, Options{ConfigPath: configPath}, logr, metricsReg); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("reloaded"))
	})
	return mux
}

func authorized(r *http.Request) bool {
	token := os.Getenv("ADMIN_TOKEN")
	if token == "" {
		return false
	}
	auth := r.Header.Get("Authorization")
	return auth == "Bearer "+token
}

func newAutocert(cfg *config.Config) (*autocert.Manager, error) {
	if cfg.ACME.Email == "" {
		return nil, fmt.Errorf("ACME_EMAIL is required")
	}
	var hosts []string
	for _, srv := range cfg.Servers {
		hosts = append(hosts, srv.Hostname)
	}
	mgr := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cfg.ACME.StoragePath),
		Email:      cfg.ACME.Email,
		HostPolicy: autocert.HostWhitelist(hosts...),
	}
	if cfg.ACME.CA != "" || cfg.ACME.Staging {
		url := cfg.ACME.CA
		if url == "" && cfg.ACME.Staging {
			url = "https://acme-staging-v02.api.letsencrypt.org/directory"
		}
		mgr.Client = &acme.Client{DirectoryURL: url}
	}
	return mgr, nil
}

type handler struct {
	proxies     map[string]*proxy.UpstreamProxy
	hosts       map[string][]routeHandle
	log         *logging.Logger
	metrics     *metrics.Registry
	rateLimiter *limits.RateLimiter
	connLimiter *limits.ConnLimiter
	risk        *challenge.RiskTracker
	challenge   *challenge.Manager
	challengeEx []string
	limits      config.LimitsConfig
	allowlist   *ipAllowlist
}

type routeHandle struct {
	matcher     *config.Matcher
	stripPrefix string
	upstream    string
	proxy       *proxy.UpstreamProxy
	matcherName string
}

func newHandler(cfg *config.Config, logr *logging.Logger, metricsReg *metrics.Registry) (*handler, error) {
	proxies := map[string]*proxy.UpstreamProxy{}
	hosts := map[string][]routeHandle{}
	for _, srv := range cfg.Servers {
		var handles []routeHandle
		for _, h := range srv.Handles {
			p, ok := proxies[h.Upstream]
			if !ok {
				proxyInstance, err := proxy.NewUpstreamProxy(h.Upstream, 10*time.Second)
				if err != nil {
					return nil, err
				}
				proxies[h.Upstream] = proxyInstance
				p = proxyInstance
			}
			handles = append(handles, routeHandle{
				matcher:     h.Matcher,
				stripPrefix: h.StripPrefix,
				upstream:    h.Upstream,
				proxy:       p,
				matcherName: h.MatcherName,
			})
		}
		hosts[strings.ToLower(srv.Hostname)] = handles
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}

	var challengeMgr *challenge.Manager
	if cfg.Challenge.Enabled {
		challengeMgr = challenge.NewManager(secret, time.Duration(cfg.Challenge.CookieTTLSeconds)*time.Second)
		challengeMgr.BindIP = cfg.Challenge.BindIP
		challengeMgr.BindUA = cfg.Challenge.BindUA
	}

	h := &handler{
		proxies:     proxies,
		hosts:       hosts,
		log:         logr,
		metrics:     metricsReg,
		rateLimiter: limits.NewRateLimiter(cfg.Limits.RPS, cfg.Limits.Burst, 10*time.Minute),
		connLimiter: limits.NewConnLimiter(cfg.Limits.ConnLimit, cfg.Limits.WSConnLimit),
		risk: challenge.NewRiskTracker(
			cfg.Limits.RiskThreshold,
			time.Duration(cfg.Limits.RiskStatusWindow)*time.Second,
			time.Duration(cfg.Limits.RiskTTLSeconds)*time.Second,
			cfg.Limits.BanAfter,
			time.Duration(cfg.Limits.BanSeconds)*time.Second,
		),
		challenge:   challengeMgr,
		challengeEx: cfg.Challenge.ExemptGlobs,
		limits:      cfg.Limits,
		allowlist:   nil,
	}

	allowlist, err := newIPAllowlist(cfg.Limits.WhitelistIPs)
	if err != nil {
		return nil, err
	}
	h.allowlist = allowlist

	go h.cleanupLoop()
	return h, nil
}

func (h *handler) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		h.rateLimiter.Cleanup()
		h.risk.Cleanup()
		if h.challenge != nil {
			h.challenge.Cleanup()
		}
	}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	atomic.AddUint64(&h.metrics.Requests, 1)

	ctx := &requestContext{}
	rec := &responseRecorder{ResponseWriter: w, status: 0}
	defer func() {
		if ctx.Status == 0 {
			ctx.Status = rec.status
		}
		if ctx.Status == 0 {
			ctx.Status = http.StatusOK
		}
		if rec.status == 0 {
			rec.status = ctx.Status
		}
		h.metrics.ObserveLatency(time.Since(start))
		if ctx.Status >= 500 {
			atomic.AddUint64(&h.metrics.UpstreamErrors, 1)
		}
		h.finishLog(rec, r, ctx, start)
	}()

	if r.URL.Path == "/healthz" {
		rec.WriteHeader(http.StatusOK)
		_, _ = rec.Write([]byte("ok"))
		ctx.Status = http.StatusOK
		return
	}
	if r.URL.Path == "/metrics" {
		rec.Header().Set("Content-Type", "text/plain; version=0.0.4")
		h.metrics.WritePrometheus(rec)
		ctx.Status = http.StatusOK
		return
	}

	ip := limits.ClientIP(r.RemoteAddr)
	isTrustedIP := h.allowlist.Contains(ip)

	if len(r.URL.RequestURI()) > h.limits.MaxURLLength && !isTrustedIP {
		ctx.Blocked = true
		h.risk.RegisterLimitViolation(ip)
		h.writeResponse(rec, r, ctx, http.StatusRequestURITooLong, "uri too long")
		return
	}

	if !isACMEPath(r.URL.Path) {
		if !isTrustedIP {
			if banned, until := h.risk.IsBanned(ip); banned {
				ctx.Blocked = true
				h.writeResponse(rec, r, ctx, http.StatusForbidden, fmt.Sprintf("ip banned until %s", until.UTC().Format(time.RFC3339)))
				return
			}
		}
		if h.challenge != nil && r.URL.Path == h.challenge.VerifyPath {
			h.routeRequest(rec, r, ctx)
			return
		}
		if !isTrustedIP && !h.rateLimiter.Allow(ip) {
			ctx.RateLimited = true
			atomic.AddUint64(&h.metrics.RateLimited, 1)
			h.risk.Penalize(ip, 2)
			if banned, until := h.risk.RegisterLimitViolation(ip); banned {
				ctx.Blocked = true
				h.writeResponse(rec, r, ctx, http.StatusForbidden, fmt.Sprintf("ip banned until %s", until.UTC().Format(time.RFC3339)))
				return
			}
			h.writeResponse(rec, r, ctx, http.StatusTooManyRequests, "rate limited")
			return
		}

		ws := isWebSocket(r)
		if !isTrustedIP && !h.connLimiter.Allow(ip, ws) {
			ctx.Blocked = true
			if banned, until := h.risk.RegisterLimitViolation(ip); banned {
				h.writeResponse(rec, r, ctx, http.StatusForbidden, fmt.Sprintf("ip banned until %s", until.UTC().Format(time.RFC3339)))
				return
			}
			h.writeResponse(rec, r, ctx, http.StatusTooManyRequests, "too many connections")
			return
		}
		if ws {
			atomic.AddInt64(&h.metrics.WSActive, 1)
		}
		defer func() {
			if !isTrustedIP {
				h.connLimiter.Done(ip, ws)
			}
			if ws {
				atomic.AddInt64(&h.metrics.WSActive, -1)
			}
		}()

		if !isTrustedIP {
			h.risk.UpdateRequest(ip, r)
		}
		if !isTrustedIP && h.challengeNeeded(r, ip) {
			ctx.ChallengeApplied = true
			atomic.AddUint64(&h.metrics.ChallengeServed, 1)
			rec.Header().Set("Content-Type", "text/html; charset=utf-8")
			rec.WriteHeader(http.StatusOK)
			_, _ = rec.Write([]byte(h.challenge.InterstitialHTML(ip, r.UserAgent(), r.URL.RequestURI())))
			return
		}
	}

	if h.limits.MaxBodyBytes > 0 {
		r.Body = http.MaxBytesReader(rec, r.Body, h.limits.MaxBodyBytes)
	}

	h.routeRequest(rec, r, ctx)
	if !isACMEPath(r.URL.Path) && !isTrustedIP {
		h.risk.UpdateStatus(ip, rec.status)
	}
}

func (h *handler) routeRequest(w http.ResponseWriter, r *http.Request, ctx *requestContext) {
	if h.challenge != nil && r.URL.Path == h.challenge.VerifyPath {
		h.handleVerify(w, r, ctx)
		return
	}

	host := strings.ToLower(r.Host)
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	handles := h.hosts[host]
	if handles == nil {
		ctx.Blocked = true
		h.writeResponse(w, r, ctx, http.StatusNotFound, "unknown host")
		return
	}

	// Hard fallback for cabinet host: route API/WS directly to bot upstream before generic handlers.
	if host == "cabinet.astracat.ru" {
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api" {
			p := h.proxies["remnawave_bot:8080"]
			if p == nil {
				created, err := proxy.NewUpstreamProxy("remnawave_bot:8080", 10*time.Second)
				if err == nil {
					p = created
				}
			}
			if p != nil {
				ctx.Route = "api_force"
				ctx.Upstream = "remnawave_bot:8080"
				r.URL.Path = strings.TrimPrefix(r.URL.Path, "/api")
				if r.URL.Path == "" {
					r.URL.Path = "/"
				}
				p.ServeHTTP(w, r)
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/cabinet/ws") {
			p := h.proxies["remnawave_bot:8080"]
			if p == nil {
				created, err := proxy.NewUpstreamProxy("remnawave_bot:8080", 10*time.Second)
				if err == nil {
					p = created
				}
			}
			if p != nil {
				ctx.Route = "ws_force"
				ctx.Upstream = "remnawave_bot:8080"
				p.ServeHTTP(w, r)
				return
			}
		}
	}

	// Fast-path for API and WS prefixes so dynamic endpoints are not sent to frontend fallback.
	if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api" {
		for _, handle := range handles {
			if handle.stripPrefix == "/api" || strings.Contains(handle.upstream, "remnawave_bot:8080") {
				ctx.Route = handle.matcherName
				ctx.Upstream = handle.upstream
				r.URL.Path = strings.TrimPrefix(r.URL.Path, "/api")
				if r.URL.Path == "" {
					r.URL.Path = "/"
				}
				handle.proxy.ServeHTTP(w, r)
				return
			}
		}
	}
	if strings.HasPrefix(r.URL.Path, "/cabinet/ws") {
		for _, handle := range handles {
			if handle.matcher != nil && strings.Contains(strings.TrimSpace(handle.matcher.PathGlob), "/cabinet/ws") {
				ctx.Route = handle.matcherName
				ctx.Upstream = handle.upstream
				handle.proxy.ServeHTTP(w, r)
				return
			}
		}
	}

	for _, handle := range handles {
		if handle.matcher != nil && !matchPath(handle.matcher.PathGlob, r.URL.Path) {
			continue
		}
		ctx.Route = handle.matcherName
		ctx.Upstream = handle.upstream
		if handle.stripPrefix != "" {
			if strings.HasPrefix(r.URL.Path, handle.stripPrefix) {
				r.URL.Path = strings.TrimPrefix(r.URL.Path, handle.stripPrefix)
				if r.URL.Path == "" {
					r.URL.Path = "/"
				}
			}
		}
		handle.proxy.ServeHTTP(w, r)
		return
	}

	ctx.Blocked = true
	h.writeResponse(w, r, ctx, http.StatusNotFound, "no route")
}

func (h *handler) handleVerify(w http.ResponseWriter, r *http.Request, ctx *requestContext) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		ctx.Blocked = true
		h.writeResponse(w, r, ctx, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := r.ParseForm(); err != nil {
		ctx.Blocked = true
		h.writeResponse(w, r, ctx, http.StatusBadRequest, "invalid form")
		return
	}

	ip := limits.ClientIP(r.RemoteAddr)
	ua := r.UserAgent()
	token := r.FormValue("token")
	answer := r.FormValue("answer")
	retryURL := r.FormValue("url")
	if retryURL == "" {
		retryURL = "/"
	}

	returnURL, ok := h.challenge.VerifyCaptcha(token, answer, ip, ua)
	if !ok {
		ctx.ChallengeApplied = true
		atomic.AddUint64(&h.metrics.ChallengeServed, 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		ctx.Status = http.StatusForbidden
		_, _ = w.Write([]byte(h.challenge.InterstitialHTML(ip, ua, retryURL)))
		return
	}

	exp := time.Now().Add(h.challenge.CookieTTL)
	value := h.challenge.CookieValue(ip, ua, exp)

	cookie := &http.Cookie{
		Name:     h.challenge.CookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		Expires:  exp,
	}
	http.SetCookie(w, cookie)

	ctx.Status = http.StatusFound
	http.Redirect(w, r, returnURL, http.StatusFound)
}

func (h *handler) challengeNeeded(r *http.Request, ip string) bool {
	if !h.challengeEnabled() {
		return false
	}
	if isExemptPath(r.URL.Path, h.challengeEx) {
		return false
	}
	if r.URL.Path == h.challenge.VerifyPath {
		return false
	}

	cookie, err := r.Cookie(h.challenge.CookieName)
	if err == nil {
		if h.challenge.VerifyCookie(ip, r.UserAgent(), cookie.Value) {
			return false
		}
	}

	return !h.risk.Allowed(ip)
}

func (h *handler) challengeEnabled() bool {
	return h.challenge != nil
}

func (h *handler) writeResponse(w http.ResponseWriter, r *http.Request, ctx *requestContext, status int, msg string) {
	ctx.Status = status
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}

func (h *handler) finishLog(w http.ResponseWriter, r *http.Request, ctx *requestContext, start time.Time) {
	entry := logging.Entry{
		Timestamp:        time.Now().UTC().Format(time.RFC3339Nano),
		RemoteIP:         limits.ClientIP(r.RemoteAddr),
		Host:             r.Host,
		Method:           r.Method,
		URI:              r.URL.RequestURI(),
		Status:           ctx.Status,
		LatencyMS:        time.Since(start).Milliseconds(),
		Upstream:         ctx.Upstream,
		Route:            ctx.Route,
		ChallengeApplied: ctx.ChallengeApplied,
		RateLimited:      ctx.RateLimited,
		Blocked:          ctx.Blocked,
	}
	h.log.Write(entry)
}

func matchPath(glob string, p string) bool {
	glob = strings.TrimSpace(glob)
	p = strings.TrimSpace(p)
	if glob == "" {
		return true
	}
	// Prefix match for common patterns like /api/* or /cabinet/ws*
	if strings.HasSuffix(glob, "/*") {
		prefix := strings.TrimSuffix(glob, "*")
		return strings.HasPrefix(p, prefix)
	}
	if strings.HasSuffix(glob, "*") && !strings.Contains(glob, "?") && !strings.Contains(glob, "[") {
		prefix := strings.TrimSuffix(glob, "*")
		return strings.HasPrefix(p, prefix)
	}
	if strings.HasPrefix(glob, "*.") && strings.Contains(p, ".") {
		return strings.HasSuffix(p, strings.TrimPrefix(glob, "*"))
	}
	matched, err := path.Match(glob, p)
	if err != nil {
		return false
	}
	return matched
}

func isExemptPath(p string, globs []string) bool {
	for _, g := range globs {
		if matchPath(g, p) {
			return true
		}
	}
	return false
}

func isACMEPath(p string) bool {
	return strings.HasPrefix(p, "/.well-known/acme-challenge/")
}

func isWebSocket(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") && strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

type requestContext struct {
	Upstream         string
	Route            string
	ChallengeApplied bool
	RateLimited      bool
	Blocked          bool
	Status           int
}

type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func redirectToHTTPS(httpsListen string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}
		port := strings.TrimPrefix(httpsListen, ":")
		if port != "" && port != "443" {
			host = host + ":" + port
		}
		target := "https://" + host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	}
}

func applyEnv(cfg *config.Config) {
	if v := os.Getenv("ACME_EMAIL"); v != "" {
		cfg.ACME.Email = v
	}
	if v := os.Getenv("ACME_CA"); v != "" {
		cfg.ACME.CA = v
	}
	if v := os.Getenv("ACME_STAGING"); v != "" {
		cfg.ACME.Staging = v == "1" || strings.EqualFold(v, "true")
	}
	if v := os.Getenv("ACME_KEY_TYPE"); v != "" {
		cfg.ACME.KeyType = v
	}
	if v := os.Getenv("ACME_RENEW_WINDOW"); v != "" {
		cfg.ACME.RenewWindow = v
	}
	if v := os.Getenv("ACME_STORAGE"); v != "" {
		cfg.ACME.StoragePath = v
	}
	if v := os.Getenv("RATE_LIMIT_RPS"); v != "" {
		if f, err := parseFloat(v); err == nil {
			cfg.Limits.RPS = f
		}
	}
	if v := os.Getenv("RATE_LIMIT_BURST"); v != "" {
		if f, err := parseFloat(v); err == nil {
			cfg.Limits.Burst = f
		}
	}
	if v := os.Getenv("CONN_LIMIT"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.Limits.ConnLimit = n
		}
	}
	if v := os.Getenv("WS_CONN_LIMIT"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.Limits.WSConnLimit = n
		}
	}
	if v := os.Getenv("WHITELIST_IPS"); v != "" {
		parts := strings.Split(v, ",")
		items := make([]string, 0, len(parts))
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				items = append(items, trimmed)
			}
		}
		cfg.Limits.WhitelistIPs = items
	}
	if v := os.Getenv("MAX_BODY_BYTES"); v != "" {
		if n, err := parseInt64(v); err == nil {
			cfg.Limits.MaxBodyBytes = n
		}
	}
	if v := os.Getenv("MAX_HEADER_BYTES"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.Limits.MaxHeaderBytes = n
		}
	}
	if v := os.Getenv("MAX_URL_LENGTH"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.Limits.MaxURLLength = n
		}
	}
	if v := os.Getenv("RISK_THRESHOLD"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.Limits.RiskThreshold = n
		}
	}
	if v := os.Getenv("RISK_TTL"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.Limits.RiskTTLSeconds = n
		}
	}
	if v := os.Getenv("RISK_STATUS_WINDOW"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.Limits.RiskStatusWindow = n
		}
	}
	if v := os.Getenv("BAN_AFTER"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.Limits.BanAfter = n
		}
	}
	if v := os.Getenv("BAN_SECONDS"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.Limits.BanSeconds = n
		}
	}
	if v := os.Getenv("CHALLENGE_TTL"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.Challenge.CookieTTLSeconds = n
		}
	}
	if v := os.Getenv("CHALLENGE_BIND_IP"); v != "" {
		cfg.Challenge.BindIP = v == "1" || strings.EqualFold(v, "true")
	}
	if v := os.Getenv("CHALLENGE_BIND_UA"); v != "" {
		cfg.Challenge.BindUA = v == "1" || strings.EqualFold(v, "true")
	}
	if v := os.Getenv("CHALLENGE_ENABLED"); v != "" {
		cfg.Challenge.Enabled = v == "1" || strings.EqualFold(v, "true")
	}
}

func parseInt(s string) (int, error) {
	var v int
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid int")
		}
		v = v*10 + int(r-'0')
	}
	return v, nil
}

func parseInt64(s string) (int64, error) {
	var v int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid int")
		}
		v = v*10 + int64(r-'0')
	}
	return v, nil
}

func parseFloat(s string) (float64, error) {
	var v float64
	var frac float64 = 0.1
	seenDot := false
	for _, r := range s {
		if r == '.' {
			if seenDot {
				return 0, fmt.Errorf("invalid float")
			}
			seenDot = true
			continue
		}
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid float")
		}
		if !seenDot {
			v = v*10 + float64(r-'0')
			continue
		}
		v += float64(r-'0') * frac
		frac *= 0.1
	}
	return v, nil
}

type ipAllowlist struct {
	exact map[string]struct{}
	nets  []*net.IPNet
}

func newIPAllowlist(values []string) (*ipAllowlist, error) {
	a := &ipAllowlist{
		exact: map[string]struct{}{},
		nets:  make([]*net.IPNet, 0),
	}
	for _, raw := range values {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if strings.Contains(v, "/") {
			_, network, err := net.ParseCIDR(v)
			if err != nil {
				return nil, fmt.Errorf("invalid whitelist cidr: %s", v)
			}
			a.nets = append(a.nets, network)
			continue
		}
		ip := net.ParseIP(v)
		if ip == nil {
			return nil, fmt.Errorf("invalid whitelist ip: %s", v)
		}
		a.exact[ip.String()] = struct{}{}
	}
	return a, nil
}

func (a *ipAllowlist) Contains(ipStr string) bool {
	if a == nil {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	if _, ok := a.exact[ip.String()]; ok {
		return true
	}
	for _, network := range a.nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
