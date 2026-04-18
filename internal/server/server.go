package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"astracat-protect/internal/ai"
	"astracat-protect/internal/autoshield"
	"astracat-protect/internal/bot"
	"astracat-protect/internal/challenge"
	"astracat-protect/internal/config"
	"astracat-protect/internal/limits"
	"astracat-protect/internal/logging"
	"astracat-protect/internal/metrics"
	"astracat-protect/internal/proxy"
	"astracat-protect/internal/threatintel"
	"astracat-protect/internal/waf"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
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
	tls     atomic.Value
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
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    cfg.Limits.MaxHeaderBytes,
	}

	httpsSrv.TLSConfig = rt.dynamicTLSConfig()

	h3Listen := strings.TrimSpace(cfg.HTTP3.Listen)
	if h3Listen == "" {
		h3Listen = opts.HTTPSListen
	}
	var h3Srv *http3.Server
	if cfg.HTTP3.Enabled {
		h3Srv = &http3.Server{
			Addr:      h3Listen,
			Handler:   rt.publicHandler(logr, metricsReg),
			TLSConfig: rt.dynamicTLSConfig(),
			QUICConfig: &quic.Config{
				MaxIdleTimeout: 60 * time.Second,
			},
		}
	}

	httpSrv := &http.Server{
		Addr:              opts.HTTPListen,
		Handler:           rt.httpHandler(opts.HTTPSListen),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    cfg.Limits.MaxHeaderBytes,
	}

	adminSrv := &http.Server{
		Addr:              opts.AdminListen,
		Handler:           rt.adminHandler(opts.ConfigPath, opts, logr, metricsReg),
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go handleSignals(rt, opts, logr, metricsReg)

	errCh := make(chan error, 4)
	go func() {
		log.Printf("https listening on %s", opts.HTTPSListen)
		errCh <- httpsSrv.ListenAndServeTLS("", "")
	}()
	if h3Srv != nil {
		go func() {
			log.Printf("http3 listening on %s", h3Listen)
			errCh <- h3Srv.ListenAndServe()
		}()
	}
	go func() {
		log.Printf("http listening on %s", opts.HTTPListen)
		errCh <- httpSrv.ListenAndServe()
	}()
	go func() {
		log.Printf("admin listening on %s", opts.AdminListen)
		errCh <- adminSrv.ListenAndServe()
	}()

	err := <-errCh
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpsSrv.Shutdown(ctx)
	if h3Srv != nil {
		_ = h3Srv.Close()
	}
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
	tlsState, err := newTLSRuntimeState(cfg, opts.HTTPSListen)
	if err != nil {
		return err
	}
	h, err := newHandler(cfg, logr, metricsReg)
	if err != nil {
		return err
	}
	if prev, ok := rt.handler.Load().(*handler); ok && prev != nil {
		prev.Close()
	}
	rt.handler.Store(h)
	rt.cfg.Store(cfg)
	rt.tls.Store(tlsState)
	return nil
}

func (rt *runtime) publicHandler(logr *logging.Logger, metricsReg *metrics.Registry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := rt.handler.Load().(*handler)
		h.ServeHTTP(w, r)
	})
}

func (rt *runtime) httpHandler(httpsListen string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, _ := rt.tls.Load().(*tlsRuntimeState)
		if state != nil && state.httpHandler != nil {
			state.httpHandler.ServeHTTP(w, r)
			return
		}
		redirectToHTTPS(httpsListen)(w, r)
	})
}

func (rt *runtime) dynamicTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h3", "h2", "http/1.1", acme.ALPNProto},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			state, _ := rt.tls.Load().(*tlsRuntimeState)
			if state == nil {
				return nil, fmt.Errorf("tls runtime is not ready")
			}
			return state.getCertificate(hello)
		},
	}
}

func (rt *runtime) adminHandler(configPath string, opts Options, logr *logging.Logger, metricsReg *metrics.Registry) http.Handler {
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
		reloadOpts := opts
		reloadOpts.ConfigPath = configPath
		if err := rt.reload(cfg, reloadOpts, logr, metricsReg); err != nil {
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

type tlsRuntimeState struct {
	httpHandler http.Handler
	autocert    *autocert.Manager
	dns01       *dns01CertManager
	certByHost  map[string]*tls.Certificate
	defaultCert *tls.Certificate
}

func newTLSRuntimeState(cfg *config.Config, httpsListen string) (*tlsRuntimeState, error) {
	state := &tlsRuntimeState{
		certByHost: map[string]*tls.Certificate{},
	}

	acmeHosts := make([]string, 0, len(cfg.Servers))
	for _, srv := range cfg.Servers {
		host := normalizeHost(srv.Hostname)
		if host == "" {
			continue
		}
		if srv.TLS == nil {
			acmeHosts = append(acmeHosts, host)
			continue
		}
		certPath := strings.TrimSpace(srv.TLS.CertFile)
		keyPath := strings.TrimSpace(srv.TLS.KeyFile)
		if certPath == "" || keyPath == "" {
			return nil, fmt.Errorf("server %s: tls cert_file and key_file are required together", srv.Hostname)
		}
		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("server %s: cannot load certificate pair: %w", srv.Hostname, err)
		}
		state.certByHost[host] = &pair
		if state.defaultCert == nil {
			state.defaultCert = &pair
		}
	}

	redirect := http.HandlerFunc(redirectToHTTPS(httpsListen))
	if cfg.ACME.DNS01Enabled {
		dnsMgr, err := newDNS01CertManager(cfg.ACME, acmeHosts)
		if err != nil {
			return nil, err
		}
		state.dns01 = dnsMgr
		state.httpHandler = redirect
	} else {
		acmeMgr, err := newAutocert(cfg, acmeHosts)
		if err != nil {
			return nil, err
		}
		state.autocert = acmeMgr
		if acmeMgr != nil {
			state.httpHandler = acmeMgr.HTTPHandler(redirect)
		} else {
			state.httpHandler = redirect
		}
	}
	return state, nil
}

func (s *tlsRuntimeState) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if s == nil {
		return nil, fmt.Errorf("tls runtime is not initialized")
	}

	host := normalizeHost(hello.ServerName)
	if cert := s.lookupCustomCert(host); cert != nil {
		return cert, nil
	}
	if s.dns01 != nil {
		if cert, err := s.dns01.GetCertificate(host); err == nil && cert != nil {
			return cert, nil
		}
	}
	if s.autocert != nil {
		return s.autocert.GetCertificate(hello)
	}
	if s.defaultCert != nil {
		return s.defaultCert, nil
	}
	return nil, fmt.Errorf("no certificate configured for host %q", host)
}

func (s *tlsRuntimeState) lookupCustomCert(host string) *tls.Certificate {
	if s == nil || host == "" {
		return nil
	}
	if cert, ok := s.certByHost[host]; ok {
		return cert
	}
	parts := strings.Split(host, ".")
	if len(parts) > 2 {
		wildcard := "*." + strings.Join(parts[1:], ".")
		if cert, ok := s.certByHost[wildcard]; ok {
			return cert
		}
	}
	return nil
}

func newAutocert(cfg *config.Config, hosts []string) (*autocert.Manager, error) {
	if len(hosts) == 0 && !cfg.ACME.OnDemandTLS {
		return nil, nil
	}
	if cfg.ACME.Email == "" {
		return nil, fmt.Errorf("ACME_EMAIL is required for automatic TLS")
	}
	mgr := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(cfg.ACME.StoragePath),
		Email:  cfg.ACME.Email,
	}
	if !cfg.ACME.OnDemandTLS && len(hosts) > 0 {
		mgr.HostPolicy = autocert.HostWhitelist(hosts...)
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

type dns01CertManager struct {
	storagePath string
	issueHook   string
	renewHook   string
	timeout     time.Duration
	renewBefore time.Duration

	mu       sync.Mutex
	inflight map[string]chan struct{}
}

func newDNS01CertManager(cfg config.ACMEConfig, hosts []string) (*dns01CertManager, error) {
	if !cfg.DNS01Enabled {
		return nil, nil
	}
	if strings.TrimSpace(cfg.DNSIssueHook) == "" {
		return nil, fmt.Errorf("acme.dns_issue_hook is required when dns01_enabled=true")
	}
	storagePath := strings.TrimSpace(cfg.DNSStoragePath)
	if storagePath == "" {
		storagePath = filepath.Join(cfg.StoragePath, "dns01")
	}
	if err := os.MkdirAll(storagePath, 0o755); err != nil {
		return nil, err
	}
	mgr := &dns01CertManager{
		storagePath: storagePath,
		issueHook:   cfg.DNSIssueHook,
		renewHook:   cfg.DNSRenewHook,
		timeout:     time.Duration(maxInt(cfg.DNSHookTimeoutSec, 1)) * time.Second,
		renewBefore: parseRenewBefore(cfg.RenewWindow),
		inflight:    map[string]chan struct{}{},
	}
	for _, host := range hosts {
		host = normalizeHost(host)
		if host == "" {
			continue
		}
		// Warmup: if no cert exists yet, try issuing it once during startup.
		_, _ = mgr.GetCertificate(host)
	}
	return mgr, nil
}

func (m *dns01CertManager) GetCertificate(host string) (*tls.Certificate, error) {
	if m == nil {
		return nil, fmt.Errorf("dns01 manager is not initialized")
	}
	host = normalizeHost(host)
	if host == "" {
		return nil, fmt.Errorf("empty sni host")
	}
	for {
		cert, notAfter, err := m.loadFromDisk(host)
		if err == nil && cert != nil && time.Until(notAfter) > m.renewBefore {
			return cert, nil
		}

		waitCh, shouldIssue := m.startIssue(host)
		if !shouldIssue {
			<-waitCh
			continue
		}
		issueErr := m.issueOrRenew(host, cert != nil && time.Until(notAfter) <= m.renewBefore)
		m.finishIssue(host)
		if issueErr != nil {
			return nil, issueErr
		}
	}
}

func (m *dns01CertManager) startIssue(host string) (<-chan struct{}, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ch, ok := m.inflight[host]; ok {
		return ch, false
	}
	ch := make(chan struct{})
	m.inflight[host] = ch
	return ch, true
}

func (m *dns01CertManager) finishIssue(host string) {
	m.mu.Lock()
	ch, ok := m.inflight[host]
	if ok {
		delete(m.inflight, host)
	}
	m.mu.Unlock()
	if ok {
		close(ch)
	}
}

func (m *dns01CertManager) issueOrRenew(host string, renew bool) error {
	certPath, keyPath := findDomainCertPair(m.storagePath, host)
	if certPath == "" {
		certPath = filepath.Join(m.storagePath, host+".crt")
	}
	if keyPath == "" {
		keyPath = filepath.Join(m.storagePath, host+".key")
	}
	hook := strings.TrimSpace(m.issueHook)
	if renew {
		if v := strings.TrimSpace(m.renewHook); v != "" {
			hook = v
		}
	}
	if hook == "" {
		return fmt.Errorf("dns01 hook command is empty")
	}

	cmd := hook
	cmd = strings.ReplaceAll(cmd, "{domain}", shellEscape(host))
	cmd = strings.ReplaceAll(cmd, "{storage}", shellEscape(m.storagePath))
	cmd = strings.ReplaceAll(cmd, "{cert}", shellEscape(certPath))
	cmd = strings.ReplaceAll(cmd, "{key}", shellEscape(keyPath))

	ctx, cancel := context.WithTimeout(context.Background(), m.timeout)
	defer cancel()
	proc := exec.CommandContext(ctx, "/bin/sh", "-lc", cmd)
	var stderr bytes.Buffer
	proc.Stderr = &stderr
	if err := proc.Run(); err != nil {
		return fmt.Errorf("dns01 hook failed for %s: %w: %s", host, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (m *dns01CertManager) loadFromDisk(host string) (*tls.Certificate, time.Time, error) {
	certPath, keyPath := findDomainCertPair(m.storagePath, host)
	if certPath == "" || keyPath == "" {
		return nil, time.Time{}, fmt.Errorf("no certificate files for %s", host)
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(pair.Certificate) == 0 {
		return nil, time.Time{}, fmt.Errorf("certificate chain is empty")
	}
	parsed, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, time.Time{}, err
	}
	pair.Leaf = parsed
	return &pair, parsed.NotAfter, nil
}

func parseRenewBefore(value string) time.Duration {
	v := strings.TrimSpace(value)
	if v == "" {
		return 30 * 24 * time.Hour
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 30 * 24 * time.Hour
	}
	return d
}

func normalizeHost(v string) string {
	h := strings.ToLower(strings.TrimSpace(v))
	h = strings.TrimSuffix(h, ".")
	if idx := strings.Index(h, ":"); idx != -1 {
		h = h[:idx]
	}
	return h
}

type handler struct {
	proxies            map[string]*proxy.UpstreamProxy
	hosts              map[string][]routeHandle
	log                *logging.Logger
	metrics            *metrics.Registry
	rateLimiter        *limits.RateLimiter
	connLimiter        *limits.ConnLimiter
	risk               *challenge.RiskTracker
	challenge          *challenge.Manager
	challengeEx        []string
	autoShield         *autoshield.Engine
	autoShieldDefault  bool
	autoShieldByHost   map[string]bool
	threatIntel        *threatintel.Engine
	botMgmt            *bot.Engine
	waf                *waf.Engine
	ai                 *ai.Engine
	wafEx              []string
	wafExHosts         map[string]struct{}
	wafExRuleIDs       map[string]struct{}
	wafExRuleIDsByGlob map[string]map[string]struct{}
	limits             config.LimitsConfig
	allowlist          *ipAllowlist
	routeRatePolicies  []routeRatePolicy
	globalRatePenalty  *limits.PenaltyBox
	wafPenaltySeconds  int
}

type routeRatePolicy struct {
	name    string
	globs   []string
	keyMode string
	limiter *limits.RateLimiter
	penalty *limits.PenaltyBox
}

type routeHandle struct {
	matcher     *config.Matcher
	stripPrefix string
	upstream    string
	upstreams   []string
	pool        *proxy.Pool
	mode        string
	lbPolicy    string
	matcherName string
}

func newHandler(cfg *config.Config, logr *logging.Logger, metricsReg *metrics.Registry) (*handler, error) {
	proxies := map[string]*proxy.UpstreamProxy{}
	hosts := map[string][]routeHandle{}
	autoShieldByHost := map[string]bool{}
	autoShieldHasEnabledOverride := false
	for _, srv := range cfg.Servers {
		host := normalizeHost(srv.Hostname)
		if srv.AutoShieldEnabled != nil && host != "" {
			autoShieldByHost[host] = *srv.AutoShieldEnabled
			if *srv.AutoShieldEnabled {
				autoShieldHasEnabledOverride = true
			}
		}
		var handles []routeHandle
		for _, h := range srv.Handles {
			upstreams := collectHandleUpstreams(h)
			if len(upstreams) == 0 {
				return nil, fmt.Errorf("server %s: handle has no upstreams", srv.Hostname)
			}
			poolBackends := make([]*proxy.UpstreamProxy, 0, len(upstreams))
			for _, upstream := range upstreams {
				p, ok := proxies[upstream]
				if !ok {
					proxyInstance, err := proxy.NewUpstreamProxy(upstream, 2*time.Second, 10*time.Second)
					if err != nil {
						return nil, err
					}
					proxies[upstream] = proxyInstance
					p = proxyInstance
				}
				poolBackends = append(poolBackends, p)
			}
			pool := proxy.NewPool(h.LBPolicy, poolBackends)
			handles = append(handles, routeHandle{
				matcher:     h.Matcher,
				stripPrefix: h.StripPrefix,
				upstream:    upstreams[0],
				upstreams:   upstreams,
				pool:        pool,
				mode:        normalizeRouteMode(h.Mode),
				lbPolicy:    normalizeLBPolicy(h.LBPolicy),
				matcherName: h.MatcherName,
			})
		}
		hosts[host] = handles
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
	wafRules := make([]waf.RuleConfig, 0, len(cfg.WAF.Rules))
	for _, rc := range cfg.WAF.Rules {
		wafRules = append(wafRules, waf.RuleConfig{
			ID:          rc.ID,
			Description: rc.Description,
			Pattern:     rc.Pattern,
			Targets:     rc.Targets,
			Score:       rc.Score,
			Phase:       rc.Phase,
			Action:      rc.Action,
			Paranoia:    rc.Paranoia,
			Transforms:  rc.Transforms,
		})
	}
	wafEngine, err := waf.New(waf.Config{
		Enabled:                cfg.WAF.Enabled,
		Mode:                   cfg.WAF.Mode,
		ScoreThreshold:         cfg.WAF.ScoreThreshold,
		InboundThreshold:       cfg.WAF.InboundThreshold,
		ParanoiaLevel:          cfg.WAF.ParanoiaLevel,
		Presets:                cfg.WAF.Presets,
		MaxInspectBytes:        cfg.WAF.MaxInspectBytes,
		MaxValuesPerCollection: cfg.WAF.MaxValuesPerCollection,
		MaxTotalValues:         cfg.WAF.MaxTotalValues,
		MaxJSONValues:          cfg.WAF.MaxJSONValues,
		MaxBodyValues:          cfg.WAF.MaxBodyValues,
		AllowedMethods:         cfg.WAF.AllowedMethods,
		BlockedContentTypes:    cfg.WAF.BlockedContentTypes,
		Rules:                  wafRules,
	})
	if err != nil {
		return nil, err
	}
	aiEngine, err := ai.New(ai.Config{
		Enabled:               cfg.AI.Enabled,
		LearningMode:          cfg.AI.LearningMode,
		Backend:               cfg.AI.Backend,
		ModelPath:             cfg.AI.ModelPath,
		ONNXCommand:           cfg.AI.ONNXCommand,
		TFLiteCommand:         cfg.AI.TFLiteCommand,
		StatePath:             cfg.AI.StatePath,
		MinSamples:            cfg.AI.MinSamples,
		ChallengeThreshold:    cfg.AI.ChallengeThreshold,
		RateLimitThreshold:    cfg.AI.RateLimitThreshold,
		BlockThreshold:        cfg.AI.BlockThreshold,
		MaxBodyInspectBytes:   cfg.AI.MaxBodyInspectBytes,
		CommandTimeoutMS:      cfg.AI.CommandTimeoutMS,
		UpdateProfilesOnBlock: cfg.AI.UpdateProfilesOnBlock,
	})
	if err != nil {
		return nil, err
	}
	tiEngine, err := threatintel.New(cfg.ThreatIntel)
	if err != nil {
		return nil, err
	}
	botEngine, err := bot.New(cfg.BotManagement)
	if err != nil {
		if tiEngine != nil {
			tiEngine.Close()
		}
		return nil, err
	}

	wafExRuleIDs := make(map[string]struct{}, len(cfg.WAF.ExemptRuleIDs))
	for _, id := range cfg.WAF.ExemptRuleIDs {
		id = strings.TrimSpace(id)
		if id != "" {
			wafExRuleIDs[id] = struct{}{}
		}
	}
	wafExRuleIDsByGlob := make(map[string]map[string]struct{}, len(cfg.WAF.ExemptRuleIDsByGlob))
	for glob, ids := range cfg.WAF.ExemptRuleIDsByGlob {
		g := strings.TrimSpace(glob)
		if g == "" {
			continue
		}
		set := map[string]struct{}{}
		for _, id := range ids {
			id = strings.TrimSpace(id)
			if id != "" {
				set[id] = struct{}{}
			}
		}
		wafExRuleIDsByGlob[g] = set
	}
	wafExHosts := make(map[string]struct{}, len(cfg.WAF.ExemptHosts))
	for _, host := range cfg.WAF.ExemptHosts {
		h := strings.ToLower(strings.TrimSpace(host))
		if h != "" {
			wafExHosts[h] = struct{}{}
		}
	}

	autoShieldEngine := autoshield.New(autoshield.Config{
		Enabled:                 cfg.AutoShield.Enabled || autoShieldHasEnabledOverride,
		WindowSeconds:           cfg.AutoShield.WindowSeconds,
		MinRequests:             cfg.AutoShield.MinRequests,
		ProbePathThreshold:      cfg.AutoShield.ProbePathThreshold,
		HighErrorRatioPct:       cfg.AutoShield.HighErrorRatioPct,
		HighRateLimitedRatioPct: cfg.AutoShield.HighRateLimitedRatioPct,
		ScoreThreshold:          cfg.AutoShield.ScoreThreshold,
		BanSeconds:              cfg.AutoShield.BanSeconds,
	})

	defaultRatePenalty := limits.NewPenaltyBox(
		cfg.Limits.Rate429BanAfter,
		time.Duration(cfg.Limits.Rate429WindowSec)*time.Second,
		time.Duration(cfg.Limits.Rate429BanSec)*time.Second,
	)
	routeRatePolicies := make([]routeRatePolicy, 0, len(cfg.Limits.RatePolicies))
	for _, p := range cfg.Limits.RatePolicies {
		if p.RPS <= 0 || p.Burst <= 0 || len(p.PathGlobs) == 0 {
			continue
		}
		name := strings.TrimSpace(p.Name)
		if name == "" {
			name = "route"
		}
		keyMode := strings.ToLower(strings.TrimSpace(p.Key))
		if keyMode == "" {
			keyMode = "ip_route"
		}
		banAfter := p.BanAfter429
		if banAfter <= 0 {
			banAfter = cfg.Limits.Rate429BanAfter
		}
		banWindow := p.BanWindowSec
		if banWindow <= 0 {
			banWindow = cfg.Limits.Rate429WindowSec
		}
		banSec := p.BanSec
		if banSec <= 0 {
			banSec = cfg.Limits.Rate429BanSec
		}
		routeRatePolicies = append(routeRatePolicies, routeRatePolicy{
			name:    name,
			globs:   p.PathGlobs,
			keyMode: keyMode,
			limiter: limits.NewRateLimiter(p.RPS, p.Burst, 10*time.Minute),
			penalty: limits.NewPenaltyBox(banAfter, time.Duration(banWindow)*time.Second, time.Duration(banSec)*time.Second),
		})
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
		challenge:          challengeMgr,
		challengeEx:        cfg.Challenge.ExemptGlobs,
		autoShield:         autoShieldEngine,
		autoShieldDefault:  cfg.AutoShield.Enabled,
		autoShieldByHost:   autoShieldByHost,
		threatIntel:        tiEngine,
		botMgmt:            botEngine,
		waf:                wafEngine,
		ai:                 aiEngine,
		wafEx:              cfg.WAF.ExemptGlobs,
		wafExHosts:         wafExHosts,
		wafExRuleIDs:       wafExRuleIDs,
		wafExRuleIDsByGlob: wafExRuleIDsByGlob,
		limits:             cfg.Limits,
		allowlist:          nil,
		routeRatePolicies:  routeRatePolicies,
		globalRatePenalty:  defaultRatePenalty,
		wafPenaltySeconds:  cfg.Limits.WAFBanSec,
	}

	allowlist, err := newIPAllowlist(cfg.Limits.WhitelistIPs)
	if err != nil {
		if h.ai != nil {
			_ = h.ai.Close()
		}
		if h.threatIntel != nil {
			h.threatIntel.Close()
		}
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
		if h.globalRatePenalty != nil {
			h.globalRatePenalty.Cleanup()
		}
		for _, rp := range h.routeRatePolicies {
			if rp.limiter != nil {
				rp.limiter.Cleanup()
			}
			if rp.penalty != nil {
				rp.penalty.Cleanup()
			}
		}
		if h.challenge != nil {
			h.challenge.Cleanup()
		}
		if h.autoShield != nil {
			h.autoShield.Cleanup()
		}
	}
}

func (h *handler) Close() {
	if h == nil {
		return
	}
	if h.ai != nil {
		_ = h.ai.Close()
	}
	if h.threatIntel != nil {
		h.threatIntel.Close()
	}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	atomic.AddUint64(&h.metrics.Requests, 1)

	ctx := &requestContext{}
	rec := &responseRecorder{ResponseWriter: w, status: 0}
	requestPath := r.URL.Path
	requestHost := normalizeHost(r.Host)
	routeMode := h.routeModeForRequest(requestHost, requestPath)
	passThrough := routeMode == routeModePassThrough
	ctx.PassThrough = passThrough
	ip := limits.ClientIP(r.RemoteAddr)
	isTrustedIP := h.allowlist.Contains(ip)
	isTrustedBot := false
	isTrustedClient := isTrustedIP
	bypassWAFForGoodBot := false
	autoShieldEnabled := h.autoShieldEnabledForHost(requestHost)
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
		if !passThrough && !isTrustedClient && !isACMEPath(requestPath) && autoShieldEnabled && h.autoShield != nil && h.autoShield.Enabled() {
			decision := h.autoShield.Observe(autoshield.ObserveInput{
				IP:                ip,
				Path:              requestPath,
				Status:            ctx.Status,
				Blocked:           ctx.Blocked,
				RateLimited:       ctx.RateLimited,
				WAFBlocked:        ctx.WAFBlocked,
				HasUserAgent:      strings.TrimSpace(r.UserAgent()) != "",
				HasAccept:         strings.TrimSpace(r.Header.Get("Accept")) != "",
				HasAcceptLanguage: strings.TrimSpace(r.Header.Get("Accept-Language")) != "",
			})
			if decision.Banned {
				h.risk.Penalize(ip, 3)
				if h.globalRatePenalty != nil {
					if d := time.Until(decision.Until); d > 0 {
						h.globalRatePenalty.RegisterBan(ip, d)
					}
				}
			}
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

	if !passThrough && !isTrustedIP && !isACMEPath(requestPath) {
		if h.threatIntel != nil && h.threatIntel.Enabled() {
			tiDecision := h.threatIntel.Check(threatintel.CheckInput{
				IP:  ip,
				ASN: r.Header.Get(h.threatIntel.ASNHeader()),
				JA3: r.Header.Get(h.threatIntel.JA3Header()),
				TLS: tlsFingerprintFromRequest(r),
			})
			if tiDecision.Matched {
				ctx.ThreatIntelCategory = tiDecision.Category
				ctx.ThreatIntelAction = tiDecision.Action
				ctx.ThreatIntelReason = tiDecision.Reason
				ctx.ThreatIntelIndicator = tiDecision.Indicator
				switch tiDecision.Action {
				case "block":
					ctx.Blocked = true
					h.risk.Penalize(ip, 3)
					if h.wafPenaltySeconds > 0 && h.globalRatePenalty != nil {
						h.globalRatePenalty.RegisterBan(ip, time.Duration(h.wafPenaltySeconds)*time.Second)
					}
					h.writeResponse(rec, r, ctx, http.StatusForbidden, "blocked by threat-intel")
					return
				case "rate_limit":
					ctx.RateLimited = true
					atomic.AddUint64(&h.metrics.RateLimited, 1)
					h.risk.Penalize(ip, 2)
					h.writeResponse(rec, r, ctx, http.StatusTooManyRequests, "rate limited by threat-intel")
					return
				case "challenge":
					if h.challenge != nil {
						ctx.ChallengeApplied = true
						atomic.AddUint64(&h.metrics.ChallengeServed, 1)
						rec.Header().Set("Content-Type", "text/html; charset=utf-8")
						rec.WriteHeader(http.StatusOK)
						_, _ = rec.Write([]byte(h.challenge.InterstitialHTML(ip, r.UserAgent(), r.URL.RequestURI())))
						return
					}
					ctx.Blocked = true
					h.writeResponse(rec, r, ctx, http.StatusForbidden, "blocked by threat-intel challenge action")
					return
				}
			}
		}
		if h.botMgmt != nil && h.botMgmt.Enabled() {
			botDecision := h.botMgmt.Evaluate(r.UserAgent())
			if botDecision.Matched {
				ctx.BotKind = botDecision.Kind
				ctx.BotProfile = botDecision.Profile
				ctx.BotAction = botDecision.Action
				ctx.BotReason = botDecision.Reason
				if botDecision.Kind == bot.KindGood {
					isTrustedBot = true
					isTrustedClient = true
					bypassWAFForGoodBot = h.botMgmt.BypassWAFForGood()
				} else {
					switch botDecision.Action {
					case "block":
						ctx.Blocked = true
						h.risk.Penalize(ip, 3)
						if h.wafPenaltySeconds > 0 && h.globalRatePenalty != nil {
							h.globalRatePenalty.RegisterBan(ip, time.Duration(h.wafPenaltySeconds)*time.Second)
						}
						h.writeResponse(rec, r, ctx, http.StatusForbidden, "blocked by bot policy")
						return
					case "rate_limit":
						ctx.RateLimited = true
						atomic.AddUint64(&h.metrics.RateLimited, 1)
						h.risk.Penalize(ip, 2)
						h.writeResponse(rec, r, ctx, http.StatusTooManyRequests, "rate limited by bot policy")
						return
					default:
						if h.challenge != nil {
							ctx.ChallengeApplied = true
							atomic.AddUint64(&h.metrics.ChallengeServed, 1)
							rec.Header().Set("Content-Type", "text/html; charset=utf-8")
							rec.WriteHeader(http.StatusOK)
							_, _ = rec.Write([]byte(h.challenge.InterstitialHTML(ip, r.UserAgent(), r.URL.RequestURI())))
							return
						}
						ctx.Blocked = true
						h.writeResponse(rec, r, ctx, http.StatusForbidden, "blocked by bot policy challenge action")
						return
					}
				}
			}
		}
	}

	if !passThrough && !isTrustedClient {
		if status, reason := h.checkProtocolLimits(r); status != 0 {
			ctx.Blocked = true
			h.risk.RegisterLimitViolation(ip)
			h.writeResponse(rec, r, ctx, status, reason)
			return
		}
	}

	if !passThrough && !isACMEPath(requestPath) {
		if !isTrustedClient {
			if autoShieldEnabled && h.autoShield != nil && h.autoShield.Enabled() {
				if banned, until, reason := h.autoShield.IsBanned(ip); banned {
					ctx.Blocked = true
					h.writeResponse(rec, r, ctx, http.StatusForbidden, fmt.Sprintf("%s until %s", reason, until.UTC().Format(time.RFC3339)))
					return
				}
			}
			if h.globalRatePenalty != nil {
				if banned, until := h.globalRatePenalty.IsBanned(ip); banned {
					ctx.Blocked = true
					h.writeResponse(rec, r, ctx, http.StatusForbidden, fmt.Sprintf("ip penalty-banned until %s", until.UTC().Format(time.RFC3339)))
					return
				}
			}
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

		if !isTrustedClient {
			allowed, policyName, penaltyUntil := h.allowByRatePolicies(ip, requestPath)
			if !allowed {
				ctx.RateLimited = true
				if policyName != "" {
					ctx.Route = "rate:" + policyName
				}
				atomic.AddUint64(&h.metrics.RateLimited, 1)
				h.risk.Penalize(ip, 2)
				if !penaltyUntil.IsZero() {
					ctx.Blocked = true
					h.writeResponse(rec, r, ctx, http.StatusForbidden, fmt.Sprintf("rate penalty until %s", penaltyUntil.UTC().Format(time.RFC3339)))
					return
				}
				if banned, until := h.risk.RegisterLimitViolation(ip); banned {
					ctx.Blocked = true
					h.writeResponse(rec, r, ctx, http.StatusForbidden, fmt.Sprintf("ip banned until %s", until.UTC().Format(time.RFC3339)))
					return
				}
				h.writeResponse(rec, r, ctx, http.StatusTooManyRequests, "rate limited")
				return
			}
		}

		ws := isWebSocket(r)
		if !isTrustedClient && !h.connLimiter.Allow(ip, ws) {
			ctx.Blocked = true
			if banned, until := h.risk.RegisterLimitViolation(ip); banned {
				ctx.Blocked = true
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
			if !isTrustedClient {
				h.connLimiter.Done(ip, ws)
			}
			if ws {
				atomic.AddInt64(&h.metrics.WSActive, -1)
			}
		}()

		if !isTrustedClient {
			h.risk.UpdateRequest(ip, r)
		}
		if !isTrustedClient && h.ai != nil && h.ai.Enabled() {
			aiDecision, err := h.ai.Inspect(r)
			if err == nil {
				ctx.AIAction = aiDecision.Action
				ctx.AIScore = aiDecision.Score
				ctx.AIReason = aiDecision.Reason
				switch aiDecision.Action {
				case ai.ActionBlock:
					ctx.Blocked = true
					h.risk.Penalize(ip, 3)
					if h.wafPenaltySeconds > 0 && h.globalRatePenalty != nil {
						h.globalRatePenalty.RegisterBan(ip, time.Duration(h.wafPenaltySeconds)*time.Second)
					}
					h.writeResponse(rec, r, ctx, http.StatusForbidden, "blocked by ai-waf")
					return
				case ai.ActionRateLimit:
					ctx.RateLimited = true
					atomic.AddUint64(&h.metrics.RateLimited, 1)
					h.risk.Penalize(ip, 2)
					h.writeResponse(rec, r, ctx, http.StatusTooManyRequests, "rate limited by ai-waf")
					return
				case ai.ActionChallenge:
					if h.challenge != nil {
						ctx.ChallengeApplied = true
						atomic.AddUint64(&h.metrics.ChallengeServed, 1)
						rec.Header().Set("Content-Type", "text/html; charset=utf-8")
						rec.WriteHeader(http.StatusOK)
						_, _ = rec.Write([]byte(h.challenge.InterstitialHTML(ip, r.UserAgent(), r.URL.RequestURI())))
						return
					}
					ctx.Blocked = true
					h.writeResponse(rec, r, ctx, http.StatusForbidden, "blocked by ai-waf challenge action")
					return
				}
			}
		}
		applyWAF := (!isTrustedClient) || (isTrustedBot && !bypassWAFForGoodBot)
		if applyWAF && h.waf != nil && h.waf.Enabled() && !isExemptPath(requestPath, h.wafEx) && !h.isWAFHostExempt(r.Host) {
			decision, err := h.waf.Inspect(r, &waf.InspectOptions{SkipRuleIDs: h.wafRuleExclusionsForPath(requestPath)})
			if err == nil && decision.Matched {
				ctx.WAFScore = decision.Score
				ctx.WAFRules = decision.RuleIDs
				ctx.WAFReason = decision.Reason
				ctx.WAFAction = decision.Action
				switch decision.Action {
				case "rate_limit":
					ctx.RateLimited = true
					atomic.AddUint64(&h.metrics.RateLimited, 1)
					h.risk.Penalize(ip, 2)
					h.writeResponse(rec, r, ctx, http.StatusTooManyRequests, "rate limited by waf")
					return
				case "challenge":
					if h.challenge != nil {
						ctx.ChallengeApplied = true
						atomic.AddUint64(&h.metrics.ChallengeServed, 1)
						rec.Header().Set("Content-Type", "text/html; charset=utf-8")
						rec.WriteHeader(http.StatusOK)
						_, _ = rec.Write([]byte(h.challenge.InterstitialHTML(ip, r.UserAgent(), r.URL.RequestURI())))
						return
					}
					ctx.Blocked = true
					ctx.WAFBlocked = true
					atomic.AddUint64(&h.metrics.WAFBlocked, 1)
					h.risk.Penalize(ip, 3)
					if h.wafPenaltySeconds > 0 && h.globalRatePenalty != nil {
						h.globalRatePenalty.RegisterBan(ip, time.Duration(h.wafPenaltySeconds)*time.Second)
					}
					h.writeResponse(rec, r, ctx, http.StatusForbidden, "blocked by waf challenge action")
					return
				case "block":
					ctx.Blocked = true
					ctx.WAFBlocked = true
					atomic.AddUint64(&h.metrics.WAFBlocked, 1)
					h.risk.Penalize(ip, 3)
					if h.wafPenaltySeconds > 0 && h.globalRatePenalty != nil {
						h.globalRatePenalty.RegisterBan(ip, time.Duration(h.wafPenaltySeconds)*time.Second)
					}
					h.writeResponse(rec, r, ctx, http.StatusForbidden, "blocked by waf")
					return
				}
			}
		}
		if !isTrustedClient && h.challengeNeeded(r, ip) {
			ctx.ChallengeApplied = true
			atomic.AddUint64(&h.metrics.ChallengeServed, 1)
			rec.Header().Set("Content-Type", "text/html; charset=utf-8")
			rec.WriteHeader(http.StatusOK)
			_, _ = rec.Write([]byte(h.challenge.InterstitialHTML(ip, r.UserAgent(), r.URL.RequestURI())))
			return
		}
	}

	if !passThrough && h.limits.MaxBodyBytes > 0 {
		r.Body = http.MaxBytesReader(rec, r.Body, h.limits.MaxBodyBytes)
	}

	h.routeRequest(rec, r, ctx)
	if !passThrough && !isACMEPath(requestPath) && !isTrustedClient {
		h.risk.UpdateStatus(ip, rec.status)
	}
}

func (h *handler) routeRequest(w http.ResponseWriter, r *http.Request, ctx *requestContext) {
	if h.challenge != nil && r.URL.Path == h.challenge.VerifyPath {
		h.handleVerify(w, r, ctx)
		return
	}

	host := normalizeHost(r.Host)

	handles := h.hosts[host]
	if handles == nil {
		ctx.Blocked = true
		h.writeResponse(w, r, ctx, http.StatusNotFound, "unknown host")
		return
	}

	// Fast-path for API and WS prefixes so dynamic endpoints are not sent to frontend fallback.
	if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api" {
		for _, handle := range handles {
			if handle.stripPrefix == "/api" || handle.includesUpstream("remnawave_bot:8080") {
				ctx.Route = handle.matcherName
				r.URL.Path = strings.TrimPrefix(r.URL.Path, "/api")
				if r.URL.Path == "" {
					r.URL.Path = "/"
				}
				h.forwardToHandle(handle, w, r, ctx)
				return
			}
		}
	}
	if strings.HasPrefix(r.URL.Path, "/cabinet/ws") {
		for _, handle := range handles {
			if handle.matcher != nil && strings.Contains(strings.TrimSpace(handle.matcher.PathGlob), "/cabinet/ws") {
				ctx.Route = handle.matcherName
				h.forwardToHandle(handle, w, r, ctx)
				return
			}
		}
	}

	for _, handle := range handles {
		if handle.matcher != nil && !matchRoute(handle.matcher, r.URL.Path) {
			continue
		}
		ctx.Route = handle.matcherName
		if handle.stripPrefix != "" {
			if strings.HasPrefix(r.URL.Path, handle.stripPrefix) {
				r.URL.Path = strings.TrimPrefix(r.URL.Path, handle.stripPrefix)
				if r.URL.Path == "" {
					r.URL.Path = "/"
				}
			}
		}
		h.forwardToHandle(handle, w, r, ctx)
		return
	}

	ctx.Blocked = true
	h.writeResponse(w, r, ctx, http.StatusNotFound, "no route")
}

func (h *handler) forwardToHandle(handle routeHandle, w http.ResponseWriter, r *http.Request, ctx *requestContext) {
	if handle.pool == nil {
		ctx.Blocked = true
		h.writeResponse(w, r, ctx, http.StatusBadGateway, "upstream pool not configured")
		return
	}
	ctx.Upstream = handle.pool.ServeHTTP(w, r)
	if ctx.Upstream == "" {
		ctx.Upstream = handle.upstream
	}
}

func (h *handler) routeModeForRequest(host, reqPath string) string {
	handles := h.hosts[normalizeHost(host)]
	for _, handle := range handles {
		if handle.matcher != nil && !matchRoute(handle.matcher, reqPath) {
			continue
		}
		return normalizeRouteMode(handle.mode)
	}
	return routeModeStandard
}

func (h routeHandle) includesUpstream(needle string) bool {
	for _, upstream := range h.upstreams {
		if strings.Contains(upstream, needle) {
			return true
		}
	}
	return strings.Contains(h.upstream, needle)
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

func (h *handler) finishLog(w *responseRecorder, r *http.Request, ctx *requestContext, start time.Time) {
	entry := logging.Entry{
		BytesIn:          bytesIn(r),
		BytesOut:         int64(w.bytes),
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
		WAFBlocked:       ctx.WAFBlocked,
		WAFScore:         ctx.WAFScore,
		WAFRules:         strings.Join(ctx.WAFRules, ","),
		WAFReason:        ctx.WAFReason,
		WAFAction:        ctx.WAFAction,
		ThreatCategory:   ctx.ThreatIntelCategory,
		ThreatAction:     ctx.ThreatIntelAction,
		ThreatIndicator:  ctx.ThreatIntelIndicator,
		ThreatReason:     ctx.ThreatIntelReason,
		BotKind:          ctx.BotKind,
		BotProfile:       ctx.BotProfile,
		BotAction:        ctx.BotAction,
		BotReason:        ctx.BotReason,
		AIAction:         ctx.AIAction,
		AIScore:          ctx.AIScore,
		AIReason:         ctx.AIReason,
	}
	h.log.Write(entry)
}

func (h *handler) checkProtocolLimits(r *http.Request) (int, string) {
	if h.limits.MaxURIBytes > 0 && len(r.URL.RequestURI()) > h.limits.MaxURIBytes {
		return http.StatusRequestURITooLong, "uri too long"
	}
	if h.limits.MaxURLLength > 0 && len(r.URL.RequestURI()) > h.limits.MaxURLLength {
		return http.StatusRequestURITooLong, "uri too long"
	}
	if h.limits.MaxQueryBytes > 0 && len(r.URL.RawQuery) > h.limits.MaxQueryBytes {
		return http.StatusRequestURITooLong, "query too long"
	}
	if h.limits.MaxHeaderBytes > 0 {
		if total := headerBytes(r.Header); total > h.limits.MaxHeaderBytes {
			return http.StatusRequestHeaderFieldsTooLarge, "headers too large"
		}
	}
	if h.limits.MaxParams > 0 {
		if countQueryParams(r.URL.Query()) > h.limits.MaxParams {
			return http.StatusBadRequest, "too many parameters"
		}
		if isURLEncoded(r.Header.Get("Content-Type")) {
			maxRead := int64(64 << 10)
			if h.limits.MaxBodyBytes > 0 && h.limits.MaxBodyBytes < maxRead {
				maxRead = h.limits.MaxBodyBytes
			}
			if n, err := countBodyFormParams(r, maxRead); err == nil && n > h.limits.MaxParams {
				return http.StatusBadRequest, "too many form parameters"
			}
		}
	}
	return 0, ""
}

func (h *handler) allowByRatePolicies(ip string, reqPath string) (bool, string, time.Time) {
	for _, p := range h.routeRatePolicies {
		if !pathMatchesAny(reqPath, p.globs) {
			continue
		}
		key := rateKey(p.keyMode, ip, p.name)
		if p.penalty != nil {
			if banned, until := p.penalty.IsBanned(key); banned {
				return false, p.name, until
			}
		}
		if p.limiter != nil && !p.limiter.Allow(key) {
			if p.penalty != nil {
				if banned, until := p.penalty.RegisterFailure(key); banned {
					return false, p.name, until
				}
			}
			return false, p.name, time.Time{}
		}
	}

	if h.globalRatePenalty != nil {
		if banned, until := h.globalRatePenalty.IsBanned(ip); banned {
			return false, "global", until
		}
	}
	if h.rateLimiter != nil && !h.rateLimiter.Allow(ip) {
		if h.globalRatePenalty != nil {
			if banned, until := h.globalRatePenalty.RegisterFailure(ip); banned {
				return false, "global", until
			}
		}
		return false, "global", time.Time{}
	}
	return true, "", time.Time{}
}

func (h *handler) wafRuleExclusionsForPath(reqPath string) map[string]struct{} {
	out := map[string]struct{}{}
	for id := range h.wafExRuleIDs {
		out[id] = struct{}{}
	}
	for glob, ids := range h.wafExRuleIDsByGlob {
		if !matchPath(glob, reqPath) {
			continue
		}
		for id := range ids {
			out[id] = struct{}{}
		}
	}
	return out
}

func (h *handler) isWAFHostExempt(host string) bool {
	if len(h.wafExHosts) == 0 {
		return false
	}
	v := normalizeHost(host)
	_, ok := h.wafExHosts[v]
	return ok
}

func (h *handler) autoShieldEnabledForHost(host string) bool {
	if h == nil {
		return false
	}
	v := normalizeHost(host)
	if enabled, ok := lookupHostBoolOverride(v, h.autoShieldByHost); ok {
		return enabled
	}
	return h.autoShieldDefault
}

func lookupHostBoolOverride(host string, values map[string]bool) (bool, bool) {
	if host == "" || len(values) == 0 {
		return false, false
	}
	if v, ok := values[host]; ok {
		return v, true
	}
	parts := strings.Split(host, ".")
	for i := 1; i < len(parts)-1; i++ {
		key := "*." + strings.Join(parts[i:], ".")
		if v, ok := values[key]; ok {
			return v, true
		}
	}
	return false, false
}

func bytesIn(r *http.Request) int64 {
	if r == nil || r.ContentLength < 0 {
		return 0
	}
	return r.ContentLength
}

func headerBytes(hdr http.Header) int {
	total := 0
	for k, vals := range hdr {
		total += len(k)
		for _, v := range vals {
			total += len(v)
		}
	}
	return total
}

func countQueryParams(q map[string][]string) int {
	total := 0
	for _, vals := range q {
		total += len(vals)
		if len(vals) == 0 {
			total++
		}
	}
	return total
}

func isURLEncoded(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	return ct == "application/x-www-form-urlencoded"
}

func countBodyFormParams(r *http.Request, maxRead int64) (int, error) {
	if r == nil || r.Body == nil || maxRead <= 0 {
		return 0, nil
	}
	chunk, err := io.ReadAll(io.LimitReader(r.Body, maxRead+1))
	if err != nil {
		return 0, err
	}
	r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(chunk), r.Body))
	if int64(len(chunk)) > maxRead {
		chunk = chunk[:maxRead]
	}
	vals, err := url.ParseQuery(string(chunk))
	if err != nil {
		return 0, err
	}
	return countQueryParams(vals), nil
}

func pathMatchesAny(reqPath string, globs []string) bool {
	for _, g := range globs {
		if matchPath(g, reqPath) {
			return true
		}
	}
	return false
}

func rateKey(mode, ip, routeGroup string) string {
	switch mode {
	case "ip":
		return ip
	default:
		return ip + ":" + routeGroup
	}
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

func matchRoute(m *config.Matcher, p string) bool {
	if m == nil {
		return true
	}
	if exact := strings.TrimSpace(m.PathExact); exact != "" {
		return p == exact
	}
	if rgx := strings.TrimSpace(m.PathRegex); rgx != "" {
		re, err := regexp.Compile(rgx)
		if err != nil {
			return false
		}
		return re.MatchString(p)
	}
	return matchPath(m.PathGlob, p)
}

const (
	routeModeStandard    = "standard"
	routeModePassThrough = "passthrough"
)

func normalizeRouteMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "pass-through", "passthrough", "stream", "doh":
		return routeModePassThrough
	default:
		return routeModeStandard
	}
}

func normalizeLBPolicy(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "least_conn", "leastconn":
		return proxy.LBPolicyLeastConn
	default:
		return proxy.LBPolicyRoundRobin
	}
}

func collectHandleUpstreams(h config.Handle) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(h.Upstreams)+1)
	appendUpstream := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	appendUpstream(h.Upstream)
	for _, upstream := range h.Upstreams {
		appendUpstream(upstream)
	}
	return out
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

func tlsFingerprintFromRequest(r *http.Request) *threatintel.TLSFingerprintInput {
	if r == nil || r.TLS == nil {
		return nil
	}
	alpn := strings.TrimSpace(r.TLS.NegotiatedProtocol)
	return &threatintel.TLSFingerprintInput{
		Version:    r.TLS.Version,
		Cipher:     r.TLS.CipherSuite,
		ServerName: r.TLS.ServerName,
		ALPN:       alpn,
	}
}

type requestContext struct {
	Upstream             string
	Route                string
	PassThrough          bool
	ChallengeApplied     bool
	RateLimited          bool
	Blocked              bool
	WAFBlocked           bool
	WAFScore             int
	WAFRules             []string
	WAFReason            string
	WAFAction            string
	ThreatIntelCategory  string
	ThreatIntelAction    string
	ThreatIntelIndicator string
	ThreatIntelReason    string
	BotKind              string
	BotProfile           string
	BotAction            string
	BotReason            string
	AIAction             string
	AIScore              float64
	AIReason             string
	Status               int
}

type responseRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *responseRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
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
	if v := os.Getenv("ACME_DNS01"); v != "" {
		cfg.ACME.DNS01Enabled = parseBool(v)
	}
	if v := os.Getenv("ACME_DNS_ISSUE_HOOK"); v != "" {
		cfg.ACME.DNSIssueHook = v
	}
	if v := os.Getenv("ACME_DNS_RENEW_HOOK"); v != "" {
		cfg.ACME.DNSRenewHook = v
	}
	if v := os.Getenv("ACME_DNS_HOOK_TIMEOUT"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.ACME.DNSHookTimeoutSec = n
		}
	}
	if v := os.Getenv("ACME_DNS_STORAGE"); v != "" {
		cfg.ACME.DNSStoragePath = v
	}
	if v := os.Getenv("HTTP3_ENABLED"); v != "" {
		cfg.HTTP3.Enabled = parseBool(v)
	}
	if v := os.Getenv("HTTP3_LISTEN"); v != "" {
		cfg.HTTP3.Listen = strings.TrimSpace(v)
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
	if v := os.Getenv("MAX_URI_BYTES"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.Limits.MaxURIBytes = n
		}
	}
	if v := os.Getenv("MAX_QUERY_BYTES"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.Limits.MaxQueryBytes = n
		}
	}
	if v := os.Getenv("MAX_PARAMS"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.Limits.MaxParams = n
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
	if v := os.Getenv("RATE_429_BAN_AFTER"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.Limits.Rate429BanAfter = n
		}
	}
	if v := os.Getenv("RATE_429_WINDOW_SECONDS"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.Limits.Rate429WindowSec = n
		}
	}
	if v := os.Getenv("RATE_429_BAN_SECONDS"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.Limits.Rate429BanSec = n
		}
	}
	if v := os.Getenv("WAF_BAN_SECONDS"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.Limits.WAFBanSec = n
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
	if v := os.Getenv("WAF_ENABLED"); v != "" {
		cfg.WAF.Enabled = v == "1" || strings.EqualFold(v, "true")
	}
	if v := os.Getenv("WAF_MODE"); v != "" {
		cfg.WAF.Mode = strings.ToLower(strings.TrimSpace(v))
	}
	if v := os.Getenv("WAF_SCORE_THRESHOLD"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.WAF.ScoreThreshold = n
		}
	}
	if v := os.Getenv("WAF_INBOUND_THRESHOLD"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.WAF.InboundThreshold = n
		}
	}
	if v := os.Getenv("WAF_PARANOIA_LEVEL"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.WAF.ParanoiaLevel = n
		}
	}
	if v := os.Getenv("WAF_MAX_INSPECT_BYTES"); v != "" {
		if n, err := parseInt64(v); err == nil {
			cfg.WAF.MaxInspectBytes = n
		}
	}
	if v := os.Getenv("WAF_MAX_VALUES_PER_COLLECTION"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.WAF.MaxValuesPerCollection = n
		}
	}
	if v := os.Getenv("WAF_MAX_TOTAL_VALUES"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.WAF.MaxTotalValues = n
		}
	}
	if v := os.Getenv("WAF_MAX_JSON_VALUES"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.WAF.MaxJSONValues = n
		}
	}
	if v := os.Getenv("WAF_MAX_BODY_VALUES"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.WAF.MaxBodyValues = n
		}
	}
	if v := os.Getenv("WAF_ALLOWED_METHODS"); v != "" {
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, strings.ToUpper(p))
			}
		}
		cfg.WAF.AllowedMethods = out
	}
	if v := os.Getenv("WAF_BLOCKED_CONTENT_TYPES"); v != "" {
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		cfg.WAF.BlockedContentTypes = out
	}
	if v := os.Getenv("WAF_PRESETS"); v != "" {
		cfg.WAF.Presets = splitCSV(v)
	}
	if v := os.Getenv("TI_ENABLED"); v != "" {
		cfg.ThreatIntel.Enabled = parseBool(v)
	}
	if v := os.Getenv("TI_ACTION"); v != "" {
		cfg.ThreatIntel.Action = strings.ToLower(strings.TrimSpace(v))
	}
	if v := os.Getenv("TI_REFRESH_SECONDS"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.ThreatIntel.RefreshSeconds = n
		}
	}
	if v := os.Getenv("TI_IP_FEEDS"); v != "" {
		cfg.ThreatIntel.IPFeeds = splitCSV(v)
	}
	if v := os.Getenv("TI_ASN_FEEDS"); v != "" {
		cfg.ThreatIntel.ASNFeeds = splitCSV(v)
	}
	if v := os.Getenv("TI_JA3_FEEDS"); v != "" {
		cfg.ThreatIntel.JA3Feeds = splitCSV(v)
	}
	if v := os.Getenv("TI_IPS"); v != "" {
		cfg.ThreatIntel.IPs = splitCSV(v)
	}
	if v := os.Getenv("TI_ASNS"); v != "" {
		cfg.ThreatIntel.ASNs = splitCSV(v)
	}
	if v := os.Getenv("TI_JA3"); v != "" {
		cfg.ThreatIntel.JA3 = splitCSV(v)
	}
	if v := os.Getenv("TI_ASN_HEADER"); v != "" {
		cfg.ThreatIntel.ASNHeader = strings.TrimSpace(v)
	}
	if v := os.Getenv("TI_JA3_HEADER"); v != "" {
		cfg.ThreatIntel.JA3Header = strings.TrimSpace(v)
	}
	if v := os.Getenv("BOT_ENABLED"); v != "" {
		cfg.BotManagement.Enabled = parseBool(v)
	}
	if v := os.Getenv("BOT_BAD_ACTION"); v != "" {
		cfg.BotManagement.BadAction = strings.ToLower(strings.TrimSpace(v))
	}
	if v := os.Getenv("BOT_BYPASS_WAF_FOR_GOOD"); v != "" {
		cfg.BotManagement.BypassWAFForGood = parseBool(v)
	}
	if v := os.Getenv("BOT_GOOD_PATTERNS"); v != "" {
		cfg.BotManagement.GoodPatterns = splitCSV(v)
	}
	if v := os.Getenv("BOT_BAD_PATTERNS"); v != "" {
		cfg.BotManagement.BadPatterns = splitCSV(v)
	}
	if v := os.Getenv("AUTO_SHIELD_ENABLED"); v != "" {
		cfg.AutoShield.Enabled = v == "1" || strings.EqualFold(v, "true")
	}
	if v := os.Getenv("AUTO_SHIELD_WINDOW_SECONDS"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.AutoShield.WindowSeconds = n
		}
	}
	if v := os.Getenv("AUTO_SHIELD_MIN_REQUESTS"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.AutoShield.MinRequests = n
		}
	}
	if v := os.Getenv("AUTO_SHIELD_PROBE_PATH_THRESHOLD"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.AutoShield.ProbePathThreshold = n
		}
	}
	if v := os.Getenv("AUTO_SHIELD_HIGH_ERROR_RATIO_PCT"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.AutoShield.HighErrorRatioPct = n
		}
	}
	if v := os.Getenv("AUTO_SHIELD_HIGH_RATE_LIMIT_RATIO_PCT"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.AutoShield.HighRateLimitedRatioPct = n
		}
	}
	if v := os.Getenv("AUTO_SHIELD_SCORE_THRESHOLD"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.AutoShield.ScoreThreshold = n
		}
	}
	if v := os.Getenv("AUTO_SHIELD_BAN_SECONDS"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.AutoShield.BanSeconds = n
		}
	}
	if v := os.Getenv("AI_ENABLED"); v != "" {
		cfg.AI.Enabled = parseBool(v)
	}
	if v := os.Getenv("AI_LEARNING_MODE"); v != "" {
		cfg.AI.LearningMode = parseBool(v)
	}
	if v := os.Getenv("AI_BACKEND"); v != "" {
		cfg.AI.Backend = strings.ToLower(strings.TrimSpace(v))
	}
	if v := os.Getenv("AI_MODEL_PATH"); v != "" {
		cfg.AI.ModelPath = strings.TrimSpace(v)
	}
	if v := os.Getenv("AI_ONNX_COMMAND"); v != "" {
		cfg.AI.ONNXCommand = v
	}
	if v := os.Getenv("AI_TFLITE_COMMAND"); v != "" {
		cfg.AI.TFLiteCommand = v
	}
	if v := os.Getenv("AI_STATE_PATH"); v != "" {
		cfg.AI.StatePath = strings.TrimSpace(v)
	}
	if v := os.Getenv("AI_MIN_SAMPLES"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.AI.MinSamples = n
		}
	}
	if v := os.Getenv("AI_CHALLENGE_THRESHOLD"); v != "" {
		if f, err := parseFloat(v); err == nil {
			cfg.AI.ChallengeThreshold = f
		}
	}
	if v := os.Getenv("AI_RATE_LIMIT_THRESHOLD"); v != "" {
		if f, err := parseFloat(v); err == nil {
			cfg.AI.RateLimitThreshold = f
		}
	}
	if v := os.Getenv("AI_BLOCK_THRESHOLD"); v != "" {
		if f, err := parseFloat(v); err == nil {
			cfg.AI.BlockThreshold = f
		}
	}
	if v := os.Getenv("AI_MAX_BODY_INSPECT_BYTES"); v != "" {
		if n, err := parseInt64(v); err == nil {
			cfg.AI.MaxBodyInspectBytes = n
		}
	}
	if v := os.Getenv("AI_COMMAND_TIMEOUT_MS"); v != "" {
		if n, err := parseInt(v); err == nil {
			cfg.AI.CommandTimeoutMS = n
		}
	}
	if v := os.Getenv("AI_UPDATE_PROFILES_ON_BLOCK"); v != "" {
		cfg.AI.UpdateProfilesOnBlock = parseBool(v)
	}
	if v := os.Getenv("ON_DEMAND_TLS"); v != "" {
		cfg.ACME.OnDemandTLS = parseBool(v)
	}
	if v := os.Getenv("WAF_LEVEL"); v != "" {
		applyWAFLevel(cfg, v)
	}
	applyProtectDomains(cfg)
	applySSLMode(cfg)
	applyDOHExclude(cfg)
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

func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "on", "yes":
		return true
	default:
		return false
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func shellEscape(v string) string {
	if v == "" {
		return ""
	}
	return "'" + strings.ReplaceAll(v, "'", "'\"'\"'") + "'"
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		item := strings.TrimSpace(p)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func appendUnique(values []string, item string) []string {
	item = strings.TrimSpace(item)
	if item == "" {
		return values
	}
	for _, existing := range values {
		if strings.EqualFold(strings.TrimSpace(existing), item) {
			return values
		}
	}
	return append(values, item)
}

func applyWAFLevel(cfg *config.Config, level string) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "off", "none", "disabled":
		cfg.WAF.Enabled = false
	case "low":
		cfg.WAF.Enabled = true
		cfg.WAF.ParanoiaLevel = 1
		cfg.WAF.InboundThreshold = 10
		cfg.WAF.ScoreThreshold = 10
	case "medium", "normal":
		cfg.WAF.Enabled = true
		cfg.WAF.ParanoiaLevel = 2
		cfg.WAF.InboundThreshold = 7
		cfg.WAF.ScoreThreshold = 7
	case "high":
		cfg.WAF.Enabled = true
		cfg.WAF.ParanoiaLevel = 3
		cfg.WAF.InboundThreshold = 5
		cfg.WAF.ScoreThreshold = 5
	case "ultra", "aggressive":
		cfg.WAF.Enabled = true
		cfg.WAF.ParanoiaLevel = 4
		cfg.WAF.InboundThreshold = 3
		cfg.WAF.ScoreThreshold = 3
	}
}

func applyProtectDomains(cfg *config.Config) {
	domains := splitCSV(os.Getenv("PROTECT_DOMAINS"))
	if len(domains) == 0 {
		return
	}

	mode := normalizeRouteMode(os.Getenv("PROXY_MODE"))
	lbPolicy := normalizeLBPolicy(os.Getenv("LB_POLICY"))

	upstreams := splitCSV(os.Getenv("PROTECT_UPSTREAMS"))
	if len(upstreams) == 0 {
		upstreams = splitCSV(os.Getenv("UPSTREAMS"))
	}
	if len(upstreams) == 0 {
		primary := strings.TrimSpace(os.Getenv("PROTECT_UPSTREAM"))
		if primary == "" {
			primary = strings.TrimSpace(os.Getenv("UPSTREAM"))
		}
		if primary == "" {
			primary = firstConfiguredUpstream(cfg)
		}
		if primary == "" {
			primary = "127.0.0.1:8080"
		}
		upstreams = []string{primary}
	}

	normalizedUpstreams := make([]string, 0, len(upstreams))
	seenUpstreams := map[string]struct{}{}
	for _, raw := range upstreams {
		upstream := strings.TrimSpace(raw)
		if upstream == "" {
			continue
		}
		if _, ok := seenUpstreams[upstream]; ok {
			continue
		}
		seenUpstreams[upstream] = struct{}{}
		normalizedUpstreams = append(normalizedUpstreams, upstream)
	}
	if len(normalizedUpstreams) == 0 {
		return
	}

	newHandle := config.Handle{
		Mode:      mode,
		LBPolicy:  lbPolicy,
		Upstream:  normalizedUpstreams[0],
		Upstreams: normalizedUpstreams,
	}

	existing := map[string]int{}
	for i := range cfg.Servers {
		existing[normalizeHost(cfg.Servers[i].Hostname)] = i
	}

	for _, rawHost := range domains {
		host := normalizeHost(rawHost)
		if host == "" {
			continue
		}
		if idx, ok := existing[host]; ok {
			if len(cfg.Servers[idx].Handles) == 0 {
				cfg.Servers[idx].Handles = []config.Handle{newHandle}
			}
			continue
		}
		cfg.Servers = append(cfg.Servers, config.Server{
			Hostname: host,
			Handles:  []config.Handle{newHandle},
		})
		existing[host] = len(cfg.Servers) - 1
	}
}

func firstConfiguredUpstream(cfg *config.Config) string {
	for _, srv := range cfg.Servers {
		for _, h := range srv.Handles {
			upstreams := collectHandleUpstreams(h)
			if len(upstreams) > 0 {
				return upstreams[0]
			}
		}
	}
	return ""
}

func applySSLMode(cfg *config.Config) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("SSL_MODE")))
	switch mode {
	case "internal", "le", "acme", "auto":
		for i := range cfg.Servers {
			cfg.Servers[i].TLS = nil
		}
	case "custom":
		certFile := strings.TrimSpace(os.Getenv("SSL_CERT_FILE"))
		keyFile := strings.TrimSpace(os.Getenv("SSL_KEY_FILE"))
		certDir := strings.TrimSpace(os.Getenv("SSL_CERT_DIR"))
		for i := range cfg.Servers {
			if certFile != "" && keyFile != "" {
				cfg.Servers[i].TLS = &config.ServerTLS{
					CertFile: certFile,
					KeyFile:  keyFile,
				}
				continue
			}
			if certDir == "" {
				continue
			}
			host := normalizeHost(cfg.Servers[i].Hostname)
			if host == "" {
				continue
			}
			cert, key := findDomainCertPair(certDir, host)
			if cert == "" || key == "" {
				continue
			}
			cfg.Servers[i].TLS = &config.ServerTLS{
				CertFile: cert,
				KeyFile:  key,
			}
		}
	}
}

func findDomainCertPair(certDir, host string) (string, string) {
	cert := firstExisting(
		filepath.Join(certDir, host+".crt"),
		filepath.Join(certDir, host+".pem"),
		filepath.Join(certDir, host, "fullchain.pem"),
	)
	key := firstExisting(
		filepath.Join(certDir, host+".key"),
		filepath.Join(certDir, host+".pem.key"),
		filepath.Join(certDir, host, "privkey.pem"),
	)
	return cert, key
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		info, err := os.Stat(p)
		if err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

func applyDOHExclude(cfg *config.Config) {
	hosts := splitCSV(os.Getenv("DOH_EXCLUDE"))
	if len(hosts) == 0 {
		return
	}
	cfg.WAF.ExemptGlobs = appendUnique(cfg.WAF.ExemptGlobs, "/dns-query")
	cfg.Challenge.ExemptGlobs = appendUnique(cfg.Challenge.ExemptGlobs, "/dns-query")

	for _, rawHost := range hosts {
		host := normalizeHost(rawHost)
		if host == "" {
			continue
		}
		cfg.WAF.ExemptHosts = appendUnique(cfg.WAF.ExemptHosts, host)
		for i := range cfg.Servers {
			if normalizeHost(cfg.Servers[i].Hostname) != host {
				continue
			}
			for j := range cfg.Servers[i].Handles {
				if isDOHHandle(cfg.Servers[i].Handles[j]) {
					cfg.Servers[i].Handles[j].Mode = routeModePassThrough
				}
			}
		}
	}
}

func isDOHHandle(h config.Handle) bool {
	if strings.Contains(strings.ToLower(strings.TrimSpace(h.MatcherName)), "doh") {
		return true
	}
	if h.Matcher == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(h.Matcher.PathExact), "/dns-query") {
		return true
	}
	if strings.Contains(strings.ToLower(strings.TrimSpace(h.Matcher.PathGlob)), "/dns-query") {
		return true
	}
	if strings.Contains(strings.ToLower(strings.TrimSpace(h.Matcher.PathRegex)), "dns-query") {
		return true
	}
	return false
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
