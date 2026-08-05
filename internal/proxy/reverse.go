package proxy

import (
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

type UpstreamProxy struct {
	proxy    *httputil.ReverseProxy
	Upstream string

	// ws, when non-nil, enables WebSocket proxying. If nil
	// (default), WebSocket upgrades are passed through to the
	// reverse proxy, which will silently drop the upgrade
	// headers and the request will be served as a regular
	// HTTP request.
	ws *WebSocketProxy
}

func NewUpstreamProxy(upstream string, connectTimeout, responseTimeout time.Duration) (*UpstreamProxy, error) {
	if !strings.Contains(upstream, "://") {
		upstream = "http://" + upstream
	}
	target, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1024,
		MaxIdleConnsPerHost:   512,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: responseTimeout,
	}

	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Transport = transport
	rp.ModifyResponse = func(resp *http.Response) error {
		// Hide upstream server signature and expose gateway branding.
		resp.Header.Set("Server", "ASTRACAT Anti-DDoS")
		resp.Header.Del("X-Powered-By")
		return nil
	}
	origDirector := rp.Director
	rp.Director = func(r *http.Request) {
		originalHost := r.Host
		origDirector(r)
		addForwardedHeaders(r, originalHost)
		// Preserve the original Host so upstream apps generate public URLs, not internal Docker DNS.
		r.Host = originalHost
	}

	return &UpstreamProxy{proxy: rp, Upstream: target.Host}, nil
}

// NewUpstreamProxyWithWS is like NewUpstreamProxy but also
// configures a WebSocket proxy for this upstream. The cfg
// fields are stored on the returned *UpstreamProxy; pass an
// empty WSConfig to enable WebSocket with default limits.
func NewUpstreamProxyWithWS(upstream string, connectTimeout, responseTimeout time.Duration, cfg WSConfig) (*UpstreamProxy, error) {
	p, err := NewUpstreamProxy(upstream, connectTimeout, responseTimeout)
	if err != nil {
		return nil, err
	}
	ws, err := NewWebSocketProxy(upstream, cfg)
	if err != nil {
		return nil, err
	}
	p.ws = ws
	return p, nil
}

// SetWSMetrics wires atomic counter pointers to the WebSocket
// proxy. Safe to call before the first request; nil pointers
// are ignored. Use this to feed the existing metrics.Registry
// without creating a package cycle.
func (p *UpstreamProxy) SetWSMetrics(connections, rejected, errors *uint64) {
	if p == nil || p.ws == nil {
		return
	}
	p.ws.cfg.CounterConnections = connections
	p.ws.cfg.CounterRejected = rejected
	p.ws.cfg.CounterErrors = errors
}

func addForwardedHeaders(r *http.Request, originalHost string) {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}

	if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
		r.Header.Set("X-Forwarded-For", prior+", "+clientIP)
	} else {
		r.Header.Set("X-Forwarded-For", clientIP)
	}

	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	r.Header.Set("X-Forwarded-Proto", proto)
	r.Header.Set("X-Forwarded-Host", originalHost)
}

func (p *UpstreamProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.ws != nil && IsWebSocketRequest(r) {
		p.ws.ServeProxy(w, r)
		return
	}
	p.proxy.ServeHTTP(w, r)
}
