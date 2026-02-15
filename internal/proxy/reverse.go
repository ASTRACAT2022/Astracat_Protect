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
}

func NewUpstreamProxy(upstream string, timeout time.Duration) (*UpstreamProxy, error) {
	if !strings.Contains(upstream, "://") {
		upstream = "http://" + upstream
	}
	target, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
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
	p.proxy.ServeHTTP(w, r)
}
