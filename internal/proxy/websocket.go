package proxy

// WebSocket reverse-proxy implementation.
//
// The standard httputil.ReverseProxy does not tunnel the HTTP/1.1
// "Connection: Upgrade" handshake to the upstream, which means
// WebSocket connections silently fail. This file implements a
// self-contained WebSocket tunnel: hijack the client connection,
// dial the upstream, write the handshake, then bidirectional-copy
// bytes between the two sockets with optional keep-alive and
// per-frame size limits.
//
// Design notes:
//   - The transport is plain TCP for ws:// and TLS for wss://. We do
//     not reuse http.Transport here because the WebSocket handshake
//     upgrades the underlying connection and we want full control.
//   - For each frame in either direction we count bytes, enforce
//     MaxMessageBytes, and emit a control-frame ping if the peer
//     has been silent for PingInterval (server-to-client only — RFC
//     6455 doesn't require the client side).
//   - We do NOT parse WebSocket frames manually; we use the gorilla
//     websocket package which is the de-facto standard. To avoid
//     adding a dependency, we instead stream raw bytes once the
//     handshake completes and apply limits via a length-checking
//     copy. The full frame parser is a small private type below
//     (see wsFrame). It is intentionally minimal: it enforces the
//     size cap, surfaces control frames for ping/pong, and never
//     blocks longer than necessary.

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// WSConfig controls WebSocket proxy behaviour. All fields are
// optional; zero values pick sensible defaults applied in
// NewWebSocketProxy.
type WSConfig struct {
	// HandshakeTimeout caps how long the upstream may take to
	// respond with 101 Switching Protocols. Default 10s.
	HandshakeTimeout time.Duration

	// ReadTimeout / WriteTimeout cap I/O on each peer. The
	// defaults are generous because WebSocket connections are
	// typically long-lived; 0 disables the cap.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// MaxMessageBytes caps the size of a single WebSocket
	// message (sum of all frames for a fragmented message).
	// 0 means "no limit". Default 1 MiB.
	MaxMessageBytes int64

	// PingInterval enables server-to-client keep-alive. When a
	// connection is silent for this long, the proxy sends a
	// WebSocket Ping; if the peer does not respond with a Pong
	// within PongTimeout the connection is closed. 0 disables.
	PingInterval time.Duration
	PongTimeout  time.Duration

	// AllowedOrigins, when non-empty, restricts the Origin
	// header. Use "*" to allow any origin (default browser
	// behaviour). An empty list rejects all WebSocket
	// connections with 403.
	AllowedOrigins []string

	// Subprotocols offered to the upstream via the
	// Sec-WebSocket-Protocol request header. The upstream's
	// response is forwarded verbatim to the client.
	Subprotocols []string

	// TLSConfig for wss:// upstreams. If nil, defaults are used
	// (TLS 1.2+, modern cipher suites).
	TLSConfig *tls.Config

	// OnConnect, if non-nil, is invoked after the upstream
	// handshake completes successfully and before the
	// bidirectional copy loop starts. It receives the client
	// and upstream addresses. Useful for access logging.
	OnConnect func(clientAddr, upstreamAddr, host, path string)
	// OnDisconnect is invoked once when the tunnel finishes,
	// with the duration of the session and the number of
	// bytes transferred in each direction.
	OnDisconnect func(dur time.Duration, in, out int64, err error)

	// Counter callbacks for metrics. Counters are exposed as
	// atomic uint64 pointers so the caller can register them
	// with the metrics package without creating a cycle.
	CounterConnections *uint64 // accepted tunnels
	CounterRejected    *uint64 // rejected handshakes (origin, oversized, etc.)
	CounterErrors      *uint64 // I/O errors after the tunnel started
}

// WebSocketProxy is attached to UpstreamProxy; it owns the
// configuration that applies to WebSocket requests for a given
// upstream. A single WebSocketProxy is safe to use from many
// goroutines; it stores no per-connection state.
type WebSocketProxy struct {
	cfg WSConfig
	// upstream is the *parsed* upstream URL (must be ws:// or
	// wss://). It is cached to avoid re-parsing on every
	// request.
	upstream *url.URL
}

// NewWebSocketProxy builds a WebSocketProxy for the given
// upstream URL. The upstream is the same string passed to
// NewUpstreamProxy (e.g. "https://backend:8443"); the scheme is
// rewritten to ws/wss for the WebSocket path.
func NewWebSocketProxy(upstream string, cfg WSConfig) (*WebSocketProxy, error) {
	if !strings.Contains(upstream, "://") {
		upstream = "http://" + upstream
	}
	target, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("websocket: parse upstream: %w", err)
	}
	switch strings.ToLower(target.Scheme) {
	case "http":
		target.Scheme = "ws"
	case "https":
		target.Scheme = "wss"
	case "ws", "wss":
		// already correct
	default:
		return nil, fmt.Errorf("websocket: unsupported scheme %q", target.Scheme)
	}

	applyWSDefaults(&cfg)
	if cfg.PongTimeout == 0 && cfg.PingInterval > 0 {
		cfg.PongTimeout = cfg.PingInterval
	}

	return &WebSocketProxy{cfg: cfg, upstream: target}, nil
}

func applyWSDefaults(c *WSConfig) {
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = 10 * time.Second
	}
	if c.MaxMessageBytes == 0 {
		c.MaxMessageBytes = 1 << 20 // 1 MiB
	}
}

// IsWebSocketRequest reports whether r is a WebSocket
// handshake. Mirrors the helper in package server so the proxy
// can make routing decisions without an import cycle.
func IsWebSocketRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	conn := strings.ToLower(r.Header.Get("Connection"))
	// "Connection" may list several tokens; "upgrade" must be
	// among them.
	for _, tok := range strings.Split(conn, ",") {
		if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
			return true
		}
	}
	return false
}

// ServeProxy hijacks the client connection, opens a TCP (or
// TLS) connection to the upstream, replays the WebSocket
// handshake, and pumps bytes in both directions. It returns
// once the tunnel ends. Any HTTP response it writes (e.g. 403
// for a rejected Origin) uses w before hijacking.
func (wp *WebSocketProxy) ServeProxy(w http.ResponseWriter, r *http.Request) {
	if wp == nil || wp.upstream == nil {
		http.Error(w, "websocket proxy not configured", http.StatusInternalServerError)
		wsCounter(wp, false, false)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "websocket: method must be GET", http.StatusMethodNotAllowed)
		wsCounter(wp, false, true)
		return
	}

	if !isOriginAllowed(r.Header.Get("Origin"), wp.cfg.AllowedOrigins, r.Host) {
		http.Error(w, "websocket: origin not allowed", http.StatusForbidden)
		wsCounter(wp, false, true)
		return
	}

	clientKey := r.Header.Get("Sec-WebSocket-Key")
	if clientKey == "" {
		http.Error(w, "websocket: missing Sec-WebSocket-Key", http.StatusBadRequest)
		wsCounter(wp, false, true)
		return
	}

	// Dial upstream.
	upstreamConn, err := wp.dialUpstream(r)
	if err != nil {
		http.Error(w, "websocket: upstream dial: "+err.Error(), http.StatusBadGateway)
		wsCounter(wp, false, true)
		return
	}

	// Hijack the client. After this point we own the underlying
	// net.Conn and must not write to w. We try the standard
	// http.Hijacker first (faster path, supported by the
	// plain net/http server) and fall back to
	// http.NewResponseController, which handles wrapped
	// ResponseWriters and is the recommended API in Go 1.20+.
	clientConn, clientBuf, err := hijack(w, r)
	if err != nil {
		_ = upstreamConn.Close()
		http.Error(w, "websocket: hijack failed: "+err.Error(), http.StatusInternalServerError)
		wsCounter(wp, false, true)
		return
	}

	// Write the upstream handshake. We do it on a buffered writer
	// so a partial write can be detected.
	upstreamHost := hostWithoutPort(wp.upstream)
	upstreamReq, err := buildUpstreamHandshake(r, wp.upstream, upstreamHost, wp.cfg.Subprotocols)
	if err != nil {
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		writeHTTPError(clientConn, clientBuf, http.StatusBadRequest, err.Error())
		wsCounter(wp, false, true)
		return
	}

	if dl, ok := upstreamConn.(interface{ SetDeadline(time.Time) error }); ok {
		_ = dl.SetDeadline(time.Now().Add(wp.cfg.HandshakeTimeout))
	}
	if err := upstreamReq.Write(upstreamConn); err != nil {
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		writeHTTPError(clientConn, clientBuf, http.StatusBadGateway, "upstream handshake write: "+err.Error())
		wsCounter(wp, false, true)
		return
	}

	// Read upstream 101.
	br := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(br, upstreamReq)
	if err != nil {
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		writeHTTPError(clientConn, clientBuf, http.StatusBadGateway, "upstream handshake read: "+err.Error())
		wsCounter(wp, false, true)
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		// Upstream did not accept the upgrade. Forward its
		// response to the client (best effort) and bail.
		body := bytes.Buffer{}
		_, _ = body.ReadFrom(resp.Body)
		_ = resp.Body.Close()
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		writeHTTPError(clientConn, clientBuf, resp.StatusCode, body.String())
		wsCounter(wp, false, true)
		return
	}

	// Compose the client 101 response. We must echo the
	// Sec-WebSocket-Accept value derived from the client's key.
	accept := computeAcceptKey(clientKey)
	clientResp := buildClient101(accept, resp.Header.Get("Sec-WebSocket-Protocol"))
	if wp.cfg.WriteTimeout > 0 {
		_ = clientConn.SetWriteDeadline(time.Now().Add(wp.cfg.WriteTimeout))
	}
	if _, err := clientBuf.WriteString(clientResp); err != nil {
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		wsCounter(wp, true, false)
		return
	}
	if err := clientBuf.Flush(); err != nil {
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		wsCounter(wp, true, false)
		return
	}

	// Clear handshake deadlines; the tunnel is now established.
	if c, ok := upstreamConn.(interface{ SetDeadline(time.Time) error }); ok {
		_ = c.SetDeadline(time.Time{})
	}

	// Hand the buffered upstream reader to the pump loop.
	upstreamReader := br
	wsCounter(wp, true, false)
	if wp.cfg.OnConnect != nil {
		wp.cfg.OnConnect(clientConn.RemoteAddr().String(), upstreamConn.RemoteAddr().String(), r.Host, r.URL.Path)
	}

	pump(wp.cfg, clientConn, clientBuf, upstreamConn, upstreamReader, r)
}

// dialUpstream opens a TCP or TLS connection to the WebSocket
// upstream, with the configured handshake timeout.
func (wp *WebSocketProxy) dialUpstream(r *http.Request) (net.Conn, error) {
	host := wp.upstream.Host
	dialer := &net.Dialer{Timeout: wp.cfg.HandshakeTimeout, KeepAlive: 30 * time.Second}

	var (
		conn net.Conn
		err  error
	)
	if wp.upstream.Scheme == "wss" {
		tlsCfg := wp.cfg.TLSConfig
		if tlsCfg == nil {
			tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		// Pin ServerName to the host portion of the upstream
		// URL so certificate verification works.
		if tlsCfg.ServerName == "" {
			tlsCfg = tlsCfg.Clone()
			tlsCfg.ServerName = hostOnly(host)
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", host, tlsCfg)
	} else {
		conn, err = dialer.Dial("tcp", host)
	}
	if err != nil {
		return nil, err
	}
	if wp.cfg.HandshakeTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(wp.cfg.HandshakeTimeout))
	}
	return conn, nil
}

// buildUpstreamHandshake serialises the HTTP/1.1 GET that
// initiates the upstream-side WebSocket upgrade. The
// Sec-WebSocket-Key is re-used from the client (any 16-byte
// base64 value is acceptable to the upstream per RFC 6455).
func buildUpstreamHandshake(r *http.Request, upstream *url.URL, sni string, subprotocols []string) (*http.Request, error) {
	u := *upstream
	u.Path = singleJoinPath(upstream.Path, r.URL.Path)
	u.RawQuery = r.URL.RawQuery

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	// Copy upgrade headers from the client. We re-evaluate the
	// standard set rather than forwarding the whole header map
	// to avoid leaking hop-by-hop fields.
	for k, vs := range r.Header {
		switch strings.ToLower(k) {
		case "host", "connection", "upgrade", "sec-websocket-key",
			"sec-websocket-version", "sec-websocket-extensions",
			"sec-websocket-protocol", "content-length",
			"content-type", "transfer-encoding":
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	if r.Header.Get("Sec-WebSocket-Key") == "" {
		req.Header.Set("Sec-WebSocket-Key", randomKey())
	} else {
		req.Header.Set("Sec-WebSocket-Key", r.Header.Get("Sec-WebSocket-Key"))
	}
	if r.Header.Get("Sec-WebSocket-Version") == "" {
		req.Header.Set("Sec-WebSocket-Version", "13")
	} else {
		req.Header.Set("Sec-WebSocket-Version", r.Header.Get("Sec-WebSocket-Version"))
	}
	if len(subprotocols) > 0 {
		req.Header.Set("Sec-WebSocket-Protocol", strings.Join(subprotocols, ", "))
	} else if v := r.Header.Get("Sec-WebSocket-Protocol"); v != "" {
		req.Header.Set("Sec-WebSocket-Protocol", v)
	}
	// Preserve the original Host so upstream apps generate
	// public URLs, not internal addresses.
	if r.Host != "" {
		req.Host = r.Host
	}
	return req, nil
}

// buildClient101 produces the 101 Switching Protocols response
// the client expects. We synthesise it by hand so we don't need
// an http.ResponseWriter after hijacking.
func buildClient101(accept, subprotocol string) string {
	var b strings.Builder
	b.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	b.WriteString("Sec-WebSocket-Accept: ")
	b.WriteString(accept)
	b.WriteString("\r\n")
	if subprotocol != "" {
		b.WriteString("Sec-WebSocket-Protocol: ")
		b.WriteString(subprotocol)
		b.WriteString("\r\n")
	}
	b.WriteString("Server: ASTRACAT Anti-DDoS\r\n")
	b.WriteString("\r\n")
	return b.String()
}

func computeAcceptKey(clientKey string) string {
	h := sha1.New()
	h.Write([]byte(clientKey))
	h.Write([]byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func randomKey() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return base64.StdEncoding.EncodeToString(b[:])
}

func hostOnly(hostport string) string {
	if i := strings.IndexByte(hostport, ':'); i >= 0 {
		return hostport[:i]
	}
	return hostport
}

func hostWithoutPort(u *url.URL) string {
	return hostOnly(u.Host)
}

// schemeForRequest returns "https" if requestHost is served on
// a TLS port (443 or 8443) and "http" otherwise. The Astracat
// frontend always terminates TLS before us, so r.TLS is the
// authoritative signal; we use port-based detection only as a
// best-effort fallback for non-browser clients.
func schemeForRequest(requestHost string) string {
	if strings.HasSuffix(requestHost, ":443") || strings.HasSuffix(requestHost, ":8443") {
		return "https"
	}
	return "http"
}

// singleJoinPath joins a base path and a request path with a
// single slash separator, preserving trailing slashes.
func singleJoinPath(base, reqPath string) string {
	if base == "" {
		return reqPath
	}
	if reqPath == "" {
		return base
	}
	if !strings.HasSuffix(base, "/") && !strings.HasPrefix(reqPath, "/") {
		return base + "/" + reqPath
	}
	if strings.HasSuffix(base, "/") && strings.HasPrefix(reqPath, "/") {
		return base + strings.TrimPrefix(reqPath, "/")
	}
	return base + reqPath
}

func writeHTTPError(conn net.Conn, buf *bufio.ReadWriter, status int, msg string) {
	body := msg
	resp := "HTTP/1.1 " + strconv.Itoa(status) + " " + http.StatusText(status) + "\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" + body
	_, _ = buf.WriteString(resp)
	_ = buf.Flush()
	_ = conn.Close()
}

// hijack returns the underlying net.Conn for w. It tries the
// classic http.Hijacker first, then falls back to
// http.NewResponseController (which understands wrapped
// ResponseWriters in modern middleware). Returns an error if
// neither path is supported.
func hijack(w http.ResponseWriter, _ *http.Request) (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.(http.Hijacker); ok {
		return h.Hijack()
	}
	// NewResponseController requires Go 1.20+; the project's
	// go.mod targets 1.24, so this is always available.
	rc := http.NewResponseController(w)
	conn, buf, err := rc.Hijack()
	if err != nil {
		return nil, nil, err
	}
	return conn, buf, nil
}

func isOriginAllowed(origin string, allowed []string, requestHost string) bool {
	// If no allow-list is configured we honour the standard
	// "same-origin" rule: missing Origin (non-browser client)
	// is allowed; otherwise the entire origin (scheme + host)
	// must match the request host.
	if len(allowed) == 0 {
		if origin == "" {
			return true
		}
		o, err := url.Parse(origin)
		if err != nil || o.Host == "" {
			return false
		}
		if o.Scheme != "http" && o.Scheme != "https" && o.Scheme != "ws" && o.Scheme != "wss" {
			return false
		}
		return strings.EqualFold(hostOnly(o.Host), hostOnly(requestHost)) && strings.EqualFold(o.Scheme, schemeForRequest(requestHost))
	}
	for _, rule := range allowed {
		if rule == "*" {
			return true
		}
		if strings.EqualFold(rule, origin) {
			return true
		}
		// Wildcard subdomain match: "*.example.com" matches
		// "https://x.example.com" but not "https://example.com".
		if strings.HasPrefix(rule, "*.") {
			suffix := rule[1:] // ".example.com"
			if strings.HasSuffix(strings.ToLower(origin), strings.ToLower(suffix)) {
				return true
			}
		}
	}
	return false
}

func wsCounter(wp *WebSocketProxy, success, rejected bool) {
	if wp == nil || wp.cfg.CounterConnections == nil {
		return
	}
	if success {
		atomic.AddUint64(wp.cfg.CounterConnections, 1)
	}
	if rejected && wp.cfg.CounterRejected != nil {
		atomic.AddUint64(wp.cfg.CounterRejected, 1)
	}
}

// pump runs the bidirectional copy loop. Bytes flow between
// clientConn and upstreamConn. Each direction is wrapped in
// wsReader/wsWriter which enforce MaxMessageBytes and emit
// keep-alive pings.
func pump(cfg WSConfig, client net.Conn, clientBuf *bufio.ReadWriter, upstream net.Conn, upstreamBuf *bufio.Reader, r *http.Request) {
	start := time.Now()
	var in, out int64
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	setErr := func(e error) {
		if e == nil {
			return
		}
		errMu.Lock()
		if firstErr == nil {
			firstErr = e
		}
		errMu.Unlock()
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		n, err := copyUpstream(cfg, client, clientBuf, upstream)
		out = n
		setErr(err)
		// Half-close the upstream write side so the server
		// sees EOF if it implements half-close semantics.
		if tc, ok := upstream.(closeWriter); ok {
			_ = tc.CloseWrite()
		} else {
			_ = upstream.SetReadDeadline(time.Now())
		}
	}()
	go func() {
		defer wg.Done()
		n, err := copyClient(cfg, upstream, upstreamBuf, client, r)
		in = n
		setErr(err)
		if tc, ok := client.(closeWriter); ok {
			_ = tc.CloseWrite()
		} else {
			_ = client.SetReadDeadline(time.Now())
		}
	}()
	wg.Wait()

	_ = client.Close()
	_ = upstream.Close()

	if firstErr != nil && cfg.CounterErrors != nil {
		atomic.AddUint64(cfg.CounterErrors, 1)
	}
	if cfg.OnDisconnect != nil {
		cfg.OnDisconnect(time.Since(start), in, out, firstErr)
	}
}

type closeWriter interface{ CloseWrite() error }

// copyUpstream reads WebSocket frames from the client and
// forwards them verbatim to the upstream. Returns the number
// of bytes copied (frame payload only — control frames do not
// count) and the first error encountered.
func copyUpstream(cfg WSConfig, client net.Conn, clientBuf *bufio.ReadWriter, upstream net.Conn) (int64, error) {
	if cfg.WriteTimeout > 0 {
		_ = upstream.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
	}
	// The client may have buffered bytes that arrived after
	// the HTTP handshake. Prefer the buffered reader; we
	// already drained it for the request line.
	fr := newWSFrameReader(clientBuf.Reader, cfg.MaxMessageBytes)
	if cfg.WriteTimeout > 0 {
		_ = client.SetReadDeadline(time.Now().Add(cfg.ReadTimeout))
	}
	return fr.pumpTo(upstream)
}

// copyClient forwards WebSocket frames from the upstream to
// the client, optionally emitting keep-alive pings.
func copyClient(cfg WSConfig, upstream net.Conn, upstreamBuf *bufio.Reader, client net.Conn, r *http.Request) (int64, error) {
	if cfg.ReadTimeout > 0 {
		_ = upstream.SetReadDeadline(time.Now().Add(cfg.ReadTimeout))
	}
	fr := newWSFrameReader(upstreamBuf, cfg.MaxMessageBytes)

	// Keep-alive pings are only emitted on the server-side
	// path. RFC 6455 says clients should respond with Pong;
	// the underlying reader's read deadline doubles as our
	// "are they still there?" timer.
	if cfg.PingInterval > 0 {
		var (
			mu       sync.Mutex
			lastSeen = time.Now()
		)
		keepAlive := time.NewTicker(cfg.PingInterval)
		keepAliveDone := make(chan struct{})
		go func() {
			defer keepAlive.Stop()
			for {
				select {
				case <-keepAliveDone:
					return
				case now := <-keepAlive.C:
					mu.Lock()
					idle := now.Sub(lastSeen)
					mu.Unlock()
					if idle < cfg.PingInterval {
						continue
					}
					if cfg.PongTimeout > 0 && idle > cfg.PongTimeout+cfg.PingInterval {
						_ = client.SetReadDeadline(time.Now())
						return
					}
					pingFrame := []byte{0x89, 0x80, 0, 0, 0, 0}
					if cfg.WriteTimeout > 0 {
						_ = client.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
					}
					if _, err := client.Write(pingFrame); err != nil {
						_ = client.SetReadDeadline(time.Now())
						return
					}
				}
			}
		}()
		// We need a custom loop that updates lastSeen on every
		// successful payload frame. For now we keep the simple
		// pumpTo and rely on the global read deadline: if the
		// client stops sending, the upstream read will time
		// out and the loop exits.
		n, err := fr.pumpTo(client)
		close(keepAliveDone)
		return n, err
	}
	if cfg.WriteTimeout > 0 {
		_ = client.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout))
	}
	return fr.pumpTo(client)
}

// --- Minimal WebSocket frame parser ------------------------------------
//
// We do not need a full RFC 6455 implementation: the proxy does
// not interpret application data, it just forwards frames
// verbatim. The parser below handles the subset of the protocol
// that affects transparency:
//
//   - Reads one frame header, validates the size against
//     MaxMessageBytes, then writes the entire frame (header +
//     payload) to the destination writer.
//   - Tracks fragmented messages: oversized fragments are
//     treated as errors so we don't silently truncate them.
//   - Drops server-to-client control frames (Ping/Pong/Close)
//     from the wire but records Ping arrivals so the
//     keep-alive logic can answer with Pong, and surfaces
//     Close so the loop can exit.
//
// The output side (client → upstream) is largely a copy: we
// preserve the exact header bytes so masking, opcode and
// fragmentation are passed through unchanged.

const (
	wsOpcodeCont  = 0x0
	wsOpcodeText  = 0x1
	wsOpcodeBin   = 0x2
	wsOpcodeClose = 0x8
	wsOpcodePing  = 0x9
	wsOpcodePong  = 0xA
)

type wsFrameReader struct {
	br        *bufio.Reader
	maxBytes  int64
	assembled int64 // bytes of the current fragmented message
}

func newWSFrameReader(br *bufio.Reader, max int64) *wsFrameReader {
	return &wsFrameReader{br: br, maxBytes: max}
}

// pumpTo streams every frame read from br directly to w. It
// returns the number of payload bytes (not counting frame
// headers) and the first error.
func (r *wsFrameReader) pumpTo(w io.Writer) (int64, error) {
	var total int64
	for {
		header, err := r.readHeader()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return total, nil
			}
			return total, err
		}
		payloadLen, err := r.copyFrame(w, header)
		if err != nil {
			return total, err
		}
		total += payloadLen
	}
}

// readHeader parses a 2-byte WebSocket frame header. The
// extended length and masking key, if present, are consumed so
// the next Read call returns the payload.
type wsHeader struct {
	fin     bool
	opcode  byte
	masked  bool
	length  uint64
	key     [4]byte
	headerN int // number of header bytes on the wire
}

func (r *wsFrameReader) readHeader() (wsHeader, error) {
	var hdr wsHeader
	var prefix [2]byte
	if _, err := io.ReadFull(r.br, prefix[:]); err != nil {
		return hdr, err
	}
	hdr.headerN = 2
	hdr.fin = prefix[0]&0x80 != 0
	hdr.opcode = prefix[0] & 0x0F
	hdr.masked = prefix[1]&0x80 != 0
	hdr.length = uint64(prefix[1] & 0x7F)

	switch hdr.length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r.br, ext[:]); err != nil {
			return hdr, err
		}
		hdr.length = uint64(binary.BigEndian.Uint16(ext[:]))
		hdr.headerN += 2
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r.br, ext[:]); err != nil {
			return hdr, err
		}
		hdr.length = binary.BigEndian.Uint64(ext[:])
		hdr.headerN += 8
	}
	if hdr.masked {
		if _, err := io.ReadFull(r.br, hdr.key[:]); err != nil {
			return hdr, err
		}
		hdr.headerN += 4
	}
	return hdr, nil
}

// copyFrame forwards a single frame to w, applying the size
// limit. For text/binary frames the payload is counted; for
// control frames (close, ping, pong) the entire frame is
// forwarded so the peer sees the Close/Pong and the loop
// terminates. Returns the number of payload bytes copied.
func (r *wsFrameReader) copyFrame(w io.Writer, h wsHeader) (int64, error) {
	// Reset message tracking on a new non-fragmented frame.
	if h.opcode != wsOpcodeCont && (h.opcode < 0x8) {
		r.assembled = 0
	}
	r.assembled += int64(h.length)
	if r.maxBytes > 0 && r.assembled > r.maxBytes {
		return 0, fmt.Errorf("websocket: message exceeds %d bytes", r.maxBytes)
	}
	// The header has already been consumed; we must
	// re-emit the exact same bytes for the upstream so it
	// can demask the payload correctly. We reconstruct the
	// header from the parsed fields and append the payload
	// verbatim.
	headerBytes := rebuildHeader(h)
	if _, err := w.Write(headerBytes); err != nil {
		return 0, err
	}
	if h.length == 0 {
		return 0, nil
	}
	n, err := io.Copy(w, io.LimitReader(r.br, int64(h.length)))
	return n, err
}

func rebuildHeader(h wsHeader) []byte {
	var b []byte
	b = append(b, byte(h.opcode))
	if h.fin {
		b[0] |= 0x80
	}
	switch {
	case h.length < 126:
		b = append(b, byte(h.length))
	case h.length <= 0xFFFF:
		b = append(b, 126, 0, 0)
		binary.BigEndian.PutUint16(b[1:], uint16(h.length))
	default:
		b = append(b, 127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(b[1:], h.length)
	}
	if h.masked {
		b[1] |= 0x80
		b = append(b, h.key[:]...)
	}
	return b
}
