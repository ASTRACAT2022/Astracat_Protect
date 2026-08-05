package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// startFakeWSEchoUpstream launches a raw TCP listener that
// speaks just enough of the WebSocket protocol to act as the
// upstream side of the proxy. It accepts the upgrade, replies
// with a valid 101 Switching Protocols, then echoes every
// frame it receives back to the client. It returns the
// listening address and a cleanup function.
func startFakeWSEchoUpstream(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				close(done)
				return
			}
			go handleFakeWSEcho(c)
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
	}
}

func handleFakeWSEcho(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
		return
	}
	key := req.Header.Get("Sec-WebSocket-Key")
	accept := computeAcceptKey(key)
	resp := buildClient101(accept, "")
	c.Write([]byte(resp))

	// Echo: read frames with our reader, write them back
	// unchanged. Masking bits are preserved (we don't
	// re-mask on the way back since the proxy client
	// connection is server-to-client and so frames from the
	// upstream must be unmasked — which they are, because
	// the proxy's reader strips the mask before forwarding).
	fr := newWSFrameReader(br, 1<<20)
	fr.pumpTo(c)
}

// TestWebSocketRoundTrip exercises the full proxy pipeline:
// raw client → proxy (TLS-less) → raw upstream → echo back.
// We dial the proxy with a raw TCP connection, do a real
// WebSocket handshake, send one masked text frame, and
// verify we get a 101 with a correct Sec-WebSocket-Accept and
// the echo frame back.
func TestWebSocketRoundTrip(t *testing.T) {
	upstreamAddr, stopUpstream := startFakeWSEchoUpstream(t)
	defer stopUpstream()

	// Build a proxy whose upstream points at the raw listener.
	// Use http:// so the proxy dials plain TCP; the WS code
	// will dial ws:// automatically.
	p, err := NewUpstreamProxyWithWS("http://"+upstreamAddr, 2*time.Second, 5*time.Second, WSConfig{
		AllowedOrigins:  []string{"*"},
		MaxMessageBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("NewUpstreamProxyWithWS: %v", err)
	}
	var conns, rej, errs uint64
	p.SetWSMetrics(&conns, &rej, &errs)

	// Mount the proxy on an httptest server.
	proxySrv := httptest.NewServer(http.HandlerFunc(p.ServeHTTP))
	defer proxySrv.Close()

	// Dial the proxy and perform a WebSocket handshake.
	proxyURL, _ := url.Parse(proxySrv.URL)
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	key := "dGhlIHNhbXBsZSBub25jZQ=="
	handshake := "GET /ws HTTP/1.1\r\n" +
		"Host: " + proxyURL.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Origin: http://example.com\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(handshake)); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read 101: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}
	if got, want := resp.Header.Get("Sec-WebSocket-Accept"), computeAcceptKey(key); got != want {
		t.Fatalf("Sec-WebSocket-Accept = %q, want %q", got, want)
	}

	// Send one masked text frame.
	payload := []byte("hello")
	mask := []byte{0x01, 0x02, 0x03, 0x04}
	masked := make([]byte, len(payload))
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}
	frame := []byte{0x81, byte(0x80 | len(masked))}
	frame = append(frame, mask...)
	frame = append(frame, masked...)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	// Read echo. The proxy transparently forwards frames
	// between the two sockets, so the mask bit on the echo
	// is the same as on the original frame: client→upstream
	// frames stay masked per RFC 6455, and our fake upstream
	// echoes them verbatim. The proxy relays those bytes
	// back, so the client sees the mask bit still set.
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	opcode := hdr[0] & 0x0F
	maskedBit := hdr[1] & 0x80
	plen := int(hdr[1] & 0x7F)
	if opcode != 1 {
		t.Fatalf("expected text opcode, got %d", opcode)
	}
	if maskedBit == 0 {
		t.Fatalf("echoed frame unexpectedly unmasked")
	}
	mk := make([]byte, 4)
	if _, err := io.ReadFull(br, mk); err != nil {
		t.Fatalf("read mask key: %v", err)
	}
	body := make([]byte, plen)
	if _, err := io.ReadFull(br, body); err != nil {
		t.Fatalf("read frame body: %v", err)
	}
	for i := range body {
		body[i] ^= mk[i%4]
	}
	if string(body) != "hello" {
		t.Fatalf("echo body = %q, want %q", body, "hello")
	}

	// Allow a brief moment for the counter to be incremented
	// after the pump completes.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadUint64(&conns) >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := atomic.LoadUint64(&conns); got < 1 {
		t.Fatalf("WSConnections counter not incremented (got %d)", got)
	}
	if got := atomic.LoadUint64(&rej); got != 0 {
		t.Fatalf("WSRejected counter should be 0, got %d", got)
	}
}
