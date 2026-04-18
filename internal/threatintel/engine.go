package threatintel

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"astracat-protect/internal/config"
)

type Decision struct {
	Matched   bool
	Action    string
	Category  string // ip | asn | ja3
	Indicator string
	Reason    string
}

type CheckInput struct {
	IP  string
	ASN string
	JA3 string
	TLS *TLSFingerprintInput
}

type TLSFingerprintInput struct {
	Version    uint16
	Cipher     uint16
	ServerName string
	ALPN       string
}

type Engine struct {
	cfg      normalizedConfig
	mu       sync.RWMutex
	snapshot snapshot
	stopCh   chan struct{}
	doneCh   chan struct{}
}

type normalizedConfig struct {
	enabled     bool
	action      string
	refresh     time.Duration
	ipFeeds     []string
	asnFeeds    []string
	ja3Feeds    []string
	ipInline    []string
	asnInline   []string
	ja3Inline   []string
	asnHeader   string
	ja3Header   string
	httpTimeout time.Duration
}

type snapshot struct {
	ipExact   map[string]iocItem
	ipNets    []iocNet
	asnSet    map[string]iocItem
	asnRanges []asnRange
	ja3Set    map[string]iocItem
}

type iocItem struct {
	reason string
}

type iocNet struct {
	net  *net.IPNet
	item iocItem
}

type asnRange struct {
	asn string
	net *net.IPNet
}

func New(cfg config.ThreatIntelConfig) (*Engine, error) {
	ncfg := normalize(cfg)
	e := &Engine{
		cfg:    ncfg,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	if !ncfg.enabled {
		return e, nil
	}
	if err := e.reload(); err != nil {
		return nil, err
	}
	go e.refreshLoop()
	return e, nil
}

func (e *Engine) Enabled() bool {
	return e != nil && e.cfg.enabled
}

func (e *Engine) ASNHeader() string {
	if e == nil {
		return "X-ASN"
	}
	return e.cfg.asnHeader
}

func (e *Engine) JA3Header() string {
	if e == nil {
		return "X-JA3"
	}
	return e.cfg.ja3Header
}

func (e *Engine) Close() {
	if e == nil || !e.Enabled() {
		return
	}
	close(e.stopCh)
	<-e.doneCh
}

func (e *Engine) Check(in CheckInput) Decision {
	if !e.Enabled() {
		return Decision{}
	}
	s := e.current()
	ip := strings.TrimSpace(in.IP)
	if ip != "" {
		if item, ok := s.ipExact[ip]; ok {
			return Decision{
				Matched:   true,
				Action:    e.cfg.action,
				Category:  "ip",
				Indicator: ip,
				Reason:    withDefaultReason(item.reason, "matched ip indicator"),
			}
		}
		if parsed := net.ParseIP(ip); parsed != nil {
			for _, n := range s.ipNets {
				if n.net != nil && n.net.Contains(parsed) {
					return Decision{
						Matched:   true,
						Action:    e.cfg.action,
						Category:  "ip",
						Indicator: n.net.String(),
						Reason:    withDefaultReason(n.item.reason, "matched ip network indicator"),
					}
				}
			}
		}
	}

	asn := normalizeASN(in.ASN)
	if asn == "" && ip != "" {
		asn = s.lookupASNByIP(ip)
	}
	if asn != "" {
		if item, ok := s.asnSet[asn]; ok {
			return Decision{
				Matched:   true,
				Action:    e.cfg.action,
				Category:  "asn",
				Indicator: asn,
				Reason:    withDefaultReason(item.reason, "matched asn indicator"),
			}
		}
	}

	ja3 := normalizeJA3(in.JA3)
	if ja3 == "" && in.TLS != nil {
		ja3 = pseudoJA3(in.TLS)
	}
	if ja3 != "" {
		if item, ok := s.ja3Set[ja3]; ok {
			return Decision{
				Matched:   true,
				Action:    e.cfg.action,
				Category:  "ja3",
				Indicator: ja3,
				Reason:    withDefaultReason(item.reason, "matched ja3 indicator"),
			}
		}
	}
	return Decision{}
}

func (e *Engine) refreshLoop() {
	defer close(e.doneCh)
	t := time.NewTicker(e.cfg.refresh)
	defer t.Stop()
	for {
		select {
		case <-e.stopCh:
			return
		case <-t.C:
			_ = e.reload()
		}
	}
}

func (e *Engine) reload() error {
	next := snapshot{
		ipExact:   map[string]iocItem{},
		ipNets:    make([]iocNet, 0, 128),
		asnSet:    map[string]iocItem{},
		asnRanges: make([]asnRange, 0, 128),
		ja3Set:    map[string]iocItem{},
	}

	for _, raw := range e.cfg.ipInline {
		parseIPLine(raw, "inline", &next)
	}
	for _, src := range e.cfg.ipFeeds {
		if lines, err := e.fetchLines(src); err == nil {
			for _, line := range lines {
				parseIPLine(line, src, &next)
			}
		}
	}

	for _, raw := range e.cfg.asnInline {
		parseASNLine(raw, "inline", &next)
	}
	for _, src := range e.cfg.asnFeeds {
		if lines, err := e.fetchLines(src); err == nil {
			for _, line := range lines {
				parseASNLine(line, src, &next)
			}
		}
	}

	for _, raw := range e.cfg.ja3Inline {
		parseJA3Line(raw, "inline", &next)
	}
	for _, src := range e.cfg.ja3Feeds {
		if lines, err := e.fetchLines(src); err == nil {
			for _, line := range lines {
				parseJA3Line(line, src, &next)
			}
		}
	}

	e.mu.Lock()
	e.snapshot = next
	e.mu.Unlock()
	return nil
}

func (e *Engine) current() snapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.snapshot
}

func (s snapshot) lookupASNByIP(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return ""
	}
	for _, r := range s.asnRanges {
		if r.net != nil && r.net.Contains(parsed) {
			return r.asn
		}
	}
	return ""
}

func (e *Engine) fetchLines(source string) ([]string, error) {
	content, err := e.fetch(source)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, 128)
	sc := bufio.NewScanner(bytes.NewReader(content))
	for sc.Scan() {
		line := sanitizeFeedLine(sc.Text())
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

func (e *Engine) fetch(source string) ([]byte, error) {
	src := strings.TrimSpace(source)
	if src == "" {
		return nil, fmt.Errorf("empty source")
	}
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		client := &http.Client{Timeout: e.cfg.httpTimeout}
		resp, err := client.Get(src)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	}
	if strings.HasPrefix(src, "file://") {
		src = strings.TrimPrefix(src, "file://")
	}
	return os.ReadFile(src)
}

func parseIPLine(raw, source string, snap *snapshot) {
	fields := splitLineFields(raw)
	if len(fields) == 0 {
		return
	}
	indicator := fields[0]
	reason := ""
	if len(fields) > 1 {
		reason = strings.TrimSpace(fields[1])
	}
	if source != "" && reason == "" {
		reason = "feed:" + source
	}
	if ip := net.ParseIP(indicator); ip != nil {
		snap.ipExact[ip.String()] = iocItem{reason: reason}
		return
	}
	if strings.Contains(indicator, "/") {
		_, n, err := net.ParseCIDR(indicator)
		if err == nil && n != nil {
			snap.ipNets = append(snap.ipNets, iocNet{net: n, item: iocItem{reason: reason}})
		}
	}
}

func parseASNLine(raw, source string, snap *snapshot) {
	fields := splitLineFields(raw)
	if len(fields) == 0 {
		return
	}
	reason := ""
	if len(fields) > 2 {
		reason = strings.TrimSpace(fields[2])
	}
	feedReason := ""
	if source != "" {
		feedReason = "feed:" + source
	}

	a := normalizeASN(fields[0])
	b := strings.TrimSpace(fields[1])
	// Form: AS13335
	if a != "" && b == "" {
		if reason == "" {
			reason = feedReason
		}
		snap.asnSet[a] = iocItem{reason: reason}
		return
	}
	// Form: AS13335,reason
	if a != "" && b != "" && normalizeASN(b) == "" && !isNetworkToken(b) {
		if strings.TrimSpace(reason) == "" {
			reason = strings.TrimSpace(b)
		}
		snap.asnSet[a] = iocItem{reason: reason}
		return
	}

	// Forms: AS13335,1.1.1.0/24   OR   1.1.1.0/24,AS13335
	var asn string
	var network string
	if a != "" {
		asn = a
		network = b
	} else {
		asn = normalizeASN(b)
		network = strings.TrimSpace(fields[0])
	}
	if asn == "" {
		return
	}
	if reason == "" {
		reason = feedReason
	}
	snap.asnSet[asn] = iocItem{reason: reason}
	if network == "" {
		return
	}
	if ip := net.ParseIP(network); ip != nil {
		maskBits := 32
		if ip.To4() == nil {
			maskBits = 128
		}
		network = ip.String() + "/" + intToString(maskBits)
	}
	_, cidr, err := net.ParseCIDR(network)
	if err == nil && cidr != nil {
		snap.asnRanges = append(snap.asnRanges, asnRange{asn: asn, net: cidr})
	}
}

func isNetworkToken(v string) bool {
	s := strings.TrimSpace(v)
	if s == "" {
		return false
	}
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

func parseJA3Line(raw, source string, snap *snapshot) {
	fields := splitLineFields(raw)
	if len(fields) == 0 {
		return
	}
	indicator := normalizeJA3(fields[0])
	if indicator == "" {
		return
	}
	reason := ""
	if len(fields) > 1 {
		reason = strings.TrimSpace(fields[1])
	}
	if source != "" && reason == "" {
		reason = "feed:" + source
	}
	snap.ja3Set[indicator] = iocItem{reason: reason}
}

func splitLineFields(line string) []string {
	items := strings.Split(line, ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		v := strings.TrimSpace(item)
		if v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	if len(out) == 1 {
		return []string{out[0], "", ""}
	}
	if len(out) == 2 {
		return []string{out[0], out[1], ""}
	}
	return out
}

func sanitizeFeedLine(line string) string {
	v := strings.TrimSpace(line)
	if v == "" {
		return ""
	}
	if strings.HasPrefix(v, "#") {
		return ""
	}
	if idx := strings.Index(v, "#"); idx >= 0 {
		v = strings.TrimSpace(v[:idx])
	}
	return v
}

func normalize(cfg config.ThreatIntelConfig) normalizedConfig {
	action := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(cfg.Action, "-", "_")))
	switch action {
	case "block", "challenge", "rate_limit", "log":
	default:
		action = "block"
	}
	refresh := cfg.RefreshSeconds
	if refresh <= 0 {
		refresh = 300
	}
	asnHeader := strings.TrimSpace(cfg.ASNHeader)
	if asnHeader == "" {
		asnHeader = "X-ASN"
	}
	ja3Header := strings.TrimSpace(cfg.JA3Header)
	if ja3Header == "" {
		ja3Header = "X-JA3"
	}
	return normalizedConfig{
		enabled:     cfg.Enabled,
		action:      action,
		refresh:     time.Duration(refresh) * time.Second,
		ipFeeds:     dedupStrings(cfg.IPFeeds),
		asnFeeds:    dedupStrings(cfg.ASNFeeds),
		ja3Feeds:    dedupStrings(cfg.JA3Feeds),
		ipInline:    dedupStrings(cfg.IPs),
		asnInline:   dedupStrings(cfg.ASNs),
		ja3Inline:   dedupStrings(cfg.JA3),
		asnHeader:   asnHeader,
		ja3Header:   ja3Header,
		httpTimeout: 20 * time.Second,
	}
}

func dedupStrings(values []string) []string {
	set := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if _, ok := set[v]; ok {
			continue
		}
		set[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func normalizeASN(v string) string {
	s := strings.ToUpper(strings.TrimSpace(v))
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "AS") {
		s = strings.TrimPrefix(s, "AS")
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return ""
		}
	}
	if s == "" {
		return ""
	}
	return "AS" + s
}

func normalizeJA3(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, " ", "")
	return s
}

func pseudoJA3(in *TLSFingerprintInput) string {
	if in == nil {
		return ""
	}
	// Real JA3 requires raw ClientHello extensions; not available in net/http.
	// We derive a stable pseudo-fingerprint and hash it to match feed style.
	raw := fmt.Sprintf("%d,%d,%s,%s", in.Version, in.Cipher, strings.ToLower(strings.TrimSpace(in.ServerName)), strings.ToLower(strings.TrimSpace(in.ALPN)))
	sum := md5.Sum([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func withDefaultReason(v, fallback string) string {
	v = strings.TrimSpace(v)
	if v != "" {
		return v
	}
	return fallback
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
