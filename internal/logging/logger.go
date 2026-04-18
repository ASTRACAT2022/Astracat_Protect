package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

type Logger struct {
	format string
	out    io.Writer
}

type Entry struct {
	Timestamp        string  `json:"timestamp"`
	RemoteIP         string  `json:"remote_ip"`
	Host             string  `json:"host"`
	Method           string  `json:"method"`
	URI              string  `json:"uri"`
	Status           int     `json:"status"`
	LatencyMS        int64   `json:"latency_ms"`
	BytesIn          int64   `json:"bytes_in"`
	BytesOut         int64   `json:"bytes_out"`
	Upstream         string  `json:"upstream"`
	Route            string  `json:"route"`
	ChallengeApplied bool    `json:"challenge_applied"`
	RateLimited      bool    `json:"rate_limited"`
	Blocked          bool    `json:"blocked"`
	WAFBlocked       bool    `json:"waf_blocked,omitempty"`
	WAFScore         int     `json:"waf_score,omitempty"`
	WAFRules         string  `json:"waf_rules,omitempty"`
	WAFReason        string  `json:"waf_reason,omitempty"`
	WAFAction        string  `json:"waf_action,omitempty"`
	ThreatCategory   string  `json:"threat_category,omitempty"`
	ThreatAction     string  `json:"threat_action,omitempty"`
	ThreatIndicator  string  `json:"threat_indicator,omitempty"`
	ThreatReason     string  `json:"threat_reason,omitempty"`
	BotKind          string  `json:"bot_kind,omitempty"`
	BotProfile       string  `json:"bot_profile,omitempty"`
	BotAction        string  `json:"bot_action,omitempty"`
	BotReason        string  `json:"bot_reason,omitempty"`
	AIAction         string  `json:"ai_action,omitempty"`
	AIScore          float64 `json:"ai_score,omitempty"`
	AIReason         string  `json:"ai_reason,omitempty"`
}

func New(format string, output string) *Logger {
	out := io.Writer(os.Stdout)
	if output != "stdout" && output != "" {
		if f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
			out = f
		}
	}
	return &Logger{format: format, out: out}
}

type responseRecorder struct {
	w      http.ResponseWriter
	status int
	bytes  int
}

func (r *responseRecorder) Header() http.Header { return r.w.Header() }

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.status = statusCode
	r.w.WriteHeader(statusCode)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.w.Write(b)
	r.bytes += n
	return n, err
}

func (r *responseRecorder) Unwrap() http.ResponseWriter { return r.w }

func (l *Logger) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{w: w}
		next.ServeHTTP(rec, r)

		bytesIn := r.ContentLength
		if bytesIn < 0 {
			bytesIn = 0
		}

		entry := Entry{
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			RemoteIP:  clientIP(r.RemoteAddr),
			Host:      r.Host,
			Method:    r.Method,
			URI:       r.URL.RequestURI(),
			Status:    rec.status,
			LatencyMS: time.Since(start).Milliseconds(),
			BytesIn:   bytesIn,
			BytesOut:  int64(rec.bytes),
		}
		l.write(entry)
	})
}

func (l *Logger) Write(entry Entry) {
	l.write(entry)
}

func (l *Logger) write(entry Entry) {
	if l.format == "json" {
		b, _ := json.Marshal(entry)
		fmt.Fprintln(l.out, string(b))
		return
	}
	fmt.Fprintf(l.out, "%s %s %s %s %d %dms bytes_in=%d bytes_out=%d upstream=%s route=%s challenge=%t rate_limited=%t blocked=%t waf_action=%s waf_blocked=%t waf_score=%d waf_rules=%s waf_reason=%s threat_category=%s threat_action=%s threat_indicator=%s threat_reason=%s bot_kind=%s bot_profile=%s bot_action=%s bot_reason=%s ai_action=%s ai_score=%.3f ai_reason=%s\n",
		entry.Timestamp, entry.RemoteIP, entry.Method, entry.URI, entry.Status, entry.LatencyMS, entry.BytesIn, entry.BytesOut,
		entry.Upstream, entry.Route, entry.ChallengeApplied, entry.RateLimited, entry.Blocked,
		entry.WAFAction, entry.WAFBlocked, entry.WAFScore, entry.WAFRules, entry.WAFReason,
		entry.ThreatCategory, entry.ThreatAction, entry.ThreatIndicator, entry.ThreatReason,
		entry.BotKind, entry.BotProfile, entry.BotAction, entry.BotReason,
		entry.AIAction, entry.AIScore, entry.AIReason)
}

func clientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
