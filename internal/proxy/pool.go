package proxy

import (
	"net/http"
	"strings"
	"sync/atomic"
)

const (
	LBPolicyRoundRobin = "round_robin"
	LBPolicyLeastConn  = "least_conn"
)

type Pool struct {
	policy   string
	backends []poolBackend
	rr       uint64
}

type poolBackend struct {
	proxy  *UpstreamProxy
	active int64
}

func NewPool(policy string, backends []*UpstreamProxy) *Pool {
	clean := make([]poolBackend, 0, len(backends))
	for _, b := range backends {
		if b != nil {
			clean = append(clean, poolBackend{proxy: b})
		}
	}
	return &Pool{
		policy:   normalizePolicy(policy),
		backends: clean,
	}
}

func (p *Pool) ServeHTTP(w http.ResponseWriter, r *http.Request) string {
	if p == nil || len(p.backends) == 0 {
		return ""
	}
	idx := p.pick()
	b := &p.backends[idx]
	atomic.AddInt64(&b.active, 1)
	defer atomic.AddInt64(&b.active, -1)
	b.proxy.ServeHTTP(w, r)
	return b.proxy.Upstream
}

func normalizePolicy(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "least_conn", "leastconn":
		return LBPolicyLeastConn
	default:
		return LBPolicyRoundRobin
	}
}

func (p *Pool) pick() int {
	if len(p.backends) == 1 {
		return 0
	}
	switch p.policy {
	case LBPolicyLeastConn:
		start := int(atomic.AddUint64(&p.rr, 1) % uint64(len(p.backends)))
		minIdx := start
		minLoad := atomic.LoadInt64(&p.backends[start].active)
		for i := 1; i < len(p.backends); i++ {
			idx := (start + i) % len(p.backends)
			load := atomic.LoadInt64(&p.backends[idx].active)
			if load < minLoad {
				minLoad = load
				minIdx = idx
			}
		}
		return minIdx
	default:
		return int(atomic.AddUint64(&p.rr, 1) % uint64(len(p.backends)))
	}
}
