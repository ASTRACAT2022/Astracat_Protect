package limits

import (
	"net"
	"sync"
	"time"
)

type TokenBucket struct {
	Tokens float64
	Last   time.Time
}

type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*TokenBucket
	rps     float64
	burst   float64
	ttl     time.Duration
}

func NewRateLimiter(rps, burst float64, ttl time.Duration) *RateLimiter {
	return &RateLimiter{
		buckets: map[string]*TokenBucket{},
		rps:     rps,
		burst:   burst,
		ttl:     ttl,
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b := rl.buckets[ip]
	if b == nil {
		b = &TokenBucket{Tokens: rl.burst, Last: now}
		rl.buckets[ip] = b
	}
	elapsed := now.Sub(b.Last).Seconds()
	b.Tokens += elapsed * rl.rps
	if b.Tokens > rl.burst {
		b.Tokens = rl.burst
	}
	b.Last = now
	if b.Tokens < 1 {
		return false
	}
	b.Tokens -= 1
	return true
}

func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for k, v := range rl.buckets {
		if now.Sub(v.Last) > rl.ttl {
			delete(rl.buckets, k)
		}
	}
}

type ConnLimiter struct {
	mu       sync.Mutex
	counts   map[string]int
	wsCounts map[string]int
	limit    int
	wsLimit  int
}

func NewConnLimiter(limit, wsLimit int) *ConnLimiter {
	return &ConnLimiter{counts: map[string]int{}, wsCounts: map[string]int{}, limit: limit, wsLimit: wsLimit}
}

func (cl *ConnLimiter) Allow(ip string, ws bool) bool {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if ws {
		if cl.wsLimit > 0 && cl.wsCounts[ip] >= cl.wsLimit {
			return false
		}
		cl.wsCounts[ip]++
		return true
	}
	if cl.limit > 0 && cl.counts[ip] >= cl.limit {
		return false
	}
	cl.counts[ip]++
	return true
}

func (cl *ConnLimiter) Done(ip string, ws bool) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if ws {
		if cl.wsCounts[ip] > 0 {
			cl.wsCounts[ip]--
		}
		return
	}
	if cl.counts[ip] > 0 {
		cl.counts[ip]--
	}
}

func ClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
