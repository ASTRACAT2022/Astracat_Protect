package metrics

import (
	"fmt"
	"io"
	"sort"
	"sync/atomic"
	"time"
)

type Histogram struct {
	buckets []float64
	counts  []uint64
}

func NewHistogram(buckets []float64) *Histogram {
	counts := make([]uint64, len(buckets)+1)
	return &Histogram{buckets: buckets, counts: counts}
}

func (h *Histogram) Observe(value float64) {
	idx := len(h.buckets)
	for i, b := range h.buckets {
		if value <= b {
			idx = i
			break
		}
	}
	atomic.AddUint64(&h.counts[idx], 1)
}

func (h *Histogram) Snapshot() ([]float64, []uint64) {
	b := append([]float64(nil), h.buckets...)
	c := make([]uint64, len(h.counts))
	for i := range c {
		c[i] = atomic.LoadUint64(&h.counts[i])
	}
	return b, c
}

type Registry struct {
	Requests         uint64
	UpstreamErrors   uint64
	RateLimited      uint64
	ChallengeServed  uint64
	WAFBlocked       uint64
	WSActive         int64
	LatencyHistogram *Histogram
}

func NewRegistry() *Registry {
	return &Registry{
		LatencyHistogram: NewHistogram([]float64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}),
	}
}

func (r *Registry) ObserveLatency(d time.Duration) {
	ms := float64(d.Milliseconds())
	if ms < 0 {
		ms = 0
	}
	r.LatencyHistogram.Observe(ms)
}

func (r *Registry) WritePrometheus(w io.Writer) {
	fmt.Fprintln(w, "# TYPE astracat_requests_total counter")
	fmt.Fprintf(w, "astracat_requests_total %d\n", atomic.LoadUint64(&r.Requests))
	fmt.Fprintln(w, "# TYPE astracat_upstream_errors_total counter")
	fmt.Fprintf(w, "astracat_upstream_errors_total %d\n", atomic.LoadUint64(&r.UpstreamErrors))
	fmt.Fprintln(w, "# TYPE astracat_rate_limited_total counter")
	fmt.Fprintf(w, "astracat_rate_limited_total %d\n", atomic.LoadUint64(&r.RateLimited))
	fmt.Fprintln(w, "# TYPE astracat_challenge_served_total counter")
	fmt.Fprintf(w, "astracat_challenge_served_total %d\n", atomic.LoadUint64(&r.ChallengeServed))
	fmt.Fprintln(w, "# TYPE astracat_waf_blocked_total counter")
	fmt.Fprintf(w, "astracat_waf_blocked_total %d\n", atomic.LoadUint64(&r.WAFBlocked))
	fmt.Fprintln(w, "# TYPE astracat_ws_active gauge")
	fmt.Fprintf(w, "astracat_ws_active %d\n", atomic.LoadInt64(&r.WSActive))

	buckets, counts := r.LatencyHistogram.Snapshot()
	fmt.Fprintln(w, "# TYPE astracat_latency_ms histogram")
	var cumulative uint64
	for i, b := range buckets {
		cumulative += counts[i]
		fmt.Fprintf(w, "astracat_latency_ms_bucket{le=\"%g\"} %d\n", b, cumulative)
	}
	cumulative += counts[len(counts)-1]
	fmt.Fprintf(w, "astracat_latency_ms_bucket{le=\"+Inf\"} %d\n", cumulative)
	fmt.Fprintf(w, "astracat_latency_ms_count %d\n", cumulative)

	sum := estimateSum(buckets, counts)
	fmt.Fprintf(w, "astracat_latency_ms_sum %g\n", sum)
}

func estimateSum(buckets []float64, counts []uint64) float64 {
	values := append([]float64(nil), buckets...)
	values = append(values, buckets[len(buckets)-1]*2)
	pairs := make([]struct {
		v float64
		c uint64
	}, len(counts))
	for i := range counts {
		pairs[i] = struct {
			v float64
			c uint64
		}{v: values[i], c: counts[i]}
	}
	// already sorted by bucket
	_ = sort.Float64s
	var sum float64
	for _, p := range pairs {
		sum += float64(p.c) * p.v
	}
	return sum
}
