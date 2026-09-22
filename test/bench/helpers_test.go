package bench_test

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/pipeline"
)

// ---------------------------------------------------------------------------
// noopFilter is a zero-overhead filter for measuring pipeline chain overhead.
// ---------------------------------------------------------------------------
type noopFilter struct {
	name          string
	phase         pipeline.Phase
	bodyMode      pipeline.BodyMode
	failurePolicy pipeline.FailurePolicy
}

func newNoopFilter(name string, phase pipeline.Phase) *noopFilter {
	return &noopFilter{
		name:          name,
		phase:         phase,
		bodyMode:      pipeline.BodyModeNone,
		failurePolicy: pipeline.FailurePolicyFailClosed,
	}
}

func (f *noopFilter) Name() string                         { return f.name }
func (f *noopFilter) Phase() pipeline.Phase                 { return f.phase }
func (f *noopFilter) BodyMode() pipeline.BodyMode           { return f.bodyMode }
func (f *noopFilter) FailurePolicy() pipeline.FailurePolicy { return f.failurePolicy }
func (f *noopFilter) Close() error                          { return nil }

func (f *noopFilter) Process(_ context.Context, _ *pipeline.Envelope) (pipeline.Decision, error) {
	return pipeline.ContinueDecision(), nil
}

// ---------------------------------------------------------------------------
// panicFilter is a filter that panics on Process — used for chaos tests.
// ---------------------------------------------------------------------------
type panicFilter struct {
	noopFilter
}

func newPanicFilter(name string) *panicFilter {
	return &panicFilter{noopFilter: *newNoopFilter(name, pipeline.PhaseRequestHeaders)}
}

func (f *panicFilter) Process(_ context.Context, _ *pipeline.Envelope) (pipeline.Decision, error) {
	panic("intentional plugin crash for chaos testing")
}

// ---------------------------------------------------------------------------
// latencyCollector records per-request latencies for percentile computation.
// Thread-safe via mutex; sorts lazily on first percentile query.
// ---------------------------------------------------------------------------
type latencyCollector struct {
	mu       sync.Mutex
	samples  []time.Duration
	sorted   bool
	count    atomic.Int64
}

func newLatencyCollector(cap int) *latencyCollector {
	return &latencyCollector{
		samples: make([]time.Duration, 0, cap),
	}
}

func (c *latencyCollector) Record(d time.Duration) {
	c.mu.Lock()
	c.samples = append(c.samples, d)
	c.sorted = false
	c.mu.Unlock()
	c.count.Add(1)
}

func (c *latencyCollector) ensureSorted() {
	if !c.sorted {
		sort.Slice(c.samples, func(i, j int) bool { return c.samples[i] < c.samples[j] })
		c.sorted = true
	}
}

func (c *latencyCollector) Percentile(p float64) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.samples) == 0 {
		return 0
	}
	c.ensureSorted()
	idx := int(math.Ceil(p/100.0*float64(len(c.samples)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(c.samples) {
		idx = len(c.samples) - 1
	}
	return c.samples[idx]
}

func (c *latencyCollector) Count() int64 {
	return c.count.Load()
}

// ---------------------------------------------------------------------------
// memSnapshot captures runtime.MemStats for delta reporting.
// ---------------------------------------------------------------------------
type memSnapshot struct {
	HeapAlloc    uint64
	TotalAlloc   uint64
	NumGC        uint32
	PauseTotalNs uint64
	Mallocs      uint64
}

func captureMemStats() memSnapshot {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return memSnapshot{
		HeapAlloc:    m.HeapAlloc,
		TotalAlloc:   m.TotalAlloc,
		NumGC:        m.NumGC,
		PauseTotalNs: m.PauseTotalNs,
		Mallocs:      m.Mallocs,
	}
}

func reportStats(b *testing.B, lc *latencyCollector, before, after memSnapshot, elapsed time.Duration) {
	b.Helper()
	rps := float64(b.N) / elapsed.Seconds()
	b.ReportMetric(rps, "rps")
	b.ReportMetric(float64(lc.Percentile(50).Microseconds()), "p50_us")
	b.ReportMetric(float64(lc.Percentile(99).Microseconds()), "p99_us")
	b.ReportMetric(float64(lc.Percentile(99.9).Microseconds()), "p99.9_us")
	b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/1024, "heap_delta_kb")
	b.ReportMetric(float64(after.TotalAlloc-before.TotalAlloc)/1024/1024, "total_alloc_mb")
	b.ReportMetric(float64(after.NumGC-before.NumGC), "gc_cycles")
	b.ReportMetric(float64(after.PauseTotalNs-before.PauseTotalNs)/1e6, "gc_pause_ms")
}

// ---------------------------------------------------------------------------
// mockUpstream returns an httptest.Server that echoes 200 with a small body.
// ---------------------------------------------------------------------------
func mockUpstream() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","model":"gpt-4"}`))
		_ = r.Body.Close()
	}))
}

// ---------------------------------------------------------------------------
// mockSSEUpstream returns an httptest.Server that streams SSE events.
// ---------------------------------------------------------------------------
func mockSSEUpstream(numEvents int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		for i := 0; i < numEvents; i++ {
			_, _ = fmt.Fprintf(w, "data: {\"chunk\":%d}\n\n", i)
			if ok {
				flusher.Flush()
			}
		}
		_ = r.Body.Close()
	}))
}

// ---------------------------------------------------------------------------
// drainBody fully reads and discards a response body.
// ---------------------------------------------------------------------------
func drainBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

// ---------------------------------------------------------------------------
// buildChain constructs a pipeline.Chain with N noop filters.
// ---------------------------------------------------------------------------
func buildChain(n int) *pipeline.Chain {
	filters := make([]pipeline.Filter, n)
	for i := 0; i < n; i++ {
		filters[i] = newNoopFilter(fmt.Sprintf("noop-%d", i), pipeline.PhaseRequestHeaders)
	}
	return pipeline.NewChain(filters...)
}
