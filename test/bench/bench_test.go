package bench_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/router"
)

// ---------------------------------------------------------------------------
// httpProxyBenchmark is the core driver for HTTP proxy benchmarks.
// It boots a mock upstream, compiles a router, builds a filter chain, then
// runs concurrent requests through the pipeline + proxy loop.
// ---------------------------------------------------------------------------
func httpProxyBenchmark(b *testing.B, numFilters int, filterFactory func(int) pipeline.Filter) {
	b.Helper()

	upstream := mockUpstream()
	defer upstream.Close()

	// Build config snapshot pointing at the mock upstream.
	snap := &config.Snapshot{
		Version: 1,
		Routes: []config.RouteRule{
			{ID: "bench-route", Path: "/v1/chat/completions", Method: "POST", UpstreamID: "llm-upstream"},
		},
		Upstreams: map[string]config.UpstreamCluster{
			"llm-upstream": {ID: "llm-upstream", Protocol: "http", Endpoints: []string{upstream.URL}},
		},
	}

	rtr := router.Compile(snap)

	// Build filter chain.
	filters := make([]pipeline.Filter, numFilters)
	for i := 0; i < numFilters; i++ {
		if filterFactory != nil {
			filters[i] = filterFactory(i)
		} else {
			filters[i] = newNoopFilter(fmt.Sprintf("noop-%d", i), pipeline.PhaseRequestHeaders)
		}
	}
	chain := pipeline.NewChain(filters...)

	client := upstream.Client()

	lc := newLatencyCollector(b.N)
	before := captureMemStats()
	start := time.Now()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reqStart := time.Now()

			// 1. Route match
			match, err := rtr.Match(router.MatchCriteria{
				Method: "POST",
				Path:   "/v1/chat/completions",
			})
			if err != nil {
				b.Fatalf("route match failed: %v", err)
			}

			// 2. Get pooled envelope
			env := pipeline.GetEnvelope("bench-req", pipeline.PhaseRequestHeaders, "POST", "/v1/chat/completions", nil, nil)
			env.Route = match.Route
			env.Upstream = match.Upstream

			// 3. Run filter chain
			decision, err := chain.ExecutePhase(context.Background(), env, pipeline.PhaseRequestHeaders, 0)
			if err != nil || decision.Action == pipeline.ActionHalt {
				pipeline.PutEnvelope(env)
				b.Fatalf("filter chain failed: %v action=%v", err, decision.Action)
			}

			// 4. Proxy to upstream
			req, _ := http.NewRequest("POST", upstream.URL+"/v1/chat/completions",
				strings.NewReader(`{"model":"gpt-4","messages":[]}`))
			resp, err := client.Do(req)
			if err != nil {
				pipeline.PutEnvelope(env)
				b.Fatalf("upstream call failed: %v", err)
			}
			drainBody(resp)

			pipeline.PutEnvelope(env)
			lc.Record(time.Since(reqStart))
		}
	})

	elapsed := time.Since(start)
	after := captureMemStats()
	b.StopTimer()

	reportStats(b, lc, before, after, elapsed)
}

// ---------------------------------------------------------------------------
// HTTP Proxy Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkHTTP_Proxy_0Filters(b *testing.B) {
	httpProxyBenchmark(b, 0, nil)
}

func BenchmarkHTTP_Proxy_1Filter(b *testing.B) {
	httpProxyBenchmark(b, 1, nil)
}

func BenchmarkHTTP_Proxy_5Filters(b *testing.B) {
	httpProxyBenchmark(b, 5, nil)
}

// ---------------------------------------------------------------------------
// SSE Streaming Benchmark
// ---------------------------------------------------------------------------

func BenchmarkSSE_Stream(b *testing.B) {
	upstream := mockSSEUpstream(20) // 20 SSE events per request
	defer upstream.Close()

	snap := &config.Snapshot{
		Version: 1,
		Routes: []config.RouteRule{
			{ID: "sse-route", Path: "/v1/chat/completions", Method: "POST", UpstreamID: "sse-upstream"},
		},
		Upstreams: map[string]config.UpstreamCluster{
			"sse-upstream": {ID: "sse-upstream", Protocol: "http", Endpoints: []string{upstream.URL}},
		},
	}

	rtr := router.Compile(snap)
	chain := buildChain(1)
	client := upstream.Client()

	lc := newLatencyCollector(b.N)
	before := captureMemStats()
	start := time.Now()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reqStart := time.Now()

			_, _ = rtr.Match(router.MatchCriteria{Method: "POST", Path: "/v1/chat/completions"})

			env := pipeline.GetEnvelope("sse-req", pipeline.PhaseRequestHeaders, "POST", "/v1/chat/completions", nil, nil)
			_, _ = chain.ExecutePhase(context.Background(), env, pipeline.PhaseRequestHeaders, 0)

			req, _ := http.NewRequest("POST", upstream.URL+"/v1/chat/completions", nil)
			resp, err := client.Do(req)
			if err == nil {
				// Stream all SSE chunks
				buf := make([]byte, 4096)
				for {
					_, readErr := resp.Body.Read(buf)
					if readErr != nil {
						break
					}
				}
				_ = resp.Body.Close()
			}

			pipeline.PutEnvelope(env)
			lc.Record(time.Since(reqStart))
		}
	})

	elapsed := time.Since(start)
	after := captureMemStats()
	b.StopTimer()
	reportStats(b, lc, before, after, elapsed)
}

// ---------------------------------------------------------------------------
// Pipeline Chain Microbenchmarks (no network, pure filter overhead)
// ---------------------------------------------------------------------------

func BenchmarkPipelineChain_0Filters(b *testing.B) {
	chain := buildChain(0)
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			env := pipeline.GetEnvelope("pipe-bench", pipeline.PhaseRequestHeaders, "POST", "/v1/chat", nil, nil)
			_, _ = chain.ExecutePhase(context.Background(), env, pipeline.PhaseRequestHeaders, 0)
			pipeline.PutEnvelope(env)
		}
	})
}

func BenchmarkPipelineChain_1Filter(b *testing.B) {
	chain := buildChain(1)
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			env := pipeline.GetEnvelope("pipe-bench", pipeline.PhaseRequestHeaders, "POST", "/v1/chat", nil, nil)
			_, _ = chain.ExecutePhase(context.Background(), env, pipeline.PhaseRequestHeaders, 0)
			pipeline.PutEnvelope(env)
		}
	})
}

func BenchmarkPipelineChain_5Filters(b *testing.B) {
	chain := buildChain(5)
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			env := pipeline.GetEnvelope("pipe-bench", pipeline.PhaseRequestHeaders, "POST", "/v1/chat", nil, nil)
			_, _ = chain.ExecutePhase(context.Background(), env, pipeline.PhaseRequestHeaders, 0)
			pipeline.PutEnvelope(env)
		}
	})
}

// ---------------------------------------------------------------------------
// Router Match Microbenchmark
// ---------------------------------------------------------------------------

func BenchmarkRouterMatch(b *testing.B) {
	snap := &config.Snapshot{
		Version: 1,
		Routes: []config.RouteRule{
			{ID: "r1", Path: "/v1/chat/completions", Method: "POST", UpstreamID: "up1"},
			{ID: "r2", Path: "/v1/embeddings", Method: "POST", UpstreamID: "up1"},
			{ID: "r3", Path: "/v1/models", Method: "GET", UpstreamID: "up1"},
			{ID: "r4", Path: "/healthz", Method: "GET", UpstreamID: "up1"},
			{ID: "prefix", Path: "/api/", PathPrefix: true, UpstreamID: "up1"},
		},
		Upstreams: map[string]config.UpstreamCluster{
			"up1": {ID: "up1", Protocol: "http", Endpoints: []string{"http://localhost:9999"}},
		},
	}

	rtr := router.Compile(snap)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = rtr.Match(router.MatchCriteria{Method: "POST", Path: "/v1/chat/completions"})
		}
	})
}

// ---------------------------------------------------------------------------
// End-to-end HTTP proxy via httptest (measures actual net/http overhead)
// ---------------------------------------------------------------------------

func BenchmarkHTTP_EndToEnd_httptest(b *testing.B) {
	upstream := mockUpstream()
	defer upstream.Close()

	// Build a simple proxy handler.
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get(upstream.URL + r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})

	ts := httptest.NewServer(proxyHandler)
	defer ts.Close()

	client := ts.Client()

	lc := newLatencyCollector(b.N)
	before := captureMemStats()
	start := time.Now()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reqStart := time.Now()
			resp, err := client.Get(ts.URL + "/v1/chat/completions")
			if err != nil {
				b.Fatalf("request failed: %v", err)
			}
			drainBody(resp)
			lc.Record(time.Since(reqStart))
		}
	})

	elapsed := time.Since(start)
	after := captureMemStats()
	b.StopTimer()
	reportStats(b, lc, before, after, elapsed)
}
