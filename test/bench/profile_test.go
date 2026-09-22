package bench_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/router"
)

const profileDuration = 5 * time.Second

// ensureOutDir creates test/bench/out/ for profile output files.
func ensureOutDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("out")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("failed to create out dir: %v", err)
	}
	return dir
}

// runLoadBurst generates sustained load for the given duration.
func runLoadBurst(t *testing.T, duration time.Duration) {
	t.Helper()

	upstream := mockUpstream()
	defer upstream.Close()

	snap := &config.Snapshot{
		Version: 1,
		Routes: []config.RouteRule{
			{ID: "prof-route", Path: "/v1/chat/completions", Method: "POST", UpstreamID: "up"},
		},
		Upstreams: map[string]config.UpstreamCluster{
			"up": {ID: "up", Protocol: "http", Endpoints: []string{upstream.URL}},
		},
	}

	rtr := router.Compile(snap)
	chain := buildChain(3)
	client := upstream.Client()

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	for i := 0; i < runtime.GOMAXPROCS(0)*2; i++ {
		go func() {
			for ctx.Err() == nil {
				match, _ := rtr.Match(router.MatchCriteria{Method: "POST", Path: "/v1/chat/completions"})
				env := pipeline.GetEnvelope("prof", pipeline.PhaseRequestHeaders, "POST", "/v1/chat/completions", nil, nil)
				env.Route = match.Route
				_, _ = chain.ExecutePhase(ctx, env, pipeline.PhaseRequestHeaders, 0)

				req, _ := http.NewRequestWithContext(ctx, "POST", upstream.URL+"/v1/chat/completions",
					strings.NewReader(`{"model":"gpt-4","messages":[]}`))
				resp, err := client.Do(req)
				if err == nil {
					drainBody(resp)
				}
				pipeline.PutEnvelope(env)
			}
		}()
	}

	<-ctx.Done()
}

// TestProfile_CPU captures a CPU profile under sustained load.
func TestProfile_CPU(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping profiling in short mode")
	}

	dir := ensureOutDir(t)
	path := filepath.Join(dir, "cpu.prof")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create cpu.prof: %v", err)
	}
	defer f.Close()

	if err := pprof.StartCPUProfile(f); err != nil {
		t.Fatalf("start cpu profile: %v", err)
	}

	runLoadBurst(t, profileDuration)

	pprof.StopCPUProfile()
	t.Logf("CPU profile written to %s", path)
	t.Logf("Analyze with: go tool pprof -http=:6060 %s", path)
}

// TestProfile_Heap captures a heap profile after sustained load.
func TestProfile_Heap(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping profiling in short mode")
	}

	dir := ensureOutDir(t)

	runLoadBurst(t, profileDuration)

	// Force GC to get accurate live objects.
	runtime.GC()

	path := filepath.Join(dir, "heap.prof")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create heap.prof: %v", err)
	}
	defer f.Close()

	if err := pprof.WriteHeapProfile(f); err != nil {
		t.Fatalf("write heap profile: %v", err)
	}
	t.Logf("Heap profile written to %s", path)

	// Also print top allocators from runtime.MemStats.
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	t.Logf("HeapAlloc = %d KB, HeapObjects = %d, Mallocs = %d, Frees = %d",
		m.HeapAlloc/1024, m.HeapObjects, m.Mallocs, m.Frees)
	t.Logf("NumGC = %d, PauseTotalNs = %d ms", m.NumGC, m.PauseTotalNs/1e6)
}

// TestProfile_Mutex captures a mutex contention profile under load.
func TestProfile_Mutex(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping profiling in short mode")
	}

	dir := ensureOutDir(t)

	// Enable mutex profiling (fraction = 1 means 100% sampling).
	runtime.SetMutexProfileFraction(1)
	defer runtime.SetMutexProfileFraction(0)

	runLoadBurst(t, profileDuration)

	path := filepath.Join(dir, "mutex.prof")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create mutex.prof: %v", err)
	}
	defer f.Close()

	p := pprof.Lookup("mutex")
	if p == nil {
		t.Fatal("mutex profile not available")
	}
	if err := p.WriteTo(f, 0); err != nil {
		t.Fatalf("write mutex profile: %v", err)
	}
	t.Logf("Mutex contention profile written to %s", path)

	// Print summary.
	var buf strings.Builder
	if err := p.WriteTo(&buf, 1); err == nil {
		lines := strings.Split(buf.String(), "\n")
		top := 10
		if len(lines) < top {
			top = len(lines)
		}
		t.Log("Top mutex contention sites:")
		for i := 0; i < top; i++ {
			if lines[i] != "" {
				fmt.Fprintf(os.Stderr, "  %s\n", lines[i])
			}
		}
	}
}
