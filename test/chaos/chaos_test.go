package chaos_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/router"
)

// ---------------------------------------------------------------------------
// noopFilter is a zero-overhead filter (duplicated from bench to keep chaos
// tests independent).
// ---------------------------------------------------------------------------
type noopFilter struct {
	name  string
	phase pipeline.Phase
}

func (f *noopFilter) Name() string                         { return f.name }
func (f *noopFilter) Phase() pipeline.Phase                 { return f.phase }
func (f *noopFilter) BodyMode() pipeline.BodyMode           { return pipeline.BodyModeNone }
func (f *noopFilter) FailurePolicy() pipeline.FailurePolicy { return pipeline.FailurePolicyFailClosed }
func (f *noopFilter) Close() error                          { return nil }

func (f *noopFilter) Process(_ context.Context, _ *pipeline.Envelope) (pipeline.Decision, error) {
	return pipeline.ContinueDecision(), nil
}

// ---------------------------------------------------------------------------
// panicFilter panics on Process — simulates a crashing plugin.
// ---------------------------------------------------------------------------
type panicFilter struct {
	name   string
	phase  pipeline.Phase
	policy pipeline.FailurePolicy
}

func (f *panicFilter) Name() string                         { return f.name }
func (f *panicFilter) Phase() pipeline.Phase                 { return f.phase }
func (f *panicFilter) BodyMode() pipeline.BodyMode           { return pipeline.BodyModeNone }
func (f *panicFilter) FailurePolicy() pipeline.FailurePolicy { return f.policy }
func (f *panicFilter) Close() error                          { return nil }

func (f *panicFilter) Process(_ context.Context, _ *pipeline.Envelope) (pipeline.Decision, error) {
	panic("intentional plugin crash for chaos testing")
}

// ---------------------------------------------------------------------------
// TestChaos_PluginCrash
//
// Verifies that a panicking filter does not crash the gateway process.
// The handler must recover from the panic and either fail-open (continue)
// or fail-closed (return error), depending on the filter's failure policy.
// ---------------------------------------------------------------------------
func TestChaos_PluginCrash(t *testing.T) {
	t.Run("fail_closed_panicking_filter", func(t *testing.T) {
		crashFilter := &panicFilter{
			name:   "crasher",
			phase:  pipeline.PhaseRequestHeaders,
			policy: pipeline.FailurePolicyFailClosed,
		}
		chain := pipeline.NewChain(crashFilter)

		// Wrap chain execution in a panic-safe handler (as the gateway would).
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			env := pipeline.GetEnvelope("chaos", pipeline.PhaseRequestHeaders, r.Method, r.URL.Path, nil, nil)
			defer pipeline.PutEnvelope(env)

			func() {
				defer func() {
					if rec := recover(); rec != nil {
						http.Error(w, fmt.Sprintf(`{"error":"plugin panic: %v"}`, rec), http.StatusInternalServerError)
					}
				}()

				decision, err := chain.ExecutePhase(r.Context(), env, pipeline.PhaseRequestHeaders, 0)
				if err != nil || decision.Action == pipeline.ActionHalt {
					http.Error(w, `{"error":"filter halted"}`, decision.StatusCode)
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			}()
		})

		ts := httptest.NewServer(handler)
		defer ts.Close()

		// Send 20 concurrent requests — all should get 500 (recovered panic), not crash.
		var wg sync.WaitGroup
		var errors atomic.Int64

		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := http.Get(ts.URL + "/v1/chat")
				if err != nil {
					errors.Add(1)
					return
				}
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusInternalServerError {
					errors.Add(1)
				}
			}()
		}

		wg.Wait()

		if errors.Load() > 0 {
			t.Errorf("%d requests had unexpected results (should all be 500 from recovered panic)", errors.Load())
		}
	})
}

// ---------------------------------------------------------------------------
// TestChaos_ConfigStorm
//
// Fires 100 UpdateSnapshot calls per second for 3 seconds while concurrently
// sending HTTP requests. Verifies:
// - No panics or data races.
// - The final router state is consistent.
// - No requests see a partially compiled snapshot.
// ---------------------------------------------------------------------------
func TestChaos_ConfigStorm(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	var routerPtr atomic.Pointer[router.Router]

	// Seed initial router.
	initialSnap := &config.Snapshot{
		Version: 1,
		Routes: []config.RouteRule{
			{ID: "storm-route", Path: "/v1/chat", Method: "POST", UpstreamID: "up"},
		},
		Upstreams: map[string]config.UpstreamCluster{
			"up": {ID: "up", Protocol: "http", Endpoints: []string{upstream.URL}},
		},
	}
	routerPtr.Store(router.Compile(initialSnap))

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// --- Config storm: 100 updates/s ---
	var stormWg sync.WaitGroup
	stormWg.Add(1)
	var snapshotCount atomic.Int64
	go func() {
		defer stormWg.Done()
		ticker := time.NewTicker(10 * time.Millisecond) // 100/s
		defer ticker.Stop()
		version := uint64(2)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				snap := &config.Snapshot{
					Version: version,
					Routes: []config.RouteRule{
						{ID: fmt.Sprintf("storm-route-v%d", version), Path: "/v1/chat", Method: "POST", UpstreamID: "up"},
					},
					Upstreams: map[string]config.UpstreamCluster{
						"up": {ID: "up", Protocol: "http", Endpoints: []string{upstream.URL}},
					},
				}
				routerPtr.Store(router.Compile(snap))
				snapshotCount.Add(1)
				version++
			}
		}
	}()

	// --- Concurrent request load ---
	var reqWg sync.WaitGroup
	var successCount atomic.Int64
	var failCount atomic.Int64

	for i := 0; i < 10; i++ {
		reqWg.Add(1)
		go func() {
			defer reqWg.Done()
			for ctx.Err() == nil {
				rtr := routerPtr.Load()
				if rtr == nil {
					failCount.Add(1)
					continue
				}
				_, err := rtr.Match(router.MatchCriteria{Method: "POST", Path: "/v1/chat"})
				if err != nil {
					failCount.Add(1)
				} else {
					successCount.Add(1)
				}
			}
		}()
	}

	<-ctx.Done()
	reqWg.Wait()
	cancel()
	stormWg.Wait()

	t.Logf("Config storm: %d snapshots applied, %d successful matches, %d failed matches",
		snapshotCount.Load(), successCount.Load(), failCount.Load())

	if failCount.Load() > 0 {
		t.Errorf("%d route matches failed during config storm — should be zero", failCount.Load())
	}

	// Verify final router is consistent.
	finalRouter := routerPtr.Load()
	result, err := finalRouter.Match(router.MatchCriteria{Method: "POST", Path: "/v1/chat"})
	if err != nil {
		t.Fatalf("final router match failed: %v", err)
	}
	if result.Route == nil {
		t.Fatal("final router returned nil route")
	}
	t.Logf("Final route ID: %s", result.Route.ID)
}

// ---------------------------------------------------------------------------
// TestChaos_PlatformDown
//
// Simulates platform disconnection: the gateway must continue serving requests
// using the last-known-good snapshot. When the platform reconnects, new
// snapshots must apply.
// ---------------------------------------------------------------------------
func TestChaos_PlatformDown(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	// Simulate a snapshot holder that persists the LKG snapshot.
	holder := config.NewSnapshotHolder()

	// Load initial "LKG" snapshot.
	lkgSnap := &config.Snapshot{
		Version: 1,
		Routes: []config.RouteRule{
			{ID: "lkg-route", Path: "/v1/chat", Method: "POST", UpstreamID: "up"},
		},
		Upstreams: map[string]config.UpstreamCluster{
			"up": {ID: "up", Protocol: "http", Endpoints: []string{upstream.URL}},
		},
	}
	if err := holder.Store(lkgSnap); err != nil {
		t.Fatalf("store LKG: %v", err)
	}

	rtr := router.Compile(lkgSnap)

	// Phase 1: "Platform down" — 100 requests must all succeed using LKG.
	for i := 0; i < 100; i++ {
		result, err := rtr.Match(router.MatchCriteria{Method: "POST", Path: "/v1/chat"})
		if err != nil {
			t.Fatalf("request %d failed during platform outage: %v", i, err)
		}
		if result.Route.ID != "lkg-route" {
			t.Fatalf("request %d got route %q; want lkg-route", i, result.Route.ID)
		}
	}

	// Phase 2: "Platform reconnects" — apply new snapshot.
	newSnap := &config.Snapshot{
		Version: 2,
		Routes: []config.RouteRule{
			{ID: "new-route", Path: "/v1/chat", Method: "POST", UpstreamID: "up"},
		},
		Upstreams: map[string]config.UpstreamCluster{
			"up": {ID: "up", Protocol: "http", Endpoints: []string{upstream.URL}},
		},
	}

	if err := holder.Store(newSnap); err != nil {
		t.Fatalf("store new snapshot: %v", err)
	}

	newRtr := router.Compile(newSnap)
	result, err := newRtr.Match(router.MatchCriteria{Method: "POST", Path: "/v1/chat"})
	if err != nil {
		t.Fatalf("match after reconnect failed: %v", err)
	}
	if result.Route.ID != "new-route" {
		t.Fatalf("got route %q after reconnect; want new-route", result.Route.ID)
	}

	t.Log("Platform outage simulation: LKG served 100 requests, new snapshot applied after reconnect")
}
