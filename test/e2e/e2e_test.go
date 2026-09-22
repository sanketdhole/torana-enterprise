package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/egress"
	"github.com/phaselume/torana/internal/ingress"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/router"
	"github.com/phaselume/torana/internal/telemetry"
)

type mockSSEUpstream struct {
	chunks []string
}

func (m *mockSSEUpstream) Protocol() string { return "http" }
func (m *mockSSEUpstream) Execute(_ context.Context, _ *config.UpstreamCluster, req *egress.Request) (*egress.Response, error) {
	header := make(http.Header)
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-cache")
	header.Set("Connection", "keep-alive")

	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()
		for _, chunk := range m.chunks {
			_, _ = pw.Write([]byte(chunk))
			time.Sleep(10 * time.Millisecond) // Simulate streaming interval
		}
	}()

	return &egress.Response{
		StatusCode: http.StatusOK,
		Headers:    header,
		Body:       pr,
	}, nil
}
func (m *mockSSEUpstream) Close() error { return nil }

type nilSink struct{}

func (n *nilSink) SendBatch(_ context.Context, _ []telemetry.Event) error { return nil }

func TestE2E_SSEStreamingPassThrough(t *testing.T) {
	cfg := &config.BootstrapConfig{
		ListenHTTP: ":8080",
	}

	snap := &config.Snapshot{
		Version: 1,
		Upstreams: map[string]config.UpstreamCluster{
			"llm-stream": {ID: "llm-stream", Protocol: "http", Endpoints: []string{"http://mock.stream"}},
		},
		Routes: []config.RouteRule{
			{ID: "r-stream", Path: "/v1/chat/stream", Method: "POST", UpstreamID: "llm-stream"},
		},
	}

	holder := config.NewSnapshotHolder()
	_ = holder.Store(snap)

	egressReg := egress.NewRegistry()
	egressReg.Register("http", &mockSSEUpstream{
		chunks: []string{
			"data: {\"token\":\"Hello\"}\n\n",
			"data: {\"token\":\" World\"}\n\n",
			"data: [DONE]\n\n",
		},
	})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	emitter := telemetry.NewEmitter(100, &nilSink{}, logger)
	emitter.Start(context.Background())
	defer emitter.Stop(time.Second)

	chain := pipeline.NewChain()
	lsnr := ingress.NewHTTPListener(cfg, holder, egressReg, emitter, chain, logger)
	lsnr.UpdateRouter(router.Compile(snap))
	lsnr.SetReady(true)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/stream", bytes.NewBufferString(`{"stream":true}`))
	req.Header.Set("Accept", "text/event-stream")
	rec := httptest.NewRecorder()

	lsnr.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	if rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Errorf("expected Content-Type text/event-stream, got %s", rec.Header().Get("Content-Type"))
	}

	expectedBody := "data: {\"token\":\"Hello\"}\n\ndata: {\"token\":\" World\"}\n\ndata: [DONE]\n\n"
	if rec.Body.String() != expectedBody {
		t.Errorf("expected stream body %q, got %q", expectedBody, rec.Body.String())
	}
}

type staticMockUpstream struct {
	version string
}

func (s *staticMockUpstream) Protocol() string { return "http" }
func (s *staticMockUpstream) Execute(_ context.Context, _ *config.UpstreamCluster, req *egress.Request) (*egress.Response, error) {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("X-Backend-Version", s.version)
	return &egress.Response{
		StatusCode: http.StatusOK,
		Headers:    header,
		Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok"}`)),
	}, nil
}
func (s *staticMockUpstream) Close() error { return nil }

func TestE2E_AtomicHotSwapZeroDrop(t *testing.T) {
	cfg := &config.BootstrapConfig{ListenHTTP: ":8080"}

	snapV1 := &config.Snapshot{
		Version: 1,
		Upstreams: map[string]config.UpstreamCluster{
			"u1": {ID: "u1", Protocol: "http", Endpoints: []string{"http://mock.u1"}},
		},
		Routes: []config.RouteRule{
			{ID: "r1", Path: "/v1/hot-swap", Method: "POST", UpstreamID: "u1"},
		},
	}

	holder := config.NewSnapshotHolder()
	_ = holder.Store(snapV1)

	egressReg := egress.NewRegistry()
	egressReg.Register("http", &staticMockUpstream{version: "v1"})

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	emitter := telemetry.NewEmitter(1000, &nilSink{}, logger)
	emitter.Start(context.Background())
	defer emitter.Stop(time.Second)

	chain := pipeline.NewChain()
	lsnr := ingress.NewHTTPListener(cfg, holder, egressReg, emitter, chain, logger)
	lsnr.UpdateRouter(router.Compile(snapV1))
	lsnr.SetReady(true)

	// Send 500 concurrent requests while swapping snapshot to v2
	concurrency := 20
	iterations := 25
	var wg sync.WaitGroup

	errChan := make(chan error, concurrency*iterations)

	// Background hot-swap routine
	go func() {
		time.Sleep(5 * time.Millisecond)
		snapV2 := &config.Snapshot{
			Version: 2,
			Upstreams: map[string]config.UpstreamCluster{
				"u1": {ID: "u1", Protocol: "http", Endpoints: []string{"http://mock.u1"}},
			},
			Routes: []config.RouteRule{
				{ID: "r1", Path: "/v1/hot-swap", Method: "POST", UpstreamID: "u1"},
			},
		}
		_ = holder.Store(snapV2)
		lsnr.UpdateRouter(router.Compile(snapV2))
	}()

	for c := 0; c < concurrency; c++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				req := httptest.NewRequest(http.MethodPost, "/v1/hot-swap", bytes.NewBufferString(`{"ping":1}`))
				rec := httptest.NewRecorder()
				lsnr.ServeHTTP(rec, req)

				if rec.Code != http.StatusOK {
					errChan <- fmt.Errorf("worker %d req %d failed with code %d", workerID, i, rec.Code)
					return
				}
			}
		}(c)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Fatalf("zero-drop hot-swap encountered failure: %v", err)
	}
}
