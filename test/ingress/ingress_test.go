package ingress_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/egress"
	"github.com/phaselume/torana/internal/ingress"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/router"
	"github.com/phaselume/torana/internal/telemetry"
)

type mockEgressClient struct {
	protocol string
	response string
	status   int
}

func (m *mockEgressClient) Protocol() string { return m.protocol }
func (m *mockEgressClient) Execute(_ context.Context, _ *config.UpstreamCluster, req *egress.Request) (*egress.Response, error) {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	return &egress.Response{
		StatusCode: m.status,
		Headers:    header,
		Body:       io.NopCloser(bytes.NewBufferString(m.response)),
	}, nil
}
func (m *mockEgressClient) Close() error { return nil }

type testSink struct {
	events []telemetry.Event
}

func (t *testSink) SendBatch(_ context.Context, events []telemetry.Event) error {
	t.events = append(t.events, events...)
	return nil
}

func setupTestListener() (*ingress.HTTPListener, *testSink) {
	cfg := &config.BootstrapConfig{
		ListenHTTP: ":8080",
	}

	snap := &config.Snapshot{
		Version: 1,
		Upstreams: map[string]config.UpstreamCluster{
			"llm-openai": {
				ID:        "llm-openai",
				Protocol:  "http",
				Endpoints: []string{"http://mock.local"},
			},
		},
		Routes: []config.RouteRule{
			{
				ID:         "route-chat",
				Path:       "/v1/chat/completions",
				Method:     "POST",
				UpstreamID: "llm-openai",
			},
		},
	}

	holder := config.NewSnapshotHolder()
	_ = holder.Store(snap)

	rtr := router.Compile(snap)

	egressReg := egress.NewRegistry()
	egressReg.Register("http", &mockEgressClient{
		protocol: "http",
		response: `{"choices":[{"message":{"content":"Hello AI"}}]}`,
		status:   http.StatusOK,
	})

	sink := &testSink{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	emitter := telemetry.NewEmitter(100, sink, logger)
	emitter.Start(context.Background())

	chain := pipeline.NewChain()

	listener := ingress.NewHTTPListener(cfg, holder, egressReg, emitter, chain, logger)
	listener.UpdateRouter(rtr)
	listener.SetReady(true)

	return listener, sink
}

func TestHTTPListener_HealthAndReady(t *testing.T) {
	listener, _ := setupTestListener()

	t.Run("healthz is always UP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		rec := httptest.NewRecorder()

		listener.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rec.Code)
		}
		if rec.Body.String() != `{"status":"UP"}` {
			t.Fatalf("expected {\"status\":\"UP\"}, got %s", rec.Body.String())
		}
	})

	t.Run("readyz reflects ready state", func(t *testing.T) {
		listener.SetReady(false)
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		rec := httptest.NewRecorder()

		listener.ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("expected status 503 when not ready, got %d", rec.Code)
		}

		listener.SetReady(true)
		rec = httptest.NewRecorder()
		listener.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200 when ready, got %d", rec.Code)
		}
	})
}

func TestHTTPListener_ServeGatewayRequest(t *testing.T) {
	listener, _ := setupTestListener()

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	listener.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body=%s", rec.Code, rec.Body.String())
	}

	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", rec.Header().Get("Content-Type"))
	}

	if rec.Body.String() != `{"choices":[{"message":{"content":"Hello AI"}}]}` {
		t.Errorf("unexpected body: %s", rec.Body.String())
	}
}

func TestHTTPListener_RouteNotFound(t *testing.T) {
	listener, _ := setupTestListener()

	req := httptest.NewRequest(http.MethodGet, "/v1/nonexistent", nil)
	rec := httptest.NewRecorder()

	listener.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", rec.Code)
	}
}

func BenchmarkHTTPListener_HotPath(b *testing.B) {
	listener, _ := setupTestListener()
	body := []byte(`{"model":"gpt-4o"}`)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
			rec := httptest.NewRecorder()
			listener.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				b.Fatalf("expected status 200, got %d", rec.Code)
			}
		}
	})
}
