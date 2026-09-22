package ingress_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/egress"
	"github.com/phaselume/torana/internal/ingress"
	"github.com/phaselume/torana/internal/ingress/ws"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/router"
	"github.com/phaselume/torana/internal/security/authn"
	"google.golang.org/grpc/test/bufconn"
)

// setupWSTestEnvironment creates an in-process upstream WS server, an HTTP backend server,
// and a Torana WS gateway using bufconn.
func setupWSTestEnvironment(
	t *testing.T,
	chain *pipeline.Chain,
	revList *authn.RevocationList,
	opts ws.Options,
) (func(ctx context.Context, path string, headers http.Header) (*websocket.Conn, error), func()) {
	// 1. Upstream WebSocket Echo Server
	upstreamLis := bufconn.Listen(1024 * 1024)
	upstreamMux := http.NewServeMux()
	upstreamMux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusInternalError, "closed")

		for {
			msgType, data, err := conn.Read(r.Context())
			if err != nil {
				break
			}
			echo := append([]byte("echo:"), data...)
			if err := conn.Write(r.Context(), msgType, echo); err != nil {
				break
			}
		}
		_ = conn.Close(websocket.StatusNormalClosure, "normal")
	})

	// Upstream HTTP backend handler
	upstreamMux.HandleFunc("/api/json", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(append([]byte("backend-ack:"), body...))
	})

	upstreamServer := &http.Server{Handler: upstreamMux}
	go func() {
		_ = upstreamServer.Serve(upstreamLis)
	}()

	upstreamHTTPClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return upstreamLis.DialContext(ctx)
			},
		},
	}

	// 2. Gateway Snapshot
	holder := config.NewSnapshotHolder()
	snap := &config.Snapshot{
		Version: 1,
		Routes: []config.RouteRule{
			{
				ID:         "r-ws",
				Path:       "/echo",
				Method:     "GET",
				UpstreamID: "u-ws",
			},
			{
				ID:         "r-http-backend",
				Path:       "/api/json",
				Method:     "GET",
				UpstreamID: "u-http",
			},
		},
		Upstreams: map[string]config.UpstreamCluster{
			"u-ws": {
				ID:        "u-ws",
				Protocol:  "ws",
				Endpoints: []string{"http://bufnet-upstream"},
			},
			"u-http": {
				ID:        "u-http",
				Protocol:  "http",
				Endpoints: []string{"http://bufnet-upstream"},
			},
		},
	}
	_ = holder.Store(snap)

	// 3. Egress Registry & HTTP Gateway Listener
	egressReg := egress.NewRegistry()
	cfg := &config.BootstrapConfig{
		ListenHTTP: ":8080",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	httpLsnr := ingress.NewHTTPListener(cfg, holder, egressReg, nil, chain, logger)

	// Configure WSHandler with injected upstream HTTPClient
	wsHandler := ws.NewHandler(opts, chain, revList, logger)
	wsHandler.SetHTTPClient(upstreamHTTPClient)
	httpLsnr.SetWSHandler(wsHandler)

	compiledRouter := router.Compile(snap)
	httpLsnr.UpdateRouter(compiledRouter)
	httpLsnr.SetReady(true)

	gatewayLis := bufconn.Listen(1024 * 1024)
	go func() {
		_ = httpLsnr.Server().Serve(gatewayLis)
	}()

	gatewayHTTPClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return gatewayLis.DialContext(ctx)
			},
		},
	}

	dialer := func(ctx context.Context, path string, headers http.Header) (*websocket.Conn, error) {
		url := "ws://gateway" + path
		dialOpts := &websocket.DialOptions{
			HTTPClient: gatewayHTTPClient,
			HTTPHeader: headers,
		}
		conn, _, err := websocket.Dial(ctx, url, dialOpts)
		return conn, err
	}

	cleanup := func() {
		_ = httpLsnr.Server().Close()
		_ = gatewayLis.Close()
		_ = upstreamServer.Close()
		_ = upstreamLis.Close()
	}

	return dialer, cleanup
}

// mockChunkFilter intercepts messages and prepends a tag.
type mockChunkFilter struct {
	tag string
}

func (m *mockChunkFilter) Name() string                         { return "mock_chunk_filter" }
func (m *mockChunkFilter) Phase() pipeline.Phase                { return pipeline.PhaseRequestHeaders }
func (m *mockChunkFilter) BodyMode() pipeline.BodyMode          { return pipeline.BodyModeStreaming }
func (m *mockChunkFilter) FailurePolicy() pipeline.FailurePolicy { return pipeline.FailurePolicyFailClosed }
func (m *mockChunkFilter) Close() error                         { return nil }
func (m *mockChunkFilter) Process(ctx context.Context, env *pipeline.Envelope) (pipeline.Decision, error) {
	return pipeline.ContinueDecision(), nil
}
func (m *mockChunkFilter) OnChunk(ctx context.Context, env *pipeline.Envelope, chunk []byte) ([]byte, error) {
	return []byte(m.tag + string(chunk)), nil
}

func TestWSProxy_FullDuplexAndChunkHooks(t *testing.T) {
	chunkFilter := &mockChunkFilter{tag: "[tag]"}
	chain := pipeline.NewChain(chunkFilter)
	revList := authn.NewRevocationList()

	opts := ws.DefaultOptions()
	opts.QueueCapacity = 64

	dialer, cleanup := setupWSTestEnvironment(t, chain, revList, opts)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialer(ctx, "/echo", nil)
	if err != nil {
		t.Fatalf("failed to dial websocket gateway: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "done")

	// Send message through gateway
	if err := conn.Write(ctx, websocket.MessageText, []byte("hello")); err != nil {
		t.Fatalf("failed to write message: %v", err)
	}

	// Read response
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	// Downstream -> Upstream ChunkHook prepends "[tag]" -> "echo:[tag]hello"
	// Upstream -> Downstream ChunkHook prepends "[tag]" -> "[tag]echo:[tag]hello"
	expected := "[tag]echo:[tag]hello"
	if string(data) != expected {
		t.Errorf("expected payload %q, got %q", expected, string(data))
	}
}

func TestWSProxy_HTTPBackend(t *testing.T) {
	chain := pipeline.NewChain()
	revList := authn.NewRevocationList()

	opts := ws.DefaultOptions()
	dialer, cleanup := setupWSTestEnvironment(t, chain, revList, opts)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialer(ctx, "/api/json", nil)
	if err != nil {
		t.Fatalf("failed to dial http backend via ws: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "done")

	if err := conn.Write(ctx, websocket.MessageText, []byte(`{"action":"ping"}`)); err != nil {
		t.Fatalf("failed to write message: %v", err)
	}

	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("failed to read http response: %v", err)
	}

	expected := `backend-ack:{"action":"ping"}`
	if string(data) != expected {
		t.Errorf("expected %q, got %q", expected, string(data))
	}
}

func TestWSProxy_LiveRevocationReauthorization(t *testing.T) {
	revList := authn.NewRevocationList()
	chain := pipeline.NewChain()

	opts := ws.DefaultOptions()
	opts.PingInterval = 50 * time.Millisecond
	opts.IdleTimeout = 1 * time.Second

	dialer, cleanup := setupWSTestEnvironment(t, chain, revList, opts)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hdr := http.Header{
		"Authorization": []string{"Bearer live-revoked-token"},
	}
	conn, err := dialer(ctx, "/echo", hdr)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "done")

	// Verify connection is working
	if err := conn.Write(ctx, websocket.MessageText, []byte("ping1")); err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	_, _, err = conn.Read(ctx)
	if err != nil {
		t.Fatalf("first read failed: %v", err)
	}

	// Trigger live revocation
	revList.RevokeToken("live-revoked-token")

	// Next read or write should fail with status policy violation (closed)
	readDone := make(chan error, 1)
	go func() {
		_, _, err := conn.Read(ctx)
		readDone <- err
	}()

	select {
	case err := <-readDone:
		if err == nil {
			t.Errorf("expected connection error after live revocation, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Errorf("timed out waiting for live revocation termination")
	}
}

func TestWSProxy_ChunkFilterTransformation(t *testing.T) {
	chunkFilter := &mockChunkFilter{tag: "[audited]:"}
	chain := pipeline.NewChain(chunkFilter)
	revList := authn.NewRevocationList()

	h := ws.NewHandler(ws.DefaultOptions(), chain, revList, slog.New(slog.NewTextHandler(io.Discard, nil)))

	env := pipeline.GetEnvelope("req-2", pipeline.PhaseRequestHeaders, "GET", "/ws", http.Header{}, nil)
	defer pipeline.PutEnvelope(env)

	input := []byte("chat-message-hello")
	output, err := h.ApplyChunkHooks(context.Background(), env, input)
	if err != nil {
		t.Fatalf("chunk hook error: %v", err)
	}

	expected := "[audited]:chat-message-hello"
	if string(output) != expected {
		t.Errorf("expected %q, got %q", expected, string(output))
	}
}

func TestWSProxy_RevocationCheckMethods(t *testing.T) {
	revList := authn.NewRevocationList()
	h := ws.NewHandler(ws.DefaultOptions(), nil, revList, nil)

	t.Run("check Bearer token in Authorization header", func(t *testing.T) {
		revList.RevokeToken("secret-token-xyz")
		env := pipeline.GetEnvelope("r1", pipeline.PhaseRequestHeaders, "GET", "/ws", http.Header{
			"Authorization": []string{"Bearer secret-token-xyz"},
		}, nil)
		defer pipeline.PutEnvelope(env)

		if !h.IsRevoked(env) {
			t.Errorf("expected isRevoked to return true for revoked token")
		}
	})

	t.Run("check X-API-Key header", func(t *testing.T) {
		revList.RevokeKey("ak_bad_key_456")
		env := pipeline.GetEnvelope("r2", pipeline.PhaseRequestHeaders, "GET", "/ws", http.Header{
			"X-API-Key": []string{"ak_bad_key_456"},
		}, nil)
		defer pipeline.PutEnvelope(env)

		if !h.IsRevoked(env) {
			t.Errorf("expected isRevoked to return true for revoked API key")
		}
	})

	t.Run("check subject in identity", func(t *testing.T) {
		revList.RevokeToken("user:bad_actor")
		env := pipeline.GetEnvelope("r3", pipeline.PhaseRequestHeaders, "GET", "/ws", http.Header{}, nil)
		defer pipeline.PutEnvelope(env)
		env.Identity = &authn.Identity{
			Subject: "user:bad_actor",
		}

		if !h.IsRevoked(env) {
			t.Errorf("expected isRevoked to return true for revoked subject")
		}
	})

	t.Run("valid unrevoked credentials pass", func(t *testing.T) {
		env := pipeline.GetEnvelope("r4", pipeline.PhaseRequestHeaders, "GET", "/ws", http.Header{
			"Authorization": []string{"Bearer valid-token-789"},
		}, nil)
		defer pipeline.PutEnvelope(env)

		if h.IsRevoked(env) {
			t.Errorf("expected isRevoked to return false for valid token")
		}
	})
}

func BenchmarkWSProxy_MessageRoundTrip(b *testing.B) {
	chain := pipeline.NewChain()
	revList := authn.NewRevocationList()
	opts := ws.DefaultOptions()
	opts.QueueCapacity = 256
	dialer, cleanup := setupWSTestEnvironment(&testing.T{}, chain, revList, opts)
	defer cleanup()

	ctx := context.Background()
	conn, err := dialer(ctx, "/echo", nil)
	if err != nil {
		b.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "done")

	payload := []byte("bench-ping")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := conn.Write(ctx, websocket.MessageText, payload); err != nil {
			b.Fatalf("write error: %v", err)
		}
		if _, _, err := conn.Read(ctx); err != nil {
			b.Fatalf("read error: %v", err)
		}
	}
}
