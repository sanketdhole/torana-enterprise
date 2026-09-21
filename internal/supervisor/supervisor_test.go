package supervisor

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/config"
)

func TestSupervisor_UpdateSnapshot(t *testing.T) {
	cfg := &config.BootstrapConfig{
		HTTPPort: "8080",
		HTTPHost: "127.0.0.1",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	sup := New(cfg, logger)

	snap := &config.Snapshot{
		Version: 2,
		Routes: []config.RouteRule{
			{ID: "r1", Path: "/v1/chat", Method: "POST", UpstreamID: "u1"},
		},
		Upstreams: map[string]config.UpstreamCluster{
			"u1": {ID: "u1", Protocol: "http", Endpoints: []string{"http://localhost:9000"}},
		},
	}

	if err := sup.UpdateSnapshot(snap); err != nil {
		t.Fatalf("failed to update snapshot: %v", err)
	}

	loaded, err := sup.holder.Load()
	if err != nil {
		t.Fatalf("failed to load snapshot from holder: %v", err)
	}
	if loaded.Version != 2 {
		t.Errorf("expected snapshot version 2, got %d", loaded.Version)
	}
}

func TestSupervisor_ContextCancelShutdown(t *testing.T) {
	cfg := &config.BootstrapConfig{
		HTTPPort:     "0",
		HTTPHost:     "127.0.0.1",
		DrainTimeout: 1 * time.Second,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sup := New(cfg, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_ = sup.httpLsnr.Stop(ctx)
}
