package supervisor

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/config"
)

func TestSupervisor_StartupUnreadyUntilSnapshot(t *testing.T) {
	cfg := &config.BootstrapConfig{
		ListenHTTP: ":8080",
		ListenGRPC: ":9090",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	sup := New(cfg, logger)

	// Verify not ready on startup when no bundle provided
	if sup.holder.HasSnapshot() {
		t.Errorf("expected holder to have no snapshot on startup")
	}

	snap := &config.Snapshot{
		Version: 1,
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

	if !sup.holder.HasSnapshot() {
		t.Errorf("expected holder to have snapshot after update")
	}

	loaded, err := sup.holder.Load()
	if err != nil || loaded.Version != 1 {
		t.Fatalf("expected version 1, got %v", loaded)
	}
}

func TestSupervisor_StartupWithBundle(t *testing.T) {
	tmpDir := t.TempDir()
	bundleFile := filepath.Join(tmpDir, "init-bundle.json")

	validJSON := `{
		"version": 10,
		"routes": [{"id": "r1", "path": "/v1/models", "method": "GET", "upstream_id": "u1"}],
		"upstreams": {"u1": {"id": "u1", "protocol": "http", "endpoints": ["http://localhost:8000"]}}
	}`

	if err := os.WriteFile(bundleFile, []byte(validJSON), 0600); err != nil {
		t.Fatalf("failed to write bundle: %v", err)
	}

	cfg := &config.BootstrapConfig{
		ConfigBundle: bundleFile,
		ListenHTTP:   ":8080",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	sup := New(cfg, logger)

	if !sup.holder.HasSnapshot() {
		t.Fatalf("expected supervisor to have snapshot from bundle")
	}

	loaded, err := sup.holder.Load()
	if err != nil || loaded.Version != 10 {
		t.Fatalf("expected version 10 from bundle, got %v", loaded)
	}
}

func TestSupervisor_ContextCancelShutdown(t *testing.T) {
	cfg := &config.BootstrapConfig{
		ListenHTTP:   ":0",
		DrainTimeout: 1 * time.Second,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sup := New(cfg, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_ = sup.httpLsnr.Stop(ctx)
}
