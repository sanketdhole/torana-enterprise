package config_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/config"
)

func TestSnapshotHolder_StoreAndLoad(t *testing.T) {
	tests := []struct {
		name          string
		initial       *config.Snapshot
		store         *config.Snapshot
		expectedError error
		wantVersion   uint64
	}{
		{
			name:          "uninitialized holder returns error",
			initial:       nil,
			store:         nil,
			expectedError: config.ErrNoSnapshotAvailable,
		},
		{
			name:    "store valid snapshot",
			initial: nil,
			store: &config.Snapshot{
				Version:   1,
				Timestamp: time.Now(),
				Routes: []config.RouteRule{
					{ID: "r1", Path: "/v1/chat", Method: "POST", UpstreamID: "u1"},
				},
				Upstreams: map[string]config.UpstreamCluster{
					"u1": {ID: "u1", Protocol: "http", Endpoints: []string{"http://localhost:9000"}},
				},
			},
			wantVersion: 1,
		},
		{
			name: "store nil snapshot returns ErrNilSnapshot",
			initial: &config.Snapshot{
				Version: 1,
			},
			store:         nil,
			expectedError: config.ErrNilSnapshot,
			wantVersion:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			holder := config.NewSnapshotHolder()
			if tt.initial != nil {
				_ = holder.Store(tt.initial)
			}

			if tt.store != nil || tt.expectedError == config.ErrNilSnapshot {
				err := holder.Store(tt.store)
				if err != tt.expectedError {
					t.Fatalf("expected store error %v, got %v", tt.expectedError, err)
				}
			}

			snap, err := holder.Load()
			if tt.expectedError != nil && tt.expectedError != config.ErrNilSnapshot {
				if err != tt.expectedError {
					t.Fatalf("expected load error %v, got %v", tt.expectedError, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected load error: %v", err)
			}
			if snap.Version != tt.wantVersion {
				t.Errorf("expected version %d, got %d", tt.wantVersion, snap.Version)
			}
		})
	}
}

func TestSnapshot_Validate(t *testing.T) {
	t.Run("nil snapshot", func(t *testing.T) {
		var s *config.Snapshot
		if err := s.Validate(); err == nil {
			t.Fatalf("expected error for nil snapshot")
		}
	})

	t.Run("empty path route", func(t *testing.T) {
		s := &config.Snapshot{
			Version: 1,
			Routes:  []config.RouteRule{{ID: "r1", Path: ""}},
		}
		if err := s.Validate(); err == nil {
			t.Fatalf("expected error for empty route path")
		}
	})

	t.Run("valid snapshot", func(t *testing.T) {
		s := &config.Snapshot{
			Version: 1,
			Routes: []config.RouteRule{
				{ID: "r1", Path: "/v1/chat", UpstreamID: "u1"},
			},
		}
		if err := s.Validate(); err != nil {
			t.Fatalf("unexpected validation error: %v", err)
		}
	})
}

func TestSaveAndLoadLKG(t *testing.T) {
	tmpDir := t.TempDir()
	lkgPath := filepath.Join(tmpDir, "lkg.json")

	orig := &config.Snapshot{
		Version: 99,
		Routes: []config.RouteRule{
			{ID: "r-lkg", Path: "/v1/lkg", Method: "POST", UpstreamID: "u1"},
		},
		Upstreams: map[string]config.UpstreamCluster{
			"u1": {ID: "u1", Protocol: "http", Endpoints: []string{"http://localhost:8000"}},
		},
	}

	if err := config.SaveLKG(lkgPath, orig); err != nil {
		t.Fatalf("failed to save LKG: %v", err)
	}

	loaded, err := config.LoadLKG(lkgPath)
	if err != nil {
		t.Fatalf("failed to load LKG: %v", err)
	}

	if loaded.Version != 99 {
		t.Errorf("expected loaded version 99, got %d", loaded.Version)
	}
	if len(loaded.Routes) != 1 || loaded.Routes[0].ID != "r-lkg" {
		t.Errorf("unexpected loaded routes: %v", loaded.Routes)
	}
}

func TestLoadBundleFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	bundleFile := filepath.Join(tmpDir, "bundle.json")

	validJSON := `{
		"version": 42,
		"signature": "test-signature",
		"routes": [
			{"id": "r1", "path": "/v1/chat/completions", "method": "POST", "upstream_id": "u1"}
		],
		"upstreams": {
			"u1": {"id": "u1", "protocol": "http", "endpoints": ["http://localhost:8000"]}
		}
	}`

	if err := os.WriteFile(bundleFile, []byte(validJSON), 0600); err != nil {
		t.Fatalf("failed to write test bundle: %v", err)
	}

	snap, err := config.LoadBundleFromFile(bundleFile)
	if err != nil {
		t.Fatalf("failed to load bundle: %v", err)
	}
	if snap.Version != 42 {
		t.Errorf("expected version 42, got %d", snap.Version)
	}
	if len(snap.Routes) != 1 {
		t.Errorf("expected 1 route, got %d", len(snap.Routes))
	}
}

func TestSnapshotHolder_ConcurrentAccess(t *testing.T) {
	holder := config.NewSnapshotHolder()
	initial := &config.Snapshot{Version: 0}
	_ = holder.Store(initial)

	var wg sync.WaitGroup
	workers := 20
	iterations := 1000

	// Concurrent readers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				snap, err := holder.Load()
				if err != nil || snap == nil {
					t.Errorf("failed to load snapshot concurrently: %v", err)
					return
				}
			}
		}()
	}

	// Concurrent writer
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 1; j <= 50; j++ {
			_ = holder.Store(&config.Snapshot{Version: uint64(j)})
			time.Sleep(100 * time.Microsecond)
		}
	}()

	wg.Wait()
}

func TestSnapshotHolder_ApplyAndNACK(t *testing.T) {
	holder := config.NewSnapshotHolder()
	tmpDir := t.TempDir()
	lkgPath := filepath.Join(tmpDir, "lkg.json")
	holder.SetLKGPath(lkgPath)

	validSnap := &config.Snapshot{
		Version: 1,
		Routes: []config.RouteRule{
			{
				ID:         "r1",
				Path:       "/v1/chat",
				Method:     "POST",
				UpstreamID: "u1",
				Headers: map[string]string{
					"X-Custom": "^[a-z]+$",
				},
				Policies: []config.PolicyRule{
					{ID: "p1", Name: "auth", Type: "authn", Action: "ALLOW"},
				},
			},
		},
		Upstreams: map[string]config.UpstreamCluster{
			"u1": {ID: "u1", Protocol: "http", Endpoints: []string{"http://localhost:8000"}},
		},
	}

	// 1. Apply valid snapshot
	if err := holder.Apply(validSnap); err != nil {
		t.Fatalf("unexpected error applying valid snapshot: %v", err)
	}

	compiled, err := holder.LoadCompiled()
	if err != nil || compiled == nil {
		t.Fatalf("expected compiled config after apply, got %v", err)
	}
	if len(compiled.Routes) != 1 || compiled.Routes[0].Rule.ID != "r1" {
		t.Fatalf("unexpected compiled routes: %v", compiled.Routes)
	}
	if len(compiled.FilterChains) != 1 || compiled.FilterChains["r1"] == nil {
		t.Fatalf("expected filter chain for r1")
	}
	if len(compiled.FilterChains["r1"].Policies) != 1 {
		t.Fatalf("expected 1 policy for r1")
	}

	// Verify LKG was written to disk
	if _, err := os.Stat(lkgPath); os.IsNotExist(err) {
		t.Fatalf("expected LKG file to be written to disk: %v", err)
	}

	// 2. Apply invalid snapshot: empty path (should NACK with structured error)
	invalidSnap := &config.Snapshot{
		Version: 2,
		Routes: []config.RouteRule{
			{ID: "bad-route", Path: ""},
		},
	}
	err = holder.Apply(invalidSnap)
	if err == nil {
		t.Fatalf("expected error applying invalid snapshot")
	}
	compileErr, ok := err.(*config.CompileError)
	if !ok {
		t.Fatalf("expected *CompileError for NACK, got %T (%v)", err, err)
	}
	if compileErr.Code != "ERR_EMPTY_PATH" {
		t.Errorf("expected error code ERR_EMPTY_PATH, got %s", compileErr.Code)
	}

	// Verify previous snapshot remains active and untouched!
	snap, err := holder.Load()
	if err != nil || snap.Version != 1 {
		t.Fatalf("expected active snapshot to remain version 1, got %v", snap)
	}

	// 3. Apply snapshot with invalid regex
	invalidRegexSnap := &config.Snapshot{
		Version: 3,
		Routes: []config.RouteRule{
			{
				ID:         "r3",
				Path:       "/v1/test",
				UpstreamID: "u1",
				Headers: map[string]string{
					"X-Bad-Regex": "^[a-z", // unclosed bracket with ^ prefix
				},
			},
		},
	}
	err = holder.Apply(invalidRegexSnap)
	if err == nil {
		t.Fatalf("expected error applying snapshot with invalid regex")
	}
	compileErr, ok = err.(*config.CompileError)
	if !ok || compileErr.Code != "ERR_INVALID_HEADER_REGEX" {
		t.Fatalf("expected ERR_INVALID_HEADER_REGEX, got %v", err)
	}

	// 4. Test LoadStartupLKG
	startupHolder := config.NewSnapshotHolder()
	loadedLKG, err := startupHolder.LoadStartupLKG(lkgPath)
	if err != nil {
		t.Fatalf("failed to load startup LKG: %v", err)
	}
	if loadedLKG.Version != 1 {
		t.Errorf("expected version 1 from LKG, got %d", loadedLKG.Version)
	}
	compiledStartup, err := startupHolder.LoadCompiled()
	if err != nil || compiledStartup == nil {
		t.Fatalf("expected startup holder to have compiled config")
	}
}

func TestRouteTrie(t *testing.T) {
	trie := config.NewRouteTrie()

	r1 := &config.CompiledRoute{
		Rule: &config.RouteRule{ID: "exact", Path: "/v1/chat/completions"},
	}
	r2 := &config.CompiledRoute{
		Rule: &config.RouteRule{ID: "prefix", Path: "/v1/models/", PathPrefix: true},
	}
	r3 := &config.CompiledRoute{
		Rule: &config.RouteRule{ID: "wildcard", Path: "/v1/*/status"},
	}

	trie.Insert(r1)
	trie.Insert(r2)
	trie.Insert(r3)

	// Exact match
	m1 := trie.Match("/v1/chat/completions")
	if len(m1) == 0 || m1[0].Rule.ID != "exact" {
		t.Fatalf("expected exact match, got %v", m1)
	}

	// Prefix match
	m2 := trie.Match("/v1/models/claude-3-opus")
	if len(m2) == 0 || m2[0].Rule.ID != "prefix" {
		t.Fatalf("expected prefix match, got %v", m2)
	}

	// Wildcard segment match
	m3 := trie.Match("/v1/openai/status")
	if len(m3) == 0 || m3[0].Rule.ID != "wildcard" {
		t.Fatalf("expected wildcard match, got %v", m3)
	}

	// No match
	m4 := trie.Match("/v2/unknown")
	if len(m4) != 0 {
		t.Fatalf("expected no match, got %v", m4)
	}
}

func TestParseFlags_DefaultsAndOverrides(t *testing.T) {
	t.Run("default flags", func(t *testing.T) {
		cfg, showVersion, err := config.ParseFlags([]string{})
		if err != nil {
			t.Fatalf("unexpected error parsing flags: %v", err)
		}
		if showVersion {
			t.Errorf("expected showVersion to be false")
		}
		if cfg.ListenHTTP != ":8080" {
			t.Errorf("expected default HTTP port ':8080', got %s", cfg.ListenHTTP)
		}
		if cfg.ListenGRPC != ":9090" {
			t.Errorf("expected default gRPC port ':9090', got %s", cfg.ListenGRPC)
		}
		if cfg.Namespace != "default" {
			t.Errorf("expected default namespace 'default', got %s", cfg.Namespace)
		}
	})

	t.Run("flag overrides", func(t *testing.T) {
		args := []string{
			"--namespace=prod-ai",
			"--platform-url=https://cp.torana.io:443",
			"--listen-http=:8000",
			"--listen-grpc=:9000",
			"--peers-dns=torana-peers.internal",
			"--config-bundle=/etc/torana/bundle.json",
		}
		cfg, _, err := config.ParseFlags(args)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Namespace != "prod-ai" {
			t.Errorf("expected namespace 'prod-ai', got %s", cfg.Namespace)
		}
		if cfg.PlatformURL != "https://cp.torana.io:443" {
			t.Errorf("expected platform URL 'https://cp.torana.io:443', got %s", cfg.PlatformURL)
		}
		if cfg.ListenHTTP != ":8000" {
			t.Errorf("expected HTTP port ':8000', got %s", cfg.ListenHTTP)
		}
		if cfg.ListenGRPC != ":9000" {
			t.Errorf("expected gRPC port ':9000', got %s", cfg.ListenGRPC)
		}
		if cfg.PeersDNS != "torana-peers.internal" {
			t.Errorf("expected peers DNS 'torana-peers.internal', got %s", cfg.PeersDNS)
		}
		if cfg.ConfigBundle != "/etc/torana/bundle.json" {
			t.Errorf("expected config bundle '/etc/torana/bundle.json', got %s", cfg.ConfigBundle)
		}
	})

	t.Run("env var fallback", func(t *testing.T) {
		_ = os.Setenv("GATEWAY_NAMESPACE", "staging-ai")
		_ = os.Setenv("PLATFORM_URL", "grpc://cp.staging.local:9090")
		defer func() {
			_ = os.Unsetenv("GATEWAY_NAMESPACE")
			_ = os.Unsetenv("PLATFORM_URL")
		}()

		cfg, _, err := config.ParseFlags([]string{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Namespace != "staging-ai" {
			t.Errorf("expected namespace 'staging-ai', got %s", cfg.Namespace)
		}
		if cfg.PlatformURL != "grpc://cp.staging.local:9090" {
			t.Errorf("expected platform URL 'grpc://cp.staging.local:9090', got %s", cfg.PlatformURL)
		}
	})

	t.Run("version flag", func(t *testing.T) {
		_, showVersion, err := config.ParseFlags([]string{"--version"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !showVersion {
			t.Errorf("expected showVersion to be true")
		}
	})
}

func BenchmarkSnapshotHolder_Load(b *testing.B) {
	holder := config.NewSnapshotHolder()
	_ = holder.Store(&config.Snapshot{
		Version:   42,
		Timestamp: time.Now(),
	})

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			snap, err := holder.Load()
			if err != nil || snap == nil {
				b.Fatal(err)
			}
		}
	})
}
