package config

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSnapshotHolder_StoreAndLoad(t *testing.T) {
	tests := []struct {
		name          string
		initial       *Snapshot
		store         *Snapshot
		expectedError error
		wantVersion   uint64
	}{
		{
			name:          "uninitialized holder returns error",
			initial:       nil,
			store:         nil,
			expectedError: ErrNoSnapshotAvailable,
		},
		{
			name:    "store valid snapshot",
			initial: nil,
			store: &Snapshot{
				Version:   1,
				Timestamp: time.Now(),
				Routes: []RouteRule{
					{ID: "r1", Path: "/v1/chat", Method: "POST", UpstreamID: "u1"},
				},
				Upstreams: map[string]UpstreamCluster{
					"u1": {ID: "u1", Protocol: "http", Endpoints: []string{"http://localhost:9000"}},
				},
			},
			wantVersion: 1,
		},
		{
			name: "store nil snapshot returns ErrNilSnapshot",
			initial: &Snapshot{
				Version: 1,
			},
			store:         nil,
			expectedError: ErrNilSnapshot,
			wantVersion:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			holder := NewSnapshotHolder()
			if tt.initial != nil {
				_ = holder.Store(tt.initial)
			}

			if tt.store != nil || tt.expectedError == ErrNilSnapshot {
				err := holder.Store(tt.store)
				if err != tt.expectedError {
					t.Fatalf("expected store error %v, got %v", tt.expectedError, err)
				}
			}

			snap, err := holder.Load()
			if tt.expectedError != nil && tt.expectedError != ErrNilSnapshot {
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

	snap, err := LoadBundleFromFile(bundleFile)
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
	holder := NewSnapshotHolder()
	initial := &Snapshot{Version: 0}
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
			_ = holder.Store(&Snapshot{Version: uint64(j)})
			time.Sleep(100 * time.Microsecond)
		}
	}()

	wg.Wait()
}

func BenchmarkSnapshotHolder_Load(b *testing.B) {
	holder := NewSnapshotHolder()
	_ = holder.Store(&Snapshot{
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
