package wasm

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/phaselume/torana/internal/pipeline"
)

// HotSwappableFilter implements pipeline.Filter and pipeline.ChunkHook with zero-downtime hot reload.
type HotSwappableFilter struct {
	name          string
	current       atomic.Pointer[WasmFilter]
	inFlightCalls atomic.Int64
	env           *HostEnv
	logger        *slog.Logger
	mu            sync.Mutex
}

// NewHotSwappableFilter creates a new HotSwappableFilter.
func NewHotSwappableFilter(name string, env *HostEnv, logger *slog.Logger) *HotSwappableFilter {
	return &HotSwappableFilter{
		name:   name,
		env:    env,
		logger: logger,
	}
}

// Deploy compiles and loads a new Wasm module version in shadow, atomically swaps, and drains the old version.
func (h *HotSwappableFilter) Deploy(ctx context.Context, manifest *PluginManifest, wasmBytes []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if manifest == nil {
		return ErrNilManifest
	}

	// 1. Shadow loading: initialize new pool and compile module without affecting active traffic
	newPool, err := NewInstancePool(ctx, wasmBytes, manifest, h.env)
	if err != nil {
		return fmt.Errorf("shadow compilation failed for plugin %s (v%s): %w", manifest.Name, manifest.Version, err)
	}

	newFilter := NewWasmFilter(manifest, newPool, h.logger)

	// 2. Atomic pointer swap: new requests immediately hit the new module
	oldFilter := h.current.Swap(newFilter)

	if h.logger != nil {
		oldVer := "none"
		if oldFilter != nil {
			oldVer = oldFilter.Manifest().Version
		}
		h.logger.Info("hot-swapped wasm plugin version",
			"plugin", manifest.Name,
			"old_version", oldVer,
			"new_version", manifest.Version,
		)
	}

	// 3. Gracefully drain the old module
	if oldFilter != nil {
		go func(old *WasmFilter) {
			// Wait for active in-flight calls on the old version to finish (up to 15s)
			drainDeadline := time.Now().Add(15 * time.Second)
			for time.Now().Before(drainDeadline) {
				if old.pool.ActiveCount() == 0 {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			_ = old.Close()
		}(oldFilter)
	}

	return nil
}

// CurrentFilter returns the active WasmFilter instance.
func (h *HotSwappableFilter) CurrentFilter() *WasmFilter {
	return h.current.Load()
}

// Name returns the plugin identifier.
func (h *HotSwappableFilter) Name() string {
	f := h.current.Load()
	if f != nil {
		return f.Name()
	}
	return h.name
}

// Phase returns the active filter's lifecycle phase.
func (h *HotSwappableFilter) Phase() pipeline.Phase {
	f := h.current.Load()
	if f != nil {
		return f.Phase()
	}
	return pipeline.PhaseRequestHeaders
}

// BodyMode returns the active filter's body inspection mode.
func (h *HotSwappableFilter) BodyMode() pipeline.BodyMode {
	f := h.current.Load()
	if f != nil {
		return f.BodyMode()
	}
	return pipeline.BodyModeNone
}

// FailurePolicy returns the active filter's failure policy.
func (h *HotSwappableFilter) FailurePolicy() pipeline.FailurePolicy {
	f := h.current.Load()
	if f != nil {
		return f.FailurePolicy()
	}
	return pipeline.FailurePolicyFailClosed
}

// Process routes the request through the active filter version with in-flight tracking.
func (h *HotSwappableFilter) Process(ctx context.Context, env *pipeline.Envelope) (pipeline.Decision, error) {
	f := h.current.Load()
	if f == nil {
		return pipeline.ContinueDecision(), nil
	}

	h.inFlightCalls.Add(1)
	defer h.inFlightCalls.Add(-1)

	return f.Process(ctx, env)
}

// OnChunk routes streaming chunks through the active filter version with in-flight tracking.
func (h *HotSwappableFilter) OnChunk(ctx context.Context, env *pipeline.Envelope, chunk []byte) ([]byte, error) {
	f := h.current.Load()
	if f == nil {
		return chunk, nil
	}

	h.inFlightCalls.Add(1)
	defer h.inFlightCalls.Add(-1)

	return f.OnChunk(ctx, env, chunk)
}

// Close gracefully terminates the active filter.
func (h *HotSwappableFilter) Close() error {
	f := h.current.Swap(nil)
	if f != nil {
		return f.Close()
	}
	return nil
}

// PluginManager coordinates registered WebAssembly filters and their lifecycle.
type PluginManager struct {
	env     *HostEnv
	logger  *slog.Logger
	filters sync.Map // map[string]*HotSwappableFilter
}

// NewPluginManager creates a new PluginManager.
func NewPluginManager(env *HostEnv, logger *slog.Logger) *PluginManager {
	return &PluginManager{
		env:    env,
		logger: logger,
	}
}

// Deploy deploys or hot-swaps a Wasm module by name.
func (m *PluginManager) Deploy(ctx context.Context, manifest *PluginManifest, wasmBytes []byte) error {
	if manifest == nil {
		return ErrNilManifest
	}

	actual, _ := m.filters.LoadOrStore(manifest.Name, NewHotSwappableFilter(manifest.Name, m.env, m.logger))
	filter := actual.(*HotSwappableFilter)

	return filter.Deploy(ctx, manifest, wasmBytes)
}

// GetFilter retrieves a registered hot-swappable filter by name.
func (m *PluginManager) GetFilter(name string) (*HotSwappableFilter, bool) {
	val, ok := m.filters.Load(name)
	if !ok {
		return nil, false
	}
	return val.(*HotSwappableFilter), true
}

// Close shuts down all registered plugin filters.
func (m *PluginManager) Close() error {
	var errs []error
	m.filters.Range(func(key, value any) bool {
		filter := value.(*HotSwappableFilter)
		if err := filter.Close(); err != nil {
			errs = append(errs, err)
		}
		return true
	})
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}
