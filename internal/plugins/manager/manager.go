package manager

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	controlplanev1 "github.com/phaselume/torana/api/proto/controlplane/v1"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/plugins/oci"
	"github.com/phaselume/torana/internal/plugins/process"
	"github.com/phaselume/torana/internal/plugins/wasm"
)

// Config configures runtime dependencies and security parameters for the PluginManager.
type Config struct {
	SupportedABIs       []string
	AllowedCapabilities []string
	WasmHostEnv         *wasm.HostEnv
	ProcessManager      *process.ProcessPluginManager
	OCIClient           *oci.Client
	OCICache            *oci.Cache
	Logger              *slog.Logger
	StatusReporter      func(status *controlplanev1.PluginStatus)
	NackReporter        func(pluginID, code, reason string)
	AckReporter         func(pluginID, version string)
}

// activePluginState tracks the active, canary, and historical rollback state of an installed plugin.
type activePluginState struct {
	pluginID        string
	manifest        *Manifest
	version         string
	digest          string
	canaryFilter    *CanaryFilter
	currentFilter   pipeline.Filter
	previousFilter  pipeline.Filter
	previousVersion string
	previousDigest  string
}

// PluginManager coordinates plugin artifact fetching, validation, sandboxing, and hot lifecycle management.
type PluginManager struct {
	cfg           Config
	plugins       sync.Map // map[string]*activePluginState
	mu            sync.Mutex
	smokeTestHook func(ctx context.Context, f pipeline.Filter) error // Overridable for testing
}

// NewPluginManager creates an initialized PluginManager.
func NewPluginManager(cfg Config) *PluginManager {
	if len(cfg.SupportedABIs) == 0 {
		cfg.SupportedABIs = []string{"torana:wasm/v1", "torana.plugin.v1"}
	}
	if len(cfg.AllowedCapabilities) == 0 {
		cfg.AllowedCapabilities = []string{"kv", "secret", "http_call", "log", "metric"}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &PluginManager{
		cfg: cfg,
	}
}

// SetSmokeTestHook configures a custom smoke test probe for testing failing health checks.
func (m *PluginManager) SetSmokeTestHook(hook func(ctx context.Context, f pipeline.Filter) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.smokeTestHook = hook
}

// Install implements the complete installation and upgrade lifecycle per DESIGN.md 5.5:
// Fetch -> Validate Manifest -> Shadow Load -> Health Check / Smoke Test -> Atomic Swap -> Report Status.
func (m *PluginManager) Install(ctx context.Context, req *InstallRequest) (*InstallResult, error) {
	if req == nil || req.Assignment == nil {
		return nil, ErrNilAssignment
	}

	start := time.Now()
	assignment := req.Assignment
	pluginID := assignment.PluginId
	if pluginID == "" {
		pluginID = "anonymous-plugin"
	}

	// 1. Fetch Artifact from OCI Registry or Cache
	ref := req.ArtifactRef
	if ref == "" {
		ref = assignment.Endpoint
	}

	artifact, err := m.cfg.OCIClient.FetchArtifact(ctx, ref, oci.AuthConfig{
		Token: req.PullToken,
	})
	if err != nil {
		reason := fmt.Sprintf("failed to fetch artifact %q: %v", ref, err)
		m.reportNack(pluginID, "ERR_OCI_FETCH_FAILED", reason)
		status := &controlplanev1.PluginStatus{
			PluginId:     pluginID,
			Status:       "FAILED",
			ErrorMessage: reason,
			LatencyMs:    time.Since(start).Milliseconds(),
		}
		m.reportStatus(status)
		return &InstallResult{
			Success:    false,
			PluginID:   pluginID,
			NackCode:   "ERR_OCI_FETCH_FAILED",
			NackReason: reason,
			Status:     status,
		}, err
	}

	// 2. Parse and Validate Manifest
	manifest, err := ParseManifest(artifact.ManifestBytes)
	if err != nil {
		reason := fmt.Sprintf("invalid plugin manifest: %v", err)
		m.reportNack(pluginID, "ERR_INVALID_MANIFEST", reason)
		status := &controlplanev1.PluginStatus{
			PluginId:     pluginID,
			Status:       "FAILED",
			ErrorMessage: reason,
			LatencyMs:    time.Since(start).Milliseconds(),
		}
		m.reportStatus(status)
		return &InstallResult{
			Success:    false,
			PluginID:   pluginID,
			NackCode:   "ERR_INVALID_MANIFEST",
			NackReason: reason,
			Status:     status,
		}, err
	}

	// Validate ABI Compatibility & Capabilities
	if err := ValidateManifest(manifest, m.cfg.SupportedABIs, m.cfg.AllowedCapabilities); err != nil {
		code := "ERR_VALIDATION_FAILED"
		if errors.Is(err, ErrUnsupportedABI) {
			code = "ERR_UNSUPPORTED_ABI"
		} else if errors.Is(err, ErrDisallowedCapability) {
			code = "ERR_DISALLOWED_CAPABILITY"
		}
		m.reportNack(pluginID, code, err.Error())
		status := &controlplanev1.PluginStatus{
			PluginId:     pluginID,
			Status:       "FAILED",
			ErrorMessage: err.Error(),
			LatencyMs:    time.Since(start).Milliseconds(),
		}
		m.reportStatus(status)
		return &InstallResult{
			Success:    false,
			PluginID:   pluginID,
			NackCode:   code,
			NackReason: err.Error(),
			Status:     status,
		}, err
	}

	// 3. Version Pinning Verification
	if req.PinnedVersion != "" {
		if manifest.Version != req.PinnedVersion && artifact.Digest != req.PinnedVersion {
			reason := fmt.Sprintf("pinned version mismatch: required %q, artifact has version %q (digest %s)",
				req.PinnedVersion, manifest.Version, artifact.Digest)
			m.reportNack(pluginID, "ERR_VERSION_PINNED_MISMATCH", reason)
			status := &controlplanev1.PluginStatus{
				PluginId:     pluginID,
				Status:       "FAILED",
				ErrorMessage: reason,
				LatencyMs:    time.Since(start).Milliseconds(),
			}
			m.reportStatus(status)
			return &InstallResult{
				Success:    false,
				PluginID:   pluginID,
				NackCode:   "ERR_VERSION_PINNED_MISMATCH",
				NackReason: reason,
				Status:     status,
			}, ErrVersionPinnedMismatch
		}
	}

	// 4. Validate Config Schema
	if err := ValidateConfigJSON(manifest.ConfigSchema, assignment.ConfigJson); err != nil {
		reason := fmt.Sprintf("config failed schema validation: %v", err)
		m.reportNack(pluginID, "ERR_CONFIG_SCHEMA_INVALID", reason)
		status := &controlplanev1.PluginStatus{
			PluginId:     pluginID,
			Status:       "FAILED",
			ErrorMessage: reason,
			LatencyMs:    time.Since(start).Milliseconds(),
		}
		m.reportStatus(status)
		return &InstallResult{
			Success:    false,
			PluginID:   pluginID,
			NackCode:   "ERR_CONFIG_SCHEMA_INVALID",
			NackReason: reason,
			Status:     status,
		}, err
	}

	// 5. Shadow Load (Isolated Compilation / Instantiation)
	shadowFilter, err := m.createShadowInstance(ctx, manifest, artifact.PayloadBytes)
	if err != nil {
		reason := fmt.Sprintf("shadow instantiation failed: %v", err)
		m.reportNack(pluginID, "ERR_SHADOW_LOAD_FAILED", reason)
		status := &controlplanev1.PluginStatus{
			PluginId:     pluginID,
			Status:       "FAILED",
			ErrorMessage: reason,
			LatencyMs:    time.Since(start).Milliseconds(),
		}
		m.reportStatus(status)
		return &InstallResult{
			Success:    false,
			PluginID:   pluginID,
			NackCode:   "ERR_SHADOW_LOAD_FAILED",
			NackReason: reason,
			Status:     status,
		}, err
	}

	// 6. Health Check / Smoke Test on Shadow Instance
	// ANY failure leaves the previous active chain 100% untouched!
	if err := m.runSmokeTest(ctx, shadowFilter); err != nil {
		_ = closeFilter(shadowFilter)
		reason := fmt.Sprintf("shadow health check failed: %v", err)
		m.reportNack(pluginID, "ERR_HEALTH_CHECK_FAILED", reason)
		status := &controlplanev1.PluginStatus{
			PluginId:     pluginID,
			Status:       "FAILED",
			ErrorMessage: reason,
			LatencyMs:    time.Since(start).Milliseconds(),
		}
		m.reportStatus(status)
		return &InstallResult{
			Success:    false,
			PluginID:   pluginID,
			NackCode:   "ERR_HEALTH_CHECK_FAILED",
			NackReason: reason,
			Status:     status,
		}, ErrHealthCheckFailed
	}

	if req.DryRun {
		_ = closeFilter(shadowFilter)
		return &InstallResult{
			Success:  true,
			PluginID: pluginID,
			Version:  manifest.Version,
			Digest:   artifact.Digest,
		}, nil
	}

	// 7. Atomic Swap into Filter Chain
	m.mu.Lock()
	defer m.mu.Unlock()

	var existing *activePluginState
	if val, ok := m.plugins.Load(pluginID); ok {
		existing = val.(*activePluginState)
	}

	newState := &activePluginState{
		pluginID: pluginID,
		manifest: manifest,
		version:  manifest.Version,
		digest:   artifact.Digest,
	}

	if existing != nil {
		// Clean up older discarded filter if one exists
		if existing.previousFilter != nil && existing.previousFilter != existing.currentFilter {
			go func(old pipeline.Filter) {
				time.Sleep(500 * time.Millisecond)
				_ = closeFilter(old)
			}(existing.previousFilter)
		}

		newState.previousFilter = existing.currentFilter
		newState.previousVersion = existing.version
		newState.previousDigest = existing.digest
		newState.canaryFilter = existing.canaryFilter
	}

	if req.CanaryPercentage > 0 && existing != nil && existing.currentFilter != nil {
		// Progressive canary rollout
		if newState.canaryFilter == nil {
			newState.canaryFilter = NewCanaryFilter(pluginID, existing.currentFilter)
		}
		newState.canaryFilter.SetCanary(shadowFilter, req.CanaryPercentage)
		newState.currentFilter = shadowFilter
	} else {
		// 100% promotion / immediate active swap
		if newState.canaryFilter != nil {
			_ = newState.canaryFilter.ClearCanary()
		}
		newState.canaryFilter = NewCanaryFilter(pluginID, shadowFilter)
		newState.currentFilter = shadowFilter
	}

	m.plugins.Store(pluginID, newState)

	latency := time.Since(start).Milliseconds()
	status := &controlplanev1.PluginStatus{
		PluginId:  pluginID,
		Status:    "HEALTHY",
		LatencyMs: latency,
	}
	m.reportStatus(status)
	m.reportAck(pluginID, manifest.Version)

	return &InstallResult{
		Success:          true,
		PluginID:         pluginID,
		Version:          manifest.Version,
		Digest:           artifact.Digest,
		CanaryPercentage: req.CanaryPercentage,
		Status:           status,
	}, nil
}

// Rollback atomically reverts the plugin to its previous successfully deployed version.
func (m *PluginManager) Rollback(ctx context.Context, pluginID string) (*controlplanev1.PluginStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	val, ok := m.plugins.Load(pluginID)
	if !ok {
		return nil, ErrPluginNotFound
	}
	state := val.(*activePluginState)

	if state.previousFilter == nil {
		return nil, ErrRollbackUnavailable
	}

	// Revert canary filter to previous stable filter
	if state.canaryFilter != nil {
		_ = state.canaryFilter.ClearCanary()
		state.canaryFilter.PromoteCanary()
		state.canaryFilter = NewCanaryFilter(pluginID, state.previousFilter)
	}

	// Drain discarded filter
	discarded := state.currentFilter
	if discarded != nil {
		go func(f pipeline.Filter) {
			time.Sleep(500 * time.Millisecond)
			_ = closeFilter(f)
		}(discarded)
	}

	// Update state
	state.currentFilter = state.previousFilter
	state.version = state.previousVersion
	state.digest = state.previousDigest
	state.previousFilter = nil
	state.previousVersion = ""
	state.previousDigest = ""

	m.plugins.Store(pluginID, state)

	status := &controlplanev1.PluginStatus{
		PluginId: pluginID,
		Status:   "ROLLED_BACK",
	}
	m.reportStatus(status)

	if m.cfg.Logger != nil {
		m.cfg.Logger.Info("rolled back plugin to previous version",
			"plugin", pluginID,
			"version", state.version,
		)
	}

	return status, nil
}

// GetFilter retrieves the active pipeline.Filter for a registered plugin.
func (m *PluginManager) GetFilter(pluginID string) (pipeline.Filter, bool) {
	val, ok := m.plugins.Load(pluginID)
	if !ok {
		return nil, false
	}
	state := val.(*activePluginState)
	if state.canaryFilter != nil {
		return state.canaryFilter, true
	}
	return state.currentFilter, true
}

// GarbageCollect removes unused plugin artifacts from the OCI disk cache.
func (m *PluginManager) GarbageCollect(ctx context.Context) (int, int64, error) {
	if m.cfg.OCICache == nil {
		return 0, 0, nil
	}

	activeDigests := make([]string, 0)
	m.plugins.Range(func(_, val any) bool {
		s := val.(*activePluginState)
		if s.digest != "" {
			activeDigests = append(activeDigests, s.digest)
		}
		if s.previousDigest != "" {
			activeDigests = append(activeDigests, s.previousDigest)
		}
		return true
	})

	return m.cfg.OCICache.GarbageCollect(ctx, activeDigests)
}

func (m *PluginManager) createShadowInstance(ctx context.Context, manifest *Manifest, payload []byte) (pipeline.Filter, error) {
	runtime := manifest.Runtime
	if runtime == "" {
		runtime = "wasm"
	}

	switch runtime {
	case "wasm":
		wasmManifest := manifest.Wasm
		if wasmManifest == nil {
			wasmManifest = wasm.DefaultManifest(manifest.Name, manifest.Version)
			wasmManifest.Phase = manifest.ToPipelinePhase()
			wasmManifest.BodyMode = manifest.ToPipelineBodyMode()
			wasmManifest.FailurePolicy = manifest.ToPipelineFailurePolicy()
			wasmManifest.Timeout = manifest.TimeoutDuration()
		}

		pool, err := wasm.NewInstancePool(ctx, payload, wasmManifest, m.cfg.WasmHostEnv)
		if err != nil {
			return nil, fmt.Errorf("failed to compile shadow wasm pool: %w", err)
		}
		return wasm.NewWasmFilter(wasmManifest, pool, m.cfg.Logger), nil

	case "process":
		procManifest := manifest.Process
		if procManifest == nil {
			procManifest = process.DefaultManifest(manifest.Name, process.TierLocalProcess)
			procManifest.Version = manifest.Version
			procManifest.Phase = manifest.ToPipelinePhase()
			procManifest.BodyMode = manifest.ToPipelineBodyMode()
			procManifest.FailurePolicy = manifest.ToPipelineFailurePolicy()
			procManifest.Timeout = manifest.TimeoutDuration()
		}

		if m.cfg.ProcessManager != nil {
			return m.cfg.ProcessManager.RegisterPlugin(procManifest)
		}
		return nil, fmt.Errorf("process plugin manager not initialized")

	default:
		return nil, fmt.Errorf("unsupported runtime %q", manifest.Runtime)
	}
}

func (m *PluginManager) runSmokeTest(ctx context.Context, f pipeline.Filter) error {
	m.mu.Lock()
	hook := m.smokeTestHook
	m.mu.Unlock()

	if hook != nil {
		return hook(ctx, f)
	}

	// Standard health check smoke test execution
	smokeEnv := pipeline.GetEnvelope("smoke-test", pipeline.PhaseRequestHeaders, http.MethodGet, "/torana/healthz", nil, nil)
	defer pipeline.PutEnvelope(smokeEnv)

	smokeCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	_, err := f.Process(smokeCtx, smokeEnv)
	return err
}

func (m *PluginManager) reportStatus(status *controlplanev1.PluginStatus) {
	if m.cfg.StatusReporter != nil && status != nil {
		m.cfg.StatusReporter(status)
	}
}

func (m *PluginManager) reportNack(pluginID, code, reason string) {
	if m.cfg.NackReporter != nil {
		m.cfg.NackReporter(pluginID, code, reason)
	}
}

func (m *PluginManager) reportAck(pluginID, version string) {
	if m.cfg.AckReporter != nil {
		m.cfg.AckReporter(pluginID, version)
	}
}

func closeFilter(f pipeline.Filter) error {
	if c, ok := f.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

// Close gracefully stops all active plugins.
func (m *PluginManager) Close() error {
	m.plugins.Range(func(key, val any) bool {
		s := val.(*activePluginState)
		if s.currentFilter != nil {
			_ = closeFilter(s.currentFilter)
		}
		if s.previousFilter != nil {
			_ = closeFilter(s.previousFilter)
		}
		return true
	})
	return nil
}
