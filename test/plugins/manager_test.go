package plugins_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sync"
	"testing"

	controlplanev1 "github.com/phaselume/torana/api/proto/controlplane/v1"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/plugins/manager"
	"github.com/phaselume/torana/internal/plugins/oci"
	"github.com/phaselume/torana/internal/plugins/wasm"
)

func createTestArtifact(name, version, runtime, abi string, wasmBytes []byte, schema map[string]any, caps []string) (*oci.Artifact, string) {
	if caps == nil {
		caps = []string{"log", "metric"}
	}
	m := &manager.Manifest{
		Name:             name,
		Version:          version,
		Runtime:          runtime,
		ABICompatibility: abi,
		Capabilities:     caps,
		ConfigSchema:     schema,
		Phase:            "REQUEST_HEADERS",
		BodyMode:         "NONE",
		FailurePolicy:    "FAIL_CLOSED",
		TimeoutMs:        150,
	}
	manifestBytes, _ := json.Marshal(m)

	h := sha256.Sum256(wasmBytes)
	digest := "sha256:" + hex.EncodeToString(h[:])

	ref := "registry.torana.io/plugins/" + name + ":" + version
	art := &oci.Artifact{
		Reference:     ref,
		Digest:        digest,
		ManifestBytes: manifestBytes,
		PayloadBytes:  wasmBytes,
		MediaType:     "application/vnd.torana.plugin.wasm.v1",
		Size:          int64(len(wasmBytes)),
	}
	return art, ref
}

func setupTestManager(t *testing.T) (*manager.PluginManager, *oci.Client, *oci.Cache, func()) {
	tempDir, err := os.MkdirTemp("", "torana-mgr-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	cache, err := oci.NewCache(tempDir)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	policy := oci.NamespacePolicy{
		AllowedRegistries: []string{"registry.torana.io"},
		AllowUnsigned:     true,
	}
	client := oci.NewClient(policy, cache, nil)

	wasmEnv := &wasm.HostEnv{
		KVStore: wasm.NewMemoryKVStore(),
		Metrics: wasm.NoopMetricRecorder{},
	}

	var nacks []string
	var acks []string
	var statuses []*controlplanev1.PluginStatus
	var mu sync.Mutex

	mgr := manager.NewPluginManager(manager.Config{
		SupportedABIs:       []string{"torana:wasm/v1", "torana.plugin.v1"},
		AllowedCapabilities: []string{"kv", "secret", "http_call", "log", "metric"},
		WasmHostEnv:         wasmEnv,
		OCIClient:           client,
		OCICache:            cache,
		StatusReporter: func(status *controlplanev1.PluginStatus) {
			mu.Lock()
			defer mu.Unlock()
			statuses = append(statuses, status)
		},
		NackReporter: func(pluginID, code, reason string) {
			mu.Lock()
			defer mu.Unlock()
			nacks = append(nacks, code)
		},
		AckReporter: func(pluginID, version string) {
			mu.Lock()
			defer mu.Unlock()
			acks = append(acks, version)
		},
	})

	cleanup := func() {
		_ = mgr.Close()
		_ = os.RemoveAll(tempDir)
	}

	return mgr, client, cache, cleanup
}

func TestManager_ManifestValidation_UnsupportedABI(t *testing.T) {
	mgr, client, _, cleanup := setupTestManager(t)
	defer cleanup()

	wasmBytes := buildStandardPluginWasm(int(pipeline.ActionContinue), 200, "", "")
	art, ref := createTestArtifact("unsupported-abi-plugin", "1.0.0", "wasm", "unknown:abi/v99", wasmBytes, nil, nil)
	client.RegisterMockArtifact(ref, art)

	ctx := context.Background()
	req := &manager.InstallRequest{
		Assignment: &controlplanev1.PluginAssignment{
			PluginId: "plugin-bad-abi",
			Endpoint: ref,
		},
		ArtifactRef: ref,
	}

	res, err := mgr.Install(ctx, req)
	if err == nil || !errors.Is(err, manager.ErrUnsupportedABI) {
		t.Fatalf("expected ErrUnsupportedABI, got: %v", err)
	}
	if res.Success {
		t.Fatalf("expected install failure")
	}
	if res.NackCode != "ERR_UNSUPPORTED_ABI" {
		t.Fatalf("expected nack code ERR_UNSUPPORTED_ABI, got %q", res.NackCode)
	}
}

func TestManager_ManifestValidation_DisallowedCapability(t *testing.T) {
	mgr, client, _, cleanup := setupTestManager(t)
	defer cleanup()

	wasmBytes := buildStandardPluginWasm(int(pipeline.ActionContinue), 200, "", "")
	// "raw_filesystem" is not in allowed capabilities list
	art, ref := createTestArtifact("disallowed-cap-plugin", "1.0.0", "wasm", "torana:wasm/v1", wasmBytes, nil, []string{"log", "raw_filesystem"})
	client.RegisterMockArtifact(ref, art)

	ctx := context.Background()
	req := &manager.InstallRequest{
		Assignment: &controlplanev1.PluginAssignment{
			PluginId: "plugin-bad-cap",
			Endpoint: ref,
		},
		ArtifactRef: ref,
	}

	res, err := mgr.Install(ctx, req)
	if err == nil || !errors.Is(err, manager.ErrDisallowedCapability) {
		t.Fatalf("expected ErrDisallowedCapability, got: %v", err)
	}
	if res.Success {
		t.Fatalf("expected install failure")
	}
}

func TestManager_ManifestValidation_ConfigJSONSchema(t *testing.T) {
	mgr, client, _, cleanup := setupTestManager(t)
	defer cleanup()

	schema := map[string]any{
		"type": "object",
		"required": []any{
			"api_key",
		},
		"properties": map[string]any{
			"api_key": map[string]any{
				"type": "string",
			},
			"timeout_sec": map[string]any{
				"type":    "integer",
				"minimum": float64(1),
			},
		},
	}

	wasmBytes := buildStandardPluginWasm(int(pipeline.ActionContinue), 200, "", "")
	art, ref := createTestArtifact("schema-plugin", "1.0.0", "wasm", "torana:wasm/v1", wasmBytes, schema, nil)
	client.RegisterMockArtifact(ref, art)

	ctx := context.Background()

	// 1. Missing required field "api_key"
	reqMissing := &manager.InstallRequest{
		Assignment: &controlplanev1.PluginAssignment{
			PluginId:   "schema-test",
			Endpoint:   ref,
			ConfigJson: `{"timeout_sec": 5}`,
		},
		ArtifactRef: ref,
	}
	res, err := mgr.Install(ctx, reqMissing)
	if err == nil || !errors.Is(err, manager.ErrSchemaValidationFailed) {
		t.Fatalf("expected ErrSchemaValidationFailed for missing required field, got: %v", err)
	}
	if res.NackCode != "ERR_CONFIG_SCHEMA_INVALID" {
		t.Fatalf("expected nack code ERR_CONFIG_SCHEMA_INVALID, got: %q", res.NackCode)
	}

	// 2. Type mismatch (timeout_sec passed as string instead of integer)
	reqTypeMismatch := &manager.InstallRequest{
		Assignment: &controlplanev1.PluginAssignment{
			PluginId:   "schema-test",
			Endpoint:   ref,
			ConfigJson: `{"api_key": "secret", "timeout_sec": "five"}`,
		},
		ArtifactRef: ref,
	}
	_, err = mgr.Install(ctx, reqTypeMismatch)
	if err == nil || !errors.Is(err, manager.ErrSchemaValidationFailed) {
		t.Fatalf("expected ErrSchemaValidationFailed for type mismatch, got: %v", err)
	}

	// 3. Valid Config
	reqValid := &manager.InstallRequest{
		Assignment: &controlplanev1.PluginAssignment{
			PluginId:   "schema-test",
			Endpoint:   ref,
			ConfigJson: `{"api_key": "secret123", "timeout_sec": 10}`,
		},
		ArtifactRef: ref,
	}
	resValid, err := mgr.Install(ctx, reqValid)
	if err != nil {
		t.Fatalf("expected valid config to succeed, got: %v", err)
	}
	if !resValid.Success || resValid.Status.Status != "HEALTHY" {
		t.Fatalf("expected healthy status on successful install")
	}
}

func TestManager_InstallFlow_Success(t *testing.T) {
	mgr, client, _, cleanup := setupTestManager(t)
	defer cleanup()

	wasmBytes := buildStandardPluginWasm(int(pipeline.ActionMutate), 200, "X-Plugin-Applied", "v1")
	art, ref := createTestArtifact("header-mutator", "1.0.0", "wasm", "torana:wasm/v1", wasmBytes, nil, nil)
	client.RegisterMockArtifact(ref, art)

	ctx := context.Background()
	req := &manager.InstallRequest{
		Assignment: &controlplanev1.PluginAssignment{
			PluginId: "mutator",
			Endpoint: ref,
		},
		ArtifactRef: ref,
	}

	res, err := mgr.Install(ctx, req)
	if err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	if !res.Success {
		t.Fatalf("expected install success")
	}
	if res.Status.Status != "HEALTHY" {
		t.Fatalf("expected status HEALTHY, got: %s", res.Status.Status)
	}

	// Verify filter is active and executable
	filter, ok := mgr.GetFilter("mutator")
	if !ok || filter == nil {
		t.Fatalf("expected active filter for mutator")
	}

	env := pipeline.GetEnvelope("req-1", pipeline.PhaseRequestHeaders, http.MethodGet, "/test", nil, nil)
	defer pipeline.PutEnvelope(env)

	dec, err := filter.Process(ctx, env)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}
	if dec.Action != pipeline.ActionMutate {
		t.Fatalf("expected ActionMutate, got: %v", dec.Action)
	}
	if dec.MutateHeaders["X-Plugin-Applied"] != "v1" {
		t.Fatalf("expected mutated header X-Plugin-Applied: v1")
	}
}

func TestManager_InstallFlow_FailingHealthCheck(t *testing.T) {
	mgr, client, _, cleanup := setupTestManager(t)
	defer cleanup()

	// 1. Install good v1.0.0
	wasmGood := buildStandardPluginWasm(int(pipeline.ActionMutate), 200, "X-Version", "v1.0.0")
	artGood, refGood := createTestArtifact("resilient-plugin", "1.0.0", "wasm", "torana:wasm/v1", wasmGood, nil, nil)
	client.RegisterMockArtifact(refGood, artGood)

	ctx := context.Background()
	reqGood := &manager.InstallRequest{
		Assignment: &controlplanev1.PluginAssignment{
			PluginId: "resilient-plugin",
			Endpoint: refGood,
		},
		ArtifactRef: refGood,
	}
	resGood, err := mgr.Install(ctx, reqGood)
	if err != nil || !resGood.Success {
		t.Fatalf("v1 install failed: %v", err)
	}

	// Verify v1 is active
	f1, _ := mgr.GetFilter("resilient-plugin")
	env1 := pipeline.GetEnvelope("req-1", pipeline.PhaseRequestHeaders, http.MethodGet, "/test", nil, nil)
	dec1, err := f1.Process(ctx, env1)
	pipeline.PutEnvelope(env1)
	if err != nil || dec1.MutateHeaders["X-Version"] != "v1.0.0" {
		t.Fatalf("v1 is not properly serving")
	}

	// 2. Prepare upgrade to v2.0.0 with failing health check hook
	wasmBad := buildStandardPluginWasm(int(pipeline.ActionHalt), 500, "", "")
	artBad, refBad := createTestArtifact("resilient-plugin", "2.0.0", "wasm", "torana:wasm/v1", wasmBad, nil, nil)
	client.RegisterMockArtifact(refBad, artBad)

	mgr.SetSmokeTestHook(func(_ context.Context, f pipeline.Filter) error {
		return errors.New("smoke test simulated probe failure")
	})

	reqBad := &manager.InstallRequest{
		Assignment: &controlplanev1.PluginAssignment{
			PluginId: "resilient-plugin",
			Endpoint: refBad,
		},
		ArtifactRef: refBad,
	}

	resBad, err := mgr.Install(ctx, reqBad)
	if err == nil || !errors.Is(err, manager.ErrHealthCheckFailed) {
		t.Fatalf("expected ErrHealthCheckFailed, got: %v", err)
	}
	if resBad.Success {
		t.Fatalf("expected upgrade to fail")
	}
	if resBad.Status.Status != "FAILED" {
		t.Fatalf("expected status FAILED, got: %s", resBad.Status.Status)
	}
	if resBad.NackCode != "ERR_HEALTH_CHECK_FAILED" {
		t.Fatalf("expected nack code ERR_HEALTH_CHECK_FAILED, got: %s", resBad.NackCode)
	}

	// 3. CRITICAL VERIFICATION: v1.0.0 remains ACTIVE and completely UNTOUCHED
	fActive, ok := mgr.GetFilter("resilient-plugin")
	if !ok || fActive == nil {
		t.Fatalf("active filter was removed after failed upgrade")
	}

	envCheck := pipeline.GetEnvelope("req-2", pipeline.PhaseRequestHeaders, http.MethodGet, "/test", nil, nil)
	decCheck, err := fActive.Process(ctx, envCheck)
	pipeline.PutEnvelope(envCheck)
	if err != nil {
		t.Fatalf("previous filter errored: %v", err)
	}
	if decCheck.MutateHeaders["X-Version"] != "v1.0.0" {
		t.Fatalf("expected previous version v1.0.0 still active, got: %v", decCheck.MutateHeaders)
	}
}

func TestManager_VersionPinning(t *testing.T) {
	mgr, client, _, cleanup := setupTestManager(t)
	defer cleanup()

	wasmBytes := buildStandardPluginWasm(int(pipeline.ActionContinue), 200, "", "")
	art, ref := createTestArtifact("pinned-plugin", "2.0.0", "wasm", "torana:wasm/v1", wasmBytes, nil, nil)
	client.RegisterMockArtifact(ref, art)

	ctx := context.Background()

	// Assignment requires exact version "1.5.0", but artifact is "2.0.0"
	req := &manager.InstallRequest{
		Assignment: &controlplanev1.PluginAssignment{
			PluginId: "pinned-plugin",
			Endpoint: ref,
		},
		ArtifactRef:   ref,
		PinnedVersion: "1.5.0",
	}

	res, err := mgr.Install(ctx, req)
	if err == nil || !errors.Is(err, manager.ErrVersionPinnedMismatch) {
		t.Fatalf("expected ErrVersionPinnedMismatch, got: %v", err)
	}
	if res.Success {
		t.Fatalf("expected version pinning failure")
	}
	if res.NackCode != "ERR_VERSION_PINNED_MISMATCH" {
		t.Fatalf("expected nack code ERR_VERSION_PINNED_MISMATCH, got: %s", res.NackCode)
	}

	// Now match pinned version exactly
	reqCorrect := &manager.InstallRequest{
		Assignment: &controlplanev1.PluginAssignment{
			PluginId: "pinned-plugin",
			Endpoint: ref,
		},
		ArtifactRef:   ref,
		PinnedVersion: "2.0.0",
	}

	resCorrect, err := mgr.Install(ctx, reqCorrect)
	if err != nil || !resCorrect.Success {
		t.Fatalf("expected matching pinned version to succeed, got: %v", err)
	}
}

func TestManager_CanaryRouting(t *testing.T) {
	mgr, client, _, cleanup := setupTestManager(t)
	defer cleanup()

	ctx := context.Background()

	// 1. Install stable v1
	wasmV1 := buildStandardPluginWasm(int(pipeline.ActionMutate), 200, "X-Version", "v1")
	artV1, refV1 := createTestArtifact("canary-test", "1.0.0", "wasm", "torana:wasm/v1", wasmV1, nil, nil)
	client.RegisterMockArtifact(refV1, artV1)

	_, err := mgr.Install(ctx, &manager.InstallRequest{
		Assignment:  &controlplanev1.PluginAssignment{PluginId: "canary-test", Endpoint: refV1},
		ArtifactRef: refV1,
	})
	if err != nil {
		t.Fatalf("v1 install failed: %v", err)
	}

	// 2. Install canary v2 with 50% traffic
	wasmV2 := buildStandardPluginWasm(int(pipeline.ActionMutate), 200, "X-Version", "v2")
	artV2, refV2 := createTestArtifact("canary-test", "2.0.0", "wasm", "torana:wasm/v1", wasmV2, nil, nil)
	client.RegisterMockArtifact(refV2, artV2)

	resV2, err := mgr.Install(ctx, &manager.InstallRequest{
		Assignment:       &controlplanev1.PluginAssignment{PluginId: "canary-test", Endpoint: refV2},
		ArtifactRef:      refV2,
		CanaryPercentage: 50,
	})
	if err != nil || !resV2.Success {
		t.Fatalf("canary install failed: %v", err)
	}

	filter, ok := mgr.GetFilter("canary-test")
	if !ok || filter == nil {
		t.Fatalf("filter not found")
	}

	// Execute 100 requests, verify both v1 and v2 receive traffic
	v1Count := 0
	v2Count := 0

	for i := 0; i < 100; i++ {
		env := pipeline.GetEnvelope("canary-req", pipeline.PhaseRequestHeaders, http.MethodGet, "/test", nil, nil)
		dec, err := filter.Process(ctx, env)
		pipeline.PutEnvelope(env)
		if err != nil {
			t.Fatalf("Process failed: %v", err)
		}
		if dec.MutateHeaders["X-Version"] == "v1" {
			v1Count++
		} else if dec.MutateHeaders["X-Version"] == "v2" {
			v2Count++
		}
	}

	if v1Count == 0 || v2Count == 0 {
		t.Fatalf("expected both v1 and v2 traffic with 50%% canary, got v1: %d, v2: %d", v1Count, v2Count)
	}
}

func TestManager_Rollback(t *testing.T) {
	mgr, client, _, cleanup := setupTestManager(t)
	defer cleanup()

	ctx := context.Background()

	// 1. Attempt rollback with no prior version -> ErrRollbackUnavailable
	_, err := mgr.Rollback(ctx, "nonexistent")
	if err == nil || !errors.Is(err, manager.ErrPluginNotFound) {
		t.Fatalf("expected ErrPluginNotFound, got: %v", err)
	}

	// 2. Install v1
	wasmV1 := buildStandardPluginWasm(int(pipeline.ActionMutate), 200, "X-Version", "v1.0.0")
	artV1, refV1 := createTestArtifact("rollback-plugin", "1.0.0", "wasm", "torana:wasm/v1", wasmV1, nil, nil)
	client.RegisterMockArtifact(refV1, artV1)

	_, err = mgr.Install(ctx, &manager.InstallRequest{
		Assignment:  &controlplanev1.PluginAssignment{PluginId: "rollback-plugin", Endpoint: refV1},
		ArtifactRef: refV1,
	})
	if err != nil {
		t.Fatalf("v1 install failed: %v", err)
	}

	// 3. Attempt rollback when only 1 version exists
	_, err = mgr.Rollback(ctx, "rollback-plugin")
	if err == nil || !errors.Is(err, manager.ErrRollbackUnavailable) {
		t.Fatalf("expected ErrRollbackUnavailable, got: %v", err)
	}

	// 4. Upgrade to v2
	wasmV2 := buildStandardPluginWasm(int(pipeline.ActionMutate), 200, "X-Version", "v2.0.0")
	artV2, refV2 := createTestArtifact("rollback-plugin", "2.0.0", "wasm", "torana:wasm/v1", wasmV2, nil, nil)
	client.RegisterMockArtifact(refV2, artV2)

	_, err = mgr.Install(ctx, &manager.InstallRequest{
		Assignment:  &controlplanev1.PluginAssignment{PluginId: "rollback-plugin", Endpoint: refV2},
		ArtifactRef: refV2,
	})
	if err != nil {
		t.Fatalf("v2 upgrade failed: %v", err)
	}

	// Verify v2 is serving
	filter, _ := mgr.GetFilter("rollback-plugin")
	envCheck := pipeline.GetEnvelope("req", pipeline.PhaseRequestHeaders, http.MethodGet, "/test", nil, nil)
	decCheck, _ := filter.Process(ctx, envCheck)
	pipeline.PutEnvelope(envCheck)
	if decCheck.MutateHeaders["X-Version"] != "v2.0.0" {
		t.Fatalf("expected v2.0.0, got: %v", decCheck.MutateHeaders)
	}

	// 5. Trigger Rollback!
	status, err := mgr.Rollback(ctx, "rollback-plugin")
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}
	if status.Status != "ROLLED_BACK" {
		t.Fatalf("expected status ROLLED_BACK, got: %s", status.Status)
	}

	// 6. Verify v1.0.0 is restored and serving!
	filterRestored, ok := mgr.GetFilter("rollback-plugin")
	if !ok || filterRestored == nil {
		t.Fatalf("filter not found after rollback")
	}

	envRestored := pipeline.GetEnvelope("req-restored", pipeline.PhaseRequestHeaders, http.MethodGet, "/test", nil, nil)
	decRestored, err := filterRestored.Process(ctx, envRestored)
	pipeline.PutEnvelope(envRestored)
	if err != nil {
		t.Fatalf("restored filter process failed: %v", err)
	}
	if decRestored.MutateHeaders["X-Version"] != "v1.0.0" {
		t.Fatalf("expected restored version v1.0.0, got: %v", decRestored.MutateHeaders)
	}
}

func TestManager_GarbageCollection(t *testing.T) {
	mgr, client, cache, cleanup := setupTestManager(t)
	defer cleanup()

	ctx := context.Background()

	// Install v1 (d1)
	wasmV1 := buildStandardPluginWasm(int(pipeline.ActionContinue), 200, "", "")
	artV1, refV1 := createTestArtifact("gc-plugin", "1.0.0", "wasm", "torana:wasm/v1", wasmV1, nil, nil)
	client.RegisterMockArtifact(refV1, artV1)
	_, _ = mgr.Install(ctx, &manager.InstallRequest{
		Assignment:  &controlplanev1.PluginAssignment{PluginId: "gc-plugin", Endpoint: refV1},
		ArtifactRef: refV1,
	})

	// Also put an unreferenced artifact dOrphan directly in cache
	dOrphan := "sha256:9999999999999999999999999999999999999999999999999999999999999999"
	_ = cache.Put(&oci.Artifact{
		Digest:        dOrphan,
		PayloadBytes:  []byte("orphan payload"),
		ManifestBytes: []byte(`{"name":"orphan"}`),
	})

	if !cache.Has(artV1.Digest) || !cache.Has(dOrphan) {
		t.Fatalf("both artifacts should be in cache initially")
	}

	// Trigger Garbage Collection via Manager
	purged, _, err := mgr.GarbageCollect(ctx)
	if err != nil {
		t.Fatalf("GarbageCollect failed: %v", err)
	}
	if purged != 1 {
		t.Fatalf("expected 1 orphan artifact purged, got: %d", purged)
	}

	// Active v1 remains, orphan is gone
	if !cache.Has(artV1.Digest) {
		t.Fatalf("active artifact v1 was purged")
	}
	if cache.Has(dOrphan) {
		t.Fatalf("orphan artifact was not purged")
	}
}
