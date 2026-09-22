package wasm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/secret"
)

// KVStore defines storage for namespace-scoped key-value operations.
type KVStore interface {
	Get(key string) ([]byte, bool)
	Set(key string, val []byte)
}

// MemoryKVStore is an in-memory thread-safe KVStore.
type MemoryKVStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func NewMemoryKVStore() *MemoryKVStore {
	return &MemoryKVStore{data: make(map[string][]byte)}
}

func (s *MemoryKVStore) Get(key string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[key]
	return v, ok
}

func (s *MemoryKVStore) Set(key string, val []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = val
}

// HostEnv contains host dependencies made available to guest plugins subject to capability gating.
type HostEnv struct {
	KVStore        KVStore
	SecretResolver secret.Resolver
	HTTPClient     *http.Client
	Logger         *slog.Logger
	Metrics        MetricRecorder
}

// MetricRecorder records metrics emitted from Wasm guests.
type MetricRecorder interface {
	AddCounter(name string, val int64)
	SetGauge(name string, val int64)
}

// NoopMetricRecorder drops metrics if none configured.
type NoopMetricRecorder struct{}

func (NoopMetricRecorder) AddCounter(string, int64) {}
func (NoopMetricRecorder) SetGauge(string, int64)   {}

// RegisterHostFunctions registers the sandboxed, capability-gated host functions into the wazero runtime.
func RegisterHostFunctions(ctx context.Context, r wazero.Runtime, manifest *PluginManifest, env *HostEnv) error {
	if env == nil {
		env = &HostEnv{
			KVStore:    NewMemoryKVStore(),
			HTTPClient: &http.Client{Timeout: 5 * time.Second},
			Metrics:    NoopMetricRecorder{},
		}
	}
	if env.KVStore == nil {
		env.KVStore = NewMemoryKVStore()
	}
	if env.HTTPClient == nil {
		env.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	if env.Metrics == nil {
		env.Metrics = NoopMetricRecorder{}
	}
	if env.Logger == nil {
		env.Logger = slog.Default()
	}

	modules := []string{"torana:host", "env"}
	for _, modName := range modules {
		builder := r.NewHostModuleBuilder(modName)

		// 1. KV Get
		builder.NewFunctionBuilder().
			WithFunc(func(ctx context.Context, mod api.Module, keyPtr, keyLen, outPtr, maxLen uint32) int32 {
				if !manifest.Capabilities.KV.Allowed {
					return -1
				}
				keyBytes, ok := mod.Memory().Read(keyPtr, keyLen)
				if !ok {
					return -2
				}
				scopedKey := fmt.Sprintf("%s:%s", manifest.Capabilities.KV.Namespace, string(keyBytes))
				val, found := env.KVStore.Get(scopedKey)
				if !found {
					return 0 // not found
				}
				if uint32(len(val)) > maxLen {
					return -3 // buffer too small
				}
				if !mod.Memory().Write(outPtr, val) {
					return -4
				}
				return int32(len(val))
			}).
			Export("kv_get")

		// 2. KV Set
		builder.NewFunctionBuilder().
			WithFunc(func(ctx context.Context, mod api.Module, keyPtr, keyLen, valPtr, valLen uint32) int32 {
				if !manifest.Capabilities.KV.Allowed {
					return -1
				}
				keyBytes, ok := mod.Memory().Read(keyPtr, keyLen)
				if !ok {
					return -2
				}
				valBytes, ok := mod.Memory().Read(valPtr, valLen)
				if !ok {
					return -3
				}
				scopedKey := fmt.Sprintf("%s:%s", manifest.Capabilities.KV.Namespace, string(keyBytes))
				copiedVal := make([]byte, len(valBytes))
				copy(copiedVal, valBytes)
				env.KVStore.Set(scopedKey, copiedVal)
				return 0
			}).
			Export("kv_set")

		// 3. Secret Get (Declared names only)
		builder.NewFunctionBuilder().
			WithFunc(func(ctx context.Context, mod api.Module, namePtr, nameLen, outPtr, maxLen uint32) int32 {
				if !manifest.Capabilities.Secret.Allowed {
					return -1
				}
				nameBytes, ok := mod.Memory().Read(namePtr, nameLen)
				if !ok {
					return -2
				}
				secretName := string(nameBytes)

				// Verify secret name is in allowed declared list
				allowed := false
				for _, allowedName := range manifest.Capabilities.Secret.AllowedNames {
					if allowedName == secretName {
						allowed = true
						break
					}
				}
				if !allowed {
					return -1 // unauthorized secret access
				}

				var secretVal string
				var err error
				if env.SecretResolver != nil {
					secretVal, err = env.SecretResolver.Resolve(ctx, config.SecretRef{Name: secretName, Provider: "env"})
				} else {
					res := secret.NewEnvResolver()
					secretVal, err = res.Resolve(ctx, config.SecretRef{Name: secretName, Provider: "env"})
				}
				if err != nil {
					return 0 // not found
				}

				valBytes := []byte(secretVal)
				if uint32(len(valBytes)) > maxLen {
					return -3 // buffer too small
				}
				if !mod.Memory().Write(outPtr, valBytes) {
					return -4
				}
				return int32(len(valBytes))
			}).
			Export("secret_get")

		// 4. HTTP Call (Allowlisted hosts only)
		builder.NewFunctionBuilder().
			WithFunc(func(ctx context.Context, mod api.Module, reqPtr, reqLen, resOutPtr, resMaxLen uint32) int32 {
				if !manifest.Capabilities.HTTPCall.Allowed {
					return -1
				}
				reqBytes, ok := mod.Memory().Read(reqPtr, reqLen)
				if !ok {
					return -2
				}

				var httpReq struct {
					URL     string            `json:"url"`
					Method  string            `json:"method"`
					Headers map[string]string `json:"headers"`
					Body    string            `json:"body"`
				}
				if err := json.Unmarshal(reqBytes, &httpReq); err != nil {
					return -3
				}

				parsedURL, err := url.Parse(httpReq.URL)
				if err != nil {
					return -4
				}

				// Enforce allowlisted hosts only
				allowed := false
				host := parsedURL.Hostname()
				for _, allowedHost := range manifest.Capabilities.HTTPCall.AllowedHosts {
					if strings.EqualFold(host, allowedHost) {
						allowed = true
						break
					}
				}
				if !allowed {
					return -1 // forbidden host call!
				}

				method := httpReq.Method
				if method == "" {
					method = http.MethodGet
				}

				var bodyReader io.Reader
				if len(httpReq.Body) > 0 {
					bodyReader = bytes.NewReader([]byte(httpReq.Body))
				}

				callReq, err := http.NewRequestWithContext(ctx, method, httpReq.URL, bodyReader)
				if err != nil {
					return -5
				}
				for k, v := range httpReq.Headers {
					callReq.Header.Set(k, v)
				}

				resp, err := env.HTTPClient.Do(callReq)
				if err != nil {
					return -6
				}
				defer resp.Body.Close()

				respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
				if err != nil {
					return -7
				}

				resData, err := json.Marshal(map[string]any{
					"status_code": resp.StatusCode,
					"body":        string(respBody),
				})
				if err != nil {
					return -8
				}

				if uint32(len(resData)) > resMaxLen {
					return -9
				}
				if !mod.Memory().Write(resOutPtr, resData) {
					return -10
				}
				return int32(len(resData))
			}).
			Export("http_call")

		// 5. Log
		builder.NewFunctionBuilder().
			WithFunc(func(ctx context.Context, mod api.Module, level uint32, msgPtr, msgLen uint32) {
				if !manifest.Capabilities.Log.Allowed {
					return
				}
				msgBytes, ok := mod.Memory().Read(msgPtr, msgLen)
				if !ok {
					return
				}
				msg := string(msgBytes)
				if env.Logger != nil {
					switch level {
					case 1:
						env.Logger.Debug(msg, "plugin", manifest.Name)
					case 2:
						env.Logger.Info(msg, "plugin", manifest.Name)
					case 3:
						env.Logger.Warn(msg, "plugin", manifest.Name)
					case 4:
						env.Logger.Error(msg, "plugin", manifest.Name)
					default:
						env.Logger.Info(msg, "plugin", manifest.Name)
					}
				}
			}).
			Export("log")

		// 6. Metric Counter Add
		builder.NewFunctionBuilder().
			WithFunc(func(ctx context.Context, mod api.Module, namePtr, nameLen uint32, val int64) {
				if !manifest.Capabilities.Metric.Allowed {
					return
				}
				nameBytes, ok := mod.Memory().Read(namePtr, nameLen)
				if !ok {
					return
				}
				env.Metrics.AddCounter(string(nameBytes), val)
			}).
			Export("metric_counter_add")

		// 7. Metric Gauge Set
		builder.NewFunctionBuilder().
			WithFunc(func(ctx context.Context, mod api.Module, namePtr, nameLen uint32, val int64) {
				if !manifest.Capabilities.Metric.Allowed {
					return
				}
				nameBytes, ok := mod.Memory().Read(namePtr, nameLen)
				if !ok {
					return
				}
				env.Metrics.SetGauge(string(nameBytes), val)
			}).
			Export("metric_gauge_set")

		if _, err := builder.Instantiate(ctx); err != nil {
			return fmt.Errorf("failed to instantiate host module %s: %w", modName, err)
		}
	}

	return nil
}
