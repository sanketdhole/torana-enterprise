package wasm

import (
	"errors"
	"time"

	"github.com/phaselume/torana/internal/pipeline"
)

var (
	// ErrExecutionTimeout is returned when guest plugin execution exceeds its per-call deadline.
	ErrExecutionTimeout = errors.New("wasm plugin execution timed out")
	// ErrMemoryLimitExceeded is returned when guest plugin attempts to allocate past memory page limit.
	ErrMemoryLimitExceeded = errors.New("wasm plugin exceeded memory page limit")
	// ErrCapabilityDenied is returned when a guest calls a host function not declared in its manifest.
	ErrCapabilityDenied = errors.New("wasm capability access denied")
	// ErrGuestTrap is returned when the WebAssembly guest panics or encounters an unreachable trap.
	ErrGuestTrap = errors.New("wasm guest trapped or panicked")
	// ErrPluginClosed is returned when calling an instance pool or filter that has been closed.
	ErrPluginClosed = errors.New("wasm plugin is closed")
	// ErrNilManifest is returned when creating a plugin without a manifest.
	ErrNilManifest = errors.New("plugin manifest cannot be nil")
)

// KVCapability defines namespace-scoped key-value access permissions.
type KVCapability struct {
	Allowed   bool   `json:"allowed"`
	Namespace string `json:"namespace"`
}

// SecretCapability defines declared secret access permissions.
type SecretCapability struct {
	Allowed      bool     `json:"allowed"`
	AllowedNames []string `json:"allowed_names"`
}

// HTTPCallCapability defines allowlisted host egress permissions.
type HTTPCallCapability struct {
	Allowed      bool     `json:"allowed"`
	AllowedHosts []string `json:"allowed_hosts"`
}

// LogCapability declares structured logging permission.
type LogCapability struct {
	Allowed bool `json:"allowed"`
}

// MetricCapability declares metric recording permission.
type MetricCapability struct {
	Allowed bool `json:"allowed"`
}

// CapabilitiesConfig defines all gated capabilities granted to a plugin.
type CapabilitiesConfig struct {
	KV       KVCapability       `json:"kv"`
	Secret   SecretCapability   `json:"secret"`
	HTTPCall HTTPCallCapability `json:"http_call"`
	Log      LogCapability      `json:"log"`
	Metric   MetricCapability   `json:"metric"`
}

// PluginManifest configures the WebAssembly plugin runtime constraints and capabilities.
type PluginManifest struct {
	Name             string                 `json:"name"`
	Version          string                 `json:"version"`
	Phase            pipeline.Phase         `json:"phase"`
	BodyMode         pipeline.BodyMode      `json:"body_mode"`
	FailurePolicy    pipeline.FailurePolicy `json:"failure_policy"`
	MaxBufferBytes   int64                  `json:"max_buffer_bytes"`
	MemoryLimitPages uint32                 `json:"memory_limit_pages"` // 1 page = 64KB
	Timeout          time.Duration          `json:"timeout"`
	PoolSize         int                    `json:"pool_size"`
	Capabilities     CapabilitiesConfig     `json:"capabilities"`
}

// DefaultManifest returns a manifest populated with safe enterprise defaults.
func DefaultManifest(name, version string) *PluginManifest {
	return &PluginManifest{
		Name:             name,
		Version:          version,
		Phase:            pipeline.PhaseRequestHeaders,
		BodyMode:         pipeline.BodyModeNone,
		FailurePolicy:    pipeline.FailurePolicyFailClosed,
		MaxBufferBytes:   1024 * 1024,      // 1MB
		MemoryLimitPages: 32,               // 2MB max linear memory
		Timeout:          100 * time.Millisecond,
		PoolSize:         10,
		Capabilities: CapabilitiesConfig{
			Log:    LogCapability{Allowed: true},
			Metric: MetricCapability{Allowed: true},
		},
	}
}
