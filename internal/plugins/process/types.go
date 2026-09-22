package process

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	"github.com/phaselume/torana/internal/pipeline"
)

var (
	// ErrChecksumMismatch is returned when the binary executable hash does not match platform specification.
	ErrChecksumMismatch = errors.New("plugin binary sha256 checksum mismatch")
	// ErrDisallowedBinaryPath is returned when a binary path is not in the approved directory allowlist.
	ErrDisallowedBinaryPath = errors.New("plugin binary path is not in allowed directories")
	// ErrProcessExited is returned when the child process unexpectedly exits.
	ErrProcessExited = errors.New("child plugin process exited")
	// ErrHealthCheckFailed is returned when periodic health probing fails.
	ErrHealthCheckFailed = errors.New("plugin health check probe failed")
	// ErrPluginTimeout is returned when a plugin invocation exceeds its deadline.
	ErrPluginTimeout = errors.New("plugin invocation timed out")
	// ErrCircuitOpen is returned when calls are rejected because the circuit breaker is open.
	ErrCircuitOpen = errors.New("plugin circuit breaker open")
	// ErrHandshakeFailed is returned when gRPC handshake exchange is rejected.
	ErrHandshakeFailed = errors.New("plugin handshake negotiation rejected")
	// ErrPluginClosed is returned when invoking an already closed plugin.
	ErrPluginClosed = errors.New("plugin is closed")
	// ErrNilManifest is returned when creating a plugin without a manifest.
	ErrNilManifest = errors.New("process manifest cannot be nil")
)

// PluginTier specifies whether the plugin runs as a local child process or over a remote gRPC service.
type PluginTier string

const (
	TierLocalProcess PluginTier = "local"
	TierRemote       PluginTier = "remote"
)

// PluginKind identifies whether the plugin behaves as a pipeline filter, ingress listener, or egress connector.
type PluginKind string

const (
	KindFilter  PluginKind = "filter"
	KindIngress PluginKind = "ingress"
	KindEgress  PluginKind = "egress"
)

// RLimitsConfig specifies resource constraints for the child process.
type RLimitsConfig struct {
	MaxMemoryBytes uint64 `json:"max_memory_bytes"` // RLIMIT_AS (0 for unlimited)
	MaxFDs         uint64 `json:"max_fds"`          // RLIMIT_NOFILE (0 for default)
	CPUTimeSeconds uint64 `json:"cpu_time_seconds"` // RLIMIT_CPU (0 for unlimited)
}

// TLSConfig configures mTLS client connection for remote tier plugins.
type TLSConfig struct {
	CertPEM            string `json:"cert_pem"`
	KeyPEM             string `json:"key_pem"`
	CAPEM              string `json:"ca_pem"`
	ServerName         string `json:"server_name"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

// ToTLSConfig converts TLSConfig into a standard *tls.Config.
func (t *TLSConfig) ToTLSConfig() (*tls.Config, error) {
	if t == nil {
		return nil, nil
	}

	cfg := &tls.Config{
		ServerName:         t.ServerName,
		InsecureSkipVerify: t.InsecureSkipVerify,
	}

	if t.CertPEM != "" && t.KeyPEM != "" {
		cert, err := tls.X509KeyPair([]byte(t.CertPEM), []byte(t.KeyPEM))
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	if t.CAPEM != "" {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM([]byte(t.CAPEM)) {
			cfg.RootCAs = pool
		}
	}

	return cfg, nil
}

// ProcessManifest defines the execution parameters, security sandbox, and connectivity for a plugin.
type ProcessManifest struct {
	Name                    string                 `json:"name"`
	Version                 string                 `json:"version"`
	Tier                    PluginTier             `json:"tier"` // "local" or "remote"
	Kind                    PluginKind             `json:"kind"` // "filter", "ingress", "egress"
	BinaryPath              string                 `json:"binary_path"`
	SHA256Checksum          string                 `json:"sha256_checksum"` // Expected SHA-256 hex string from platform
	AllowedBinaryDirs       []string               `json:"allowed_binary_dirs"`
	Args                    []string               `json:"args"`
	Env                     map[string]string      `json:"env"`
	SocketDir               string                 `json:"socket_dir"`      // Directory for unix domain socket (default /tmp)
	RemoteEndpoint          string                 `json:"remote_endpoint"` // host:port for remote tier
	TLS                     *TLSConfig             `json:"tls,omitempty"`
	RunAsUID                *uint32                `json:"run_as_uid,omitempty"`
	RunAsGID                *uint32                `json:"run_as_gid,omitempty"`
	RLimits                 RLimitsConfig          `json:"rlimits"`
	Phase                   pipeline.Phase         `json:"phase"`
	BodyMode                pipeline.BodyMode      `json:"body_mode"`
	FailurePolicy           pipeline.FailurePolicy `json:"failure_policy"`
	Timeout                 time.Duration          `json:"timeout"`
	HealthCheckInterval     time.Duration          `json:"health_check_interval"`
	MaxRestartAttempts      int                    `json:"max_restart_attempts"`
	RestartBackoff          time.Duration          `json:"restart_backoff"`
	CircuitBreakerThreshold int64                  `json:"circuit_breaker_threshold"`
	CircuitBreakerCooldown  time.Duration          `json:"circuit_breaker_cooldown"`
}

// DefaultManifest returns a ProcessManifest with safe defaults.
func DefaultManifest(name string, tier PluginTier) *ProcessManifest {
	return &ProcessManifest{
		Name:                    name,
		Version:                 "1.0.0",
		Tier:                    tier,
		Kind:                    KindFilter,
		SocketDir:               "/tmp",
		Phase:                   pipeline.PhaseRequestHeaders,
		BodyMode:                pipeline.BodyModeNone,
		FailurePolicy:           pipeline.FailurePolicyFailClosed,
		Timeout:                 500 * time.Millisecond,
		HealthCheckInterval:     10 * time.Second,
		MaxRestartAttempts:      5,
		RestartBackoff:          100 * time.Millisecond,
		CircuitBreakerThreshold: 5,
		CircuitBreakerCooldown:  10 * time.Second,
	}
}
