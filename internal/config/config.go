package config

import (
	"errors"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

var (
	// ErrNilSnapshot is returned when attempting to store a nil snapshot.
	ErrNilSnapshot = errors.New("snapshot cannot be nil")
	// ErrNoSnapshotAvailable is returned when loading from an uninitialized holder.
	ErrNoSnapshotAvailable = errors.New("no active configuration snapshot available")
)

// BootstrapConfig contains static configuration loaded once at process startup from env/flags.
type BootstrapConfig struct {
	Namespace          string
	ControlPlaneAddr   string
	ControlPlaneTLS    bool
	HTTPPort           string
	HTTPHost           string
	Environment        string
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
	IdleTimeout        time.Duration
	DrainTimeout       time.Duration
	TelemetryQueueSize int
}

// LoadBootstrapConfig loads startup flags and environment variables.
func LoadBootstrapConfig() *BootstrapConfig {
	readSec, _ := strconv.Atoi(getEnv("READ_TIMEOUT_SEC", "15"))
	writeSec, _ := strconv.Atoi(getEnv("WRITE_TIMEOUT_SEC", "15"))
	idleSec, _ := strconv.Atoi(getEnv("IDLE_TIMEOUT_SEC", "60"))
	drainSec, _ := strconv.Atoi(getEnv("DRAIN_TIMEOUT_SEC", "30"))
	queueSize, _ := strconv.Atoi(getEnv("TELEMETRY_QUEUE_SIZE", "10000"))

	return &BootstrapConfig{
		Namespace:          getEnv("GATEWAY_NAMESPACE", "default"),
		ControlPlaneAddr:   getEnv("CONTROL_PLANE_ADDR", "localhost:9090"),
		ControlPlaneTLS:    getEnv("CONTROL_PLANE_TLS", "false") == "true",
		HTTPPort:           getEnv("PORT", "8080"),
		HTTPHost:           getEnv("HOST", "0.0.0.0"),
		Environment:        getEnv("ENV", "development"),
		ReadTimeout:        time.Duration(readSec) * time.Second,
		WriteTimeout:       time.Duration(writeSec) * time.Second,
		IdleTimeout:        time.Duration(idleSec) * time.Second,
		DrainTimeout:       time.Duration(drainSec) * time.Second,
		TelemetryQueueSize: queueSize,
	}
}

// HTTPAddress returns the host:port string for the HTTP ingress.
func (b *BootstrapConfig) HTTPAddress() string {
	return b.HTTPHost + ":" + b.HTTPPort
}

// SecretRef represents an indirect reference to a secret stored in a local vault/k8s secret.
// Plaintext secrets never appear in snapshots or logs.
type SecretRef struct {
	Name     string `json:"name"`
	Provider string `json:"provider"` // e.g. "env", "vault", "k8s"
	Key      string `json:"key"`
}

// PolicyRule defines an individual policy attached to a route.
type PolicyRule struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"` // e.g. "authn", "authz", "ratelimit", "schema_validation"
	Action     string            `json:"action"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

// UpstreamCluster defines an egress backend target.
type UpstreamCluster struct {
	ID          string        `json:"id"`
	Protocol    string        `json:"protocol"` // "http", "grpc", "postgres", "llm", "mcp"
	Endpoints   []string      `json:"endpoints"`
	Timeout     time.Duration `json:"timeout"`
	MaxConns    int           `json:"max_conns"`
	SecretRefs  []SecretRef   `json:"secret_refs,omitempty"`
}

// RouteRule defines match criteria and upstream destination.
type RouteRule struct {
	ID         string            `json:"id"`
	Path       string            `json:"path"`
	PathPrefix bool              `json:"path_prefix"`
	Method     string            `json:"method"`
	Headers    map[string]string `json:"headers,omitempty"`
	UpstreamID string            `json:"upstream_id"`
	Policies   []PolicyRule      `json:"policies,omitempty"`
	Timeout    time.Duration     `json:"timeout"`
}

// Snapshot is an immutable configuration snapshot received from the platform control plane.
type Snapshot struct {
	Version   uint64
	Signature string
	Timestamp time.Time
	Routes    []RouteRule
	Upstreams map[string]UpstreamCluster
}

// SnapshotHolder provides lock-free atomic read/write access to the current Snapshot.
type SnapshotHolder struct {
	current atomic.Pointer[Snapshot]
}

// NewSnapshotHolder creates a new holder.
func NewSnapshotHolder() *SnapshotHolder {
	return &SnapshotHolder{}
}

// Store atomically replaces the active snapshot.
func (h *SnapshotHolder) Store(s *Snapshot) error {
	if s == nil {
		return ErrNilSnapshot
	}
	h.current.Store(s)
	return nil
}

// Load returns the active snapshot without any lock acquisition.
func (h *SnapshotHolder) Load() (*Snapshot, error) {
	s := h.current.Load()
	if s == nil {
		return nil, ErrNoSnapshotAvailable
	}
	return s, nil
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
