package control

import (
	"crypto/ed25519"
	"errors"
	"time"

	controlplanev1 "github.com/phaselume/torana/api/proto/controlplane/v1"
	"github.com/phaselume/torana/internal/config"
)

var (
	// ErrInvalidSignature is returned when Ed25519 signature verification fails.
	ErrInvalidSignature = errors.New("invalid ed25519 signature on control message")
	// ErrWrongNamespace is returned when a message namespace does not match the gateway configuration.
	ErrWrongNamespace = errors.New("control message namespace mismatch")
	// ErrEnrollmentFailed is returned when node registration is rejected by the control plane.
	ErrEnrollmentFailed = errors.New("platform enrollment rejected")
	// ErrDeltaBaseMismatch is returned when an incoming delta cannot be applied onto the active version.
	ErrDeltaBaseMismatch = errors.New("delta base version does not match active config version")
	// ErrNoActiveConfig is returned when the gateway has neither a control plane config, an LKG, nor a bundle.
	ErrNoActiveConfig = errors.New("no active configuration available")
)

// Config configures the control plane client.
type Config struct {
	Namespace          string
	NodeID             string
	PlatformURL        string
	EnrollTokenFile    string
	StateDir           string
	ConfigBundle       string
	LKGPath            string
	Ed25519PublicKey   ed25519.PublicKey
	SupportedProtocols []string
	SupportedABIs      []string
	PluginInventory    []string
	HeartbeatInterval  time.Duration
	UsageFlushInterval time.Duration
}

// SnapshotConsumer is the interface for applying configuration snapshots.
type SnapshotConsumer interface {
	UpdateSnapshot(snap *config.Snapshot) error
}

// ReadinessConsumer is an optional interface to update gateway traffic readiness.
type ReadinessConsumer interface {
	SetReady(ready bool)
}

// RevocationConsumer is the interface for applying security credential revocations immediately.
type RevocationConsumer interface {
	ApplyRevocation(rev *controlplanev1.Revocation) error
}

// MetricsCollector provides gateway runtime telemetry for periodic heartbeats.
type MetricsCollector interface {
	ActiveConnections() int64
	ActiveStreams() int64
	MemoryAllocatedBytes() int64
	CPUUsagePermille() int64
}

// UsageCollector gathers aggregated, non-sensitive token usage reports for the control plane.
type UsageCollector interface {
	CollectTenantUsage() []*controlplanev1.TenantUsage
}
