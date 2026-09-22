package peers

import (
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"time"

	controlplanev1 "github.com/phaselume/torana/api/proto/controlplane/v1"
)

var (
	// ErrInvalidPlatformSignature is returned when a peer-provided snapshot lacks a valid platform Ed25519 signature.
	ErrInvalidPlatformSignature = errors.New("invalid or missing platform ed25519 signature on peer snapshot")
	// ErrPeerFetchFailed is returned when mTLS peer HTTP snapshot retrieval fails.
	ErrPeerFetchFailed = errors.New("failed to retrieve snapshot from peer")
	// ErrNamespaceMismatch is returned when a gossip message belongs to another namespace.
	ErrNamespaceMismatch = errors.New("peer message namespace mismatch")
	// ErrNoActiveSnapshot is returned when a peer requests a snapshot but none is available.
	ErrNoActiveSnapshot = errors.New("no active configuration snapshot available to serve")
)

// Config configures the peer gossip and convergence subsystem.
type Config struct {
	NodeID             string
	Namespace          string
	BindAddr           string
	BindPort           int
	AdvertiseAddr      string
	AdvertisePort      int
	PeersDNS           string   // Kubernetes headless service DNS name, e.g. "torana-peers.torana.svc.cluster.local"
	SeedNodes          []string // Seed addresses for initial cluster join (host:port)
	TLSCertificate     *tls.Certificate
	PeerServicePort    int // Port for HTTPS/mTLS snapshot server (0 for ephemeral)
	Ed25519PublicKey   ed25519.PublicKey
	GossipInterval     time.Duration
	PushPullInterval   time.Duration
	DNSLookupInterval  time.Duration
	SnapshotConsumer   SnapshotConsumer
	SnapshotProvider   SnapshotProvider
	RevocationConsumer RevocationConsumer
	UsageHandler       UsageSyncHandler
}

// NodeMeta is gossiped across the memberlist cluster as node metadata.
type NodeMeta struct {
	NodeID          string `json:"node_id"`
	Namespace       string `json:"namespace"`
	ConfigVersion   uint64 `json:"config_version"`
	PeerServiceAddr string `json:"peer_service_addr"` // host:port for mTLS HTTP snapshot fetch
}

// MessageType indicates the type of peer broadcast message.
type MessageType uint8

const (
	MsgTypeConfigVersion MessageType = 1
	MsgTypeRevocation    MessageType = 2
	MsgTypeUsageSync     MessageType = 3
)

// PeerMessage envelopes messages transmitted through memberlist broadcasts.
type PeerMessage struct {
	Type      MessageType `json:"type"`
	Namespace string      `json:"namespace"`
	NodeID    string      `json:"node_id"`
	Payload   []byte      `json:"payload"`
}

// ConfigVersionPayload carries an announced config version.
type ConfigVersionPayload struct {
	ConfigVersion uint64 `json:"config_version"`
	ServiceAddr   string `json:"service_addr"`
}

// RevocationPayload carries credential revocation events for fast fan-out.
type RevocationPayload struct {
	BroadcastID  string                    `json:"broadcast_id"`
	Revocation   *controlplanev1.Revocation `json:"revocation"`
	SourceNodeID string                    `json:"source_node_id"`
	Timestamp    int64                     `json:"timestamp_ns"`
}

// UsageSyncPayload carries tenant token usage deltas for cross-peer limit reconciliation.
type UsageSyncPayload struct {
	NodeID        string                         `json:"node_id"`
	TenantReports []*controlplanev1.TenantUsage `json:"tenant_reports"`
	Timestamp     int64                          `json:"timestamp_ns"`
}

// SnapshotProvider supplies the active signed configuration snapshot.
type SnapshotProvider interface {
	GetActiveSnapshot() (*controlplanev1.Snapshot, uint64)
}

// SnapshotConsumer applies verified configuration snapshots to the local node.
type SnapshotConsumer interface {
	ApplySnapshot(snap *controlplanev1.Snapshot) error
}

// RevocationConsumer applies revoked credentials immediately.
type RevocationConsumer interface {
	ApplyRevocation(rev *controlplanev1.Revocation) error
}

// UsageSyncHandler receives and aggregates peer usage updates.
type UsageSyncHandler interface {
	ApplyUsageSync(nodeID string, reports []*controlplanev1.TenantUsage) error
}
