package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	controlplanev1 "github.com/phaselume/torana/api/proto/controlplane/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// NodeRecord stores the live state of a connected data plane gateway instance.
type NodeRecord struct {
	NodeID               string    `json:"node_id"`
	Namespace            string    `json:"namespace"`
	Version              string    `json:"version"`
	RemoteAddr           string    `json:"remote_addr"`
	ConnectedAt          time.Time `json:"connected_at"`
	LastHeartbeat        time.Time `json:"last_heartbeat"`
	CurrentConfigVersion uint64    `json:"current_config_version"`
	LastAckStatus        string    `json:"last_ack_status"` // "ACK" or "NACK" or "PENDING"
	LastAckTime          time.Time `json:"last_ack_time"`
	ActiveConnections    int64     `json:"active_connections"`
	MemoryAllocatedBytes int64     `json:"memory_allocated_bytes"`
}

// ConfigFileSchema defines the JSON file structure.
type ConfigFileSchema struct {
	Routes    []*controlplanev1.Route    `json:"routes"`
	Upstreams []*controlplanev1.Upstream `json:"upstreams"`
	Policies  []*controlplanev1.Policy   `json:"policies"`
}

type activeStream struct {
	nodeID  string
	msgChan chan *controlplanev1.ControlMessage
}

// PlatformState holds the server's running state, keys, connected pods, and active streams.
type PlatformState struct {
	mu            sync.RWMutex
	nodes         map[string]*NodeRecord
	streams       map[string]*activeStream
	configVersion atomic.Uint64
	currentSnap   *controlplanev1.Snapshot
	lastFileMod   time.Time
	configFile    string
	pubKey        ed25519.PublicKey
	privKey       ed25519.PrivateKey
	logger        *slog.Logger
}

// NewPlatformState initializes the platform state and generates an Ed25519 keypair.
func NewPlatformState(configFile string, logger *slog.Logger) (*PlatformState, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 keypair: %w", err)
	}

	state := &PlatformState{
		nodes:      make(map[string]*NodeRecord),
		streams:    make(map[string]*activeStream),
		configFile: configFile,
		pubKey:     pub,
		privKey:    priv,
		logger:     logger,
	}

	state.logger.Info("generated dev ed25519 keypair",
		"public_key_hex", hex.EncodeToString(pub),
	)

	// Initial configuration load
	if err := state.reloadConfigFile(); err != nil {
		return nil, fmt.Errorf("failed to load initial config file: %w", err)
	}

	return state, nil
}

// PublicKeyHex returns the hex-encoded Ed25519 public key.
func (p *PlatformState) PublicKeyHex() string {
	return hex.EncodeToString(p.pubKey)
}

// PublicKeyBytes returns the raw public key bytes.
func (p *PlatformState) PublicKeyBytes() []byte {
	return p.pubKey
}

func (p *PlatformState) reloadConfigFile() error {
	data, err := os.ReadFile(p.configFile)
	if err != nil {
		return fmt.Errorf("cannot read config file %s: %w", p.configFile, err)
	}

	var schema ConfigFileSchema
	if err := json.Unmarshal(data, &schema); err != nil {
		return fmt.Errorf("cannot parse config json: %w", err)
	}

	newVersion := p.configVersion.Add(1)

	snap := &controlplanev1.Snapshot{
		ConfigVersion: newVersion,
		CreatedAt:     timestamppb.Now(),
		Routes:        schema.Routes,
		Upstreams:     schema.Upstreams,
		Policies:      schema.Policies,
	}

	// Sign with Ed25519: payload = "config_version:<ver>"
	signPayload := []byte(fmt.Sprintf("config_version:%d", newVersion))
	sig := ed25519.Sign(p.privKey, signPayload)
	snap.Ed25519Signature = sig

	p.mu.Lock()
	p.currentSnap = snap
	p.mu.Unlock()

	p.logger.Info("loaded and signed config snapshot",
		"version", newVersion,
		"routes_count", len(snap.Routes),
		"upstreams_count", len(snap.Upstreams),
		"signature_len", len(sig),
	)

	return nil
}

// StartWatcher polls the config file for changes and pushes Deltas/Snapshots on modification.
func (p *PlatformState) StartWatcher(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			info, err := os.Stat(p.configFile)
			if err != nil {
				continue
			}

			if p.lastFileMod.IsZero() {
				p.lastFileMod = info.ModTime()
				continue
			}

			if info.ModTime().After(p.lastFileMod) {
				p.lastFileMod = info.ModTime()
				p.logger.Info("detected config file modification, hot-reloading...", "file", p.configFile)

				if err := p.reloadConfigFile(); err != nil {
					p.logger.Error("failed to hot-reload config file", "error", err)
					continue
				}

				p.broadcastSnapshot()
			}
		}
	}()
}

func (p *PlatformState) broadcastSnapshot() {
	p.mu.RLock()
	snap := p.currentSnap
	streams := make([]*activeStream, 0, len(p.streams))
	for _, s := range p.streams {
		streams = append(streams, s)
	}
	p.mu.RUnlock()

	msg := &controlplanev1.ControlMessage{
		MessageId: fmt.Sprintf("msg-snap-%d", snap.ConfigVersion),
		Timestamp: timestamppb.Now(),
		Payload: &controlplanev1.ControlMessage_Snapshot{
			Snapshot: snap,
		},
	}

	for _, s := range streams {
		select {
		case s.msgChan <- msg:
			p.logger.Info("pushed snapshot update to node", "node_id", s.nodeID, "version", snap.ConfigVersion)
		default:
			p.logger.Warn("node stream message channel full, dropping update", "node_id", s.nodeID)
		}
	}
}

// RegisterNode records a node enrollment.
func (p *PlatformState) RegisterNode(nodeID, namespace, version, remoteAddr string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.nodes[nodeID] = &NodeRecord{
		NodeID:               nodeID,
		Namespace:            namespace,
		Version:              version,
		RemoteAddr:           remoteAddr,
		ConnectedAt:          time.Now(),
		LastHeartbeat:        time.Now(),
		LastAckStatus:        "PENDING",
		CurrentConfigVersion: 0,
	}
}

// RegisterStream creates a stream channel for a connected node.
func (p *PlatformState) RegisterStream(nodeID string) chan *controlplanev1.ControlMessage {
	p.mu.Lock()
	defer p.mu.Unlock()

	ch := make(chan *controlplanev1.ControlMessage, 32)
	p.streams[nodeID] = &activeStream{
		nodeID:  nodeID,
		msgChan: ch,
	}
	return ch
}

// UnregisterStream removes the node stream.
func (p *PlatformState) UnregisterStream(nodeID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.streams, nodeID)
}

// RecordAck updates the node's applied version.
func (p *PlatformState) RecordAck(nodeID string, version uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if n, ok := p.nodes[nodeID]; ok {
		n.CurrentConfigVersion = version
		n.LastAckStatus = "ACK"
		n.LastAckTime = time.Now()
	}
}

// RecordNack updates the node's rejection status.
func (p *PlatformState) RecordNack(nodeID string, version uint64, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if n, ok := p.nodes[nodeID]; ok {
		n.LastAckStatus = fmt.Sprintf("NACK (v%d: %s)", version, reason)
		n.LastAckTime = time.Now()
	}
}

// RecordHeartbeat updates load stats.
func (p *PlatformState) RecordHeartbeat(nodeID string, activeConns, memBytes int64, ver uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if n, ok := p.nodes[nodeID]; ok {
		n.LastHeartbeat = time.Now()
		n.ActiveConnections = activeConns
		n.MemoryAllocatedBytes = memBytes
		if ver > 0 {
			n.CurrentConfigVersion = ver
		}
	}
}

// GetNodes returns a snapshot slice of all registered nodes.
func (p *PlatformState) GetNodes() []*NodeRecord {
	p.mu.RLock()
	defer p.mu.RUnlock()

	nodes := make([]*NodeRecord, 0, len(p.nodes))
	for _, n := range p.nodes {
		nodes = append(nodes, n)
	}
	return nodes
}

// CurrentSnapshot returns the active snapshot.
func (p *PlatformState) CurrentSnapshot() *controlplanev1.Snapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.currentSnap
}
