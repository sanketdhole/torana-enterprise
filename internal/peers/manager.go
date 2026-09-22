package peers

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/memberlist"
	controlplanev1 "github.com/phaselume/torana/api/proto/controlplane/v1"
)

type catchUpRequest struct {
	targetVersion uint64
	serviceAddr   string
}

// Manager manages cluster membership, peer discovery, gossip broadcasts, and autonomous snapshot convergence.
type Manager struct {
	cfg            Config
	logger         *slog.Logger
	ml             *memberlist.Memberlist
	delegate       *Delegate
	snapshotServer *SnapshotServer
	discoverer     *DNSDiscoverer
	appliedVersion atomic.Uint64

	catchUpChan chan catchUpRequest
	stopChan    chan struct{}
	wg          sync.WaitGroup
	syncMu      sync.Mutex
	closeOnce   sync.Once
}

// NewManager creates and initializes a new peer Manager instance.
func NewManager(cfg Config, logger *slog.Logger) (*Manager, error) {
	if cfg.NodeID == "" {
		cfg.NodeID = fmt.Sprintf("node-%d", time.Now().UnixNano())
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "default"
	}
	if cfg.BindAddr == "" {
		cfg.BindAddr = "127.0.0.1"
	}

	m := &Manager{
		cfg:         cfg,
		logger:      logger,
		catchUpChan: make(chan catchUpRequest, 32),
		stopChan:    make(chan struct{}),
	}

	// 1. Initialize mTLS Snapshot Server
	snapServer, err := NewSnapshotServer(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to start peer snapshot server: %w", err)
	}
	m.snapshotServer = snapServer

	// 2. Initialize Delegate with snapshot server address
	m.delegate = NewDelegate(cfg, snapServer.Addr(), m.onPeerVersionDetected, logger)

	// 3. Configure Memberlist
	mcfg := memberlist.DefaultLANConfig()
	mcfg.Name = cfg.NodeID
	mcfg.BindAddr = cfg.BindAddr
	mcfg.BindPort = cfg.BindPort
	if cfg.AdvertiseAddr != "" {
		mcfg.AdvertiseAddr = cfg.AdvertiseAddr
	}
	if cfg.AdvertisePort > 0 {
		mcfg.AdvertisePort = cfg.AdvertisePort
	}
	mcfg.Delegate = m.delegate
	mcfg.Events = m.delegate

	// Fast timings for local cluster / test responsiveness
	if cfg.GossipInterval > 0 {
		mcfg.GossipInterval = cfg.GossipInterval
	} else {
		mcfg.GossipInterval = 100 * time.Millisecond
	}
	if cfg.PushPullInterval > 0 {
		mcfg.PushPullInterval = cfg.PushPullInterval
	} else {
		mcfg.PushPullInterval = 500 * time.Millisecond
	}

	// Silence memberlist internal logger if no debug logger is provided
	if logger == nil {
		mcfg.LogOutput = io.Discard
	}

	ml, err := memberlist.Create(mcfg)
	if err != nil {
		_ = snapServer.Close()
		return nil, fmt.Errorf("failed to create memberlist: %w", err)
	}
	m.ml = ml

	// 4. Start DNS Peer Discoverer for Headless Kubernetes Service
	if cfg.PeersDNS != "" {
		port := mcfg.BindPort
		if ml.LocalNode() != nil && ml.LocalNode().Port > 0 {
			port = int(ml.LocalNode().Port)
		}
		m.discoverer = NewDNSDiscoverer(cfg.PeersDNS, port, ml, cfg.DNSLookupInterval, logger)
		m.discoverer.Start()
	}

	// 5. Join Static Seed Nodes if configured
	if len(cfg.SeedNodes) > 0 {
		joined, err := ml.Join(cfg.SeedNodes)
		if err != nil && logger != nil {
			logger.Warn("initial seed join encountered errors", "attempted", len(cfg.SeedNodes), "joined", joined, "error", err)
		}
	}

	// 6. Start Catch-Up Worker
	m.wg.Add(1)
	go m.catchUpWorker()

	return m, nil
}

// Join joins one or more peer addresses.
func (m *Manager) Join(addrs []string) (int, error) {
	if m.ml == nil {
		return 0, fmt.Errorf("memberlist not initialized")
	}
	return m.ml.Join(addrs)
}

// LocalAddr returns the bound memberlist host:port address.
func (m *Manager) LocalAddr() string {
	if m.ml != nil && m.ml.LocalNode() != nil {
		node := m.ml.LocalNode()
		return fmt.Sprintf("%s:%d", node.Addr.String(), node.Port)
	}
	return ""
}

// LivePeerCount returns the active number of live cluster nodes. Implements limits.PeerCountProvider.
func (m *Manager) LivePeerCount(_ context.Context) int {
	if m.ml == nil {
		return 1
	}
	count := m.ml.NumMembers()
	if count < 1 {
		return 1
	}
	return count
}

// BroadcastConfigVersion announces a newly applied config version to the cluster.
func (m *Manager) BroadcastConfigVersion(version uint64) error {
	m.appliedVersion.Store(version)
	m.delegate.SetAppliedVersion(version)

	if m.ml != nil {
		_ = m.ml.UpdateNode(1 * time.Second)
	}

	payload := ConfigVersionPayload{
		ConfigVersion: version,
		ServiceAddr:   m.snapshotServer.Addr(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	msg := PeerMessage{
		Type:      MsgTypeConfigVersion,
		Namespace: m.cfg.Namespace,
		NodeID:    m.cfg.NodeID,
		Payload:   data,
	}
	msgData, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	m.delegate.QueueBroadcast(msgData)
	return nil
}

// BroadcastRevocation fans out a credential revocation event quickly across all cluster peers.
func (m *Manager) BroadcastRevocation(rev *controlplanev1.Revocation) error {
	if rev == nil {
		return nil
	}

	broadcastID := fmt.Sprintf("%s-%d", m.cfg.NodeID, time.Now().UnixNano())
	payload := RevocationPayload{
		BroadcastID:  broadcastID,
		Revocation:   rev,
		SourceNodeID: m.cfg.NodeID,
		Timestamp:    time.Now().UnixNano(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	msg := PeerMessage{
		Type:      MsgTypeRevocation,
		Namespace: m.cfg.Namespace,
		NodeID:    m.cfg.NodeID,
		Payload:   data,
	}
	msgData, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	m.delegate.markRevocationSeen(broadcastID)
	m.delegate.QueueBroadcast(msgData)
	return nil
}

// BroadcastUsageSync sends tenant usage statistics to peers for distributed limit tracking.
func (m *Manager) BroadcastUsageSync(reports []*controlplanev1.TenantUsage) error {
	if len(reports) == 0 {
		return nil
	}

	payload := UsageSyncPayload{
		NodeID:        m.cfg.NodeID,
		TenantReports: reports,
		Timestamp:     time.Now().UnixNano(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	msg := PeerMessage{
		Type:      MsgTypeUsageSync,
		Namespace: m.cfg.Namespace,
		NodeID:    m.cfg.NodeID,
		Payload:   data,
	}
	msgData, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	m.delegate.QueueBroadcast(msgData)
	return nil
}

func (m *Manager) onPeerVersionDetected(remoteVer uint64, serviceAddr string) {
	if remoteVer <= m.appliedVersion.Load() || serviceAddr == "" {
		return
	}

	select {
	case m.catchUpChan <- catchUpRequest{targetVersion: remoteVer, serviceAddr: serviceAddr}:
	default:
	}
}

func (m *Manager) catchUpWorker() {
	defer m.wg.Done()

	for {
		select {
		case <-m.stopChan:
			return
		case req := <-m.catchUpChan:
			if req.targetVersion <= m.appliedVersion.Load() {
				continue
			}
			_ = m.syncFromPeer(req.serviceAddr, req.targetVersion)
		}
	}
}

// syncFromPeer retrieves a signed snapshot from a peer, verifies its Ed25519 signature, and applies it.
func (m *Manager) syncFromPeer(serviceAddr string, targetVersion uint64) error {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()

	// Double check version under lock
	if targetVersion <= m.appliedVersion.Load() {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	snap, err := FetchPeerSnapshot(ctx, serviceAddr, m.cfg.TLSCertificate)
	if err != nil {
		if m.logger != nil {
			m.logger.Warn("failed to fetch snapshot from peer", "peer", serviceAddr, "target_ver", targetVersion, "error", err)
		}
		return err
	}

	// VERIFY PLATFORM SIGNATURE: Peers must NEVER introduce unsigned or forged config
	if len(m.cfg.Ed25519PublicKey) > 0 {
		if len(snap.Ed25519Signature) == 0 {
			if m.logger != nil {
				m.logger.Error("REJECTED peer snapshot: missing platform ed25519 signature",
					"version", snap.ConfigVersion, "peer", serviceAddr)
			}
			return ErrInvalidPlatformSignature
		}

		signPayloadNS := []byte(fmt.Sprintf("%s:config_version:%d", m.cfg.Namespace, snap.ConfigVersion))
		signPayloadPlain := []byte(fmt.Sprintf("config_version:%d", snap.ConfigVersion))

		valid := ed25519.Verify(m.cfg.Ed25519PublicKey, signPayloadNS, snap.Ed25519Signature) ||
			ed25519.Verify(m.cfg.Ed25519PublicKey, signPayloadPlain, snap.Ed25519Signature)

		if !valid {
			if m.logger != nil {
				m.logger.Error("REJECTED peer snapshot: invalid platform ed25519 signature verification failed",
					"version", snap.ConfigVersion, "peer", serviceAddr)
			}
			return ErrInvalidPlatformSignature
		}
	}

	// Apply verified snapshot to local node runtime
	if m.cfg.SnapshotConsumer != nil {
		if err := m.cfg.SnapshotConsumer.ApplySnapshot(snap); err != nil {
			if m.logger != nil {
				m.logger.Error("failed to apply peer snapshot to local runtime", "version", snap.ConfigVersion, "error", err)
			}
			return err
		}
	}

	// Update local version tracking and re-broadcast
	m.appliedVersion.Store(snap.ConfigVersion)
	m.delegate.SetAppliedVersion(snap.ConfigVersion)
	if m.ml != nil {
		_ = m.ml.UpdateNode(1 * time.Second)
	}

	if m.logger != nil {
		m.logger.Info("successfully converged to peer snapshot", "version", snap.ConfigVersion, "peer", serviceAddr)
	}

	return nil
}

// TriggerCatchUp explicitly requests a sync attempt against a specific peer service address.
func (m *Manager) TriggerCatchUp(serviceAddr string, targetVersion uint64) error {
	return m.syncFromPeer(serviceAddr, targetVersion)
}

// AppliedVersion returns the current applied configuration version.
func (m *Manager) AppliedVersion() uint64 {
	return m.appliedVersion.Load()
}

// Close gracefully shuts down the discovery worker, memberlist cluster, and snapshot server.
func (m *Manager) Close() error {
	m.closeOnce.Do(func() {
		close(m.stopChan)

		if m.discoverer != nil {
			m.discoverer.Stop()
		}

		if m.ml != nil {
			_ = m.ml.Leave(1 * time.Second)
			_ = m.ml.Shutdown()
		}

		if m.snapshotServer != nil {
			_ = m.snapshotServer.Close()
		}

		m.wg.Wait()
	})
	return nil
}
