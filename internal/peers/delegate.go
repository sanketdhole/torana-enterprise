package peers

import (
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/memberlist"
)

type peerBroadcast struct {
	msg []byte
}

func (b *peerBroadcast) Invalidates(other memberlist.Broadcast) bool {
	return false
}

func (b *peerBroadcast) Message() []byte {
	return b.msg
}

func (b *peerBroadcast) Finished() {}

// Delegate coordinates memberlist gossip events, message broadcasts, and cluster convergence.
type Delegate struct {
	cfg             Config
	logger          *slog.Logger
	queue           *memberlist.TransmitLimitedQueue
	versionCallback func(uint64, string) // triggers catch-up: (version, serviceAddr)
	appliedVersion  atomic.Uint64
	serviceAddr     string

	mu              sync.RWMutex
	seenRevocations map[string]time.Time
	liveNodes       map[string]*NodeMeta
}

// NewDelegate creates a new memberlist Delegate.
func NewDelegate(cfg Config, serviceAddr string, versionCb func(uint64, string), logger *slog.Logger) *Delegate {
	d := &Delegate{
		cfg:             cfg,
		logger:          logger,
		serviceAddr:     serviceAddr,
		versionCallback: versionCb,
		seenRevocations: make(map[string]time.Time),
		liveNodes:       make(map[string]*NodeMeta),
	}

	d.queue = &memberlist.TransmitLimitedQueue{
		NumNodes: func() int {
			d.mu.RLock()
			defer d.mu.RUnlock()
			count := len(d.liveNodes)
			if count < 1 {
				return 1
			}
			return count
		},
		RetransmitMult: 4, // Ensures fast fan-out across cluster
	}

	return d
}

// SetAppliedVersion updates the local node's gossiped config version.
func (d *Delegate) SetAppliedVersion(v uint64) {
	d.appliedVersion.Store(v)
}

// NodeMeta returns the local node's metadata for memberlist announcements.
func (d *Delegate) NodeMeta(limit int) []byte {
	meta := NodeMeta{
		NodeID:          d.cfg.NodeID,
		Namespace:       d.cfg.Namespace,
		ConfigVersion:   d.appliedVersion.Load(),
		PeerServiceAddr: d.serviceAddr,
	}

	data, err := json.Marshal(meta)
	if err != nil || len(data) > limit {
		return nil
	}
	return data
}

// NotifyMsg processes an incoming broadcast message received from a cluster peer.
func (d *Delegate) NotifyMsg(buf []byte) {
	if len(buf) == 0 {
		return
	}

	var msg PeerMessage
	if err := json.Unmarshal(buf, &msg); err != nil {
		return
	}

	// Verify namespace isolation
	if msg.Namespace != "" && msg.Namespace != d.cfg.Namespace {
		return
	}

	switch msg.Type {
	case MsgTypeConfigVersion:
		var p ConfigVersionPayload
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return
		}
		if p.ConfigVersion > d.appliedVersion.Load() && d.versionCallback != nil {
			d.versionCallback(p.ConfigVersion, p.ServiceAddr)
		}

	case MsgTypeRevocation:
		var p RevocationPayload
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return
		}

		if d.isRevocationSeen(p.BroadcastID) {
			return
		}
		d.markRevocationSeen(p.BroadcastID)

		// Fast fan-out: apply immediately
		if d.cfg.RevocationConsumer != nil && p.Revocation != nil {
			if err := d.cfg.RevocationConsumer.ApplyRevocation(p.Revocation); err != nil {
				if d.logger != nil {
					d.logger.Error("failed to apply revocation from peer", "broadcast_id", p.BroadcastID, "error", err)
				}
			} else if d.logger != nil {
				d.logger.Info("applied peer revocation event", "broadcast_id", p.BroadcastID, "from", p.SourceNodeID)
			}
		}

		// Retransmit to other peers if not originator
		if p.SourceNodeID != d.cfg.NodeID {
			d.QueueBroadcast(buf)
		}

	case MsgTypeUsageSync:
		var p UsageSyncPayload
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return
		}
		if d.cfg.UsageHandler != nil {
			_ = d.cfg.UsageHandler.ApplyUsageSync(p.NodeID, p.TenantReports)
		}
	}
}

// GetBroadcasts retrieves queued broadcast messages to attach to gossip packets.
func (d *Delegate) GetBroadcasts(overhead, limit int) [][]byte {
	return d.queue.GetBroadcasts(overhead, limit)
}

// LocalState returns the push-pull state representing the node's current state.
func (d *Delegate) LocalState(join bool) []byte {
	meta := NodeMeta{
		NodeID:          d.cfg.NodeID,
		Namespace:       d.cfg.Namespace,
		ConfigVersion:   d.appliedVersion.Load(),
		PeerServiceAddr: d.serviceAddr,
	}
	data, _ := json.Marshal(meta)
	return data
}

// MergeRemoteState merges remote state received during periodic push-pull anti-entropy exchanges.
func (d *Delegate) MergeRemoteState(buf []byte, join bool) {
	if len(buf) == 0 {
		return
	}
	var remote NodeMeta
	if err := json.Unmarshal(buf, &remote); err != nil {
		return
	}
	if remote.Namespace != d.cfg.Namespace {
		return
	}

	if remote.ConfigVersion > d.appliedVersion.Load() && d.versionCallback != nil {
		d.versionCallback(remote.ConfigVersion, remote.PeerServiceAddr)
	}
}

// QueueBroadcast enqueues a raw message for distribution to the cluster.
func (d *Delegate) QueueBroadcast(msg []byte) {
	d.queue.QueueBroadcast(&peerBroadcast{msg: msg})
}

func (d *Delegate) isRevocationSeen(id string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.seenRevocations[id]
	return ok
}

func (d *Delegate) markRevocationSeen(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seenRevocations[id] = time.Now()

	// Prune old entries if map grows large (> 5000)
	if len(d.seenRevocations) > 5000 {
		cutoff := time.Now().Add(-10 * time.Minute)
		for k, t := range d.seenRevocations {
			if t.Before(cutoff) {
				delete(d.seenRevocations, k)
			}
		}
	}
}

// --- EventDelegate Implementation ---

// NotifyJoin is called when a new node joins the memberlist cluster.
func (d *Delegate) NotifyJoin(node *memberlist.Node) {
	meta := d.parseNodeMeta(node)
	if meta == nil {
		return
	}

	d.mu.Lock()
	d.liveNodes[node.Name] = meta
	d.mu.Unlock()

	if meta.ConfigVersion > d.appliedVersion.Load() && d.versionCallback != nil {
		d.versionCallback(meta.ConfigVersion, meta.PeerServiceAddr)
	}
}

// NotifyLeave is called when a node leaves or is declared dead.
func (d *Delegate) NotifyLeave(node *memberlist.Node) {
	d.mu.Lock()
	delete(d.liveNodes, node.Name)
	d.mu.Unlock()
}

// NotifyUpdate is called when a node updates its metadata.
func (d *Delegate) NotifyUpdate(node *memberlist.Node) {
	meta := d.parseNodeMeta(node)
	if meta == nil {
		return
	}

	d.mu.Lock()
	d.liveNodes[node.Name] = meta
	d.mu.Unlock()

	if meta.ConfigVersion > d.appliedVersion.Load() && d.versionCallback != nil {
		d.versionCallback(meta.ConfigVersion, meta.PeerServiceAddr)
	}
}

func (d *Delegate) parseNodeMeta(node *memberlist.Node) *NodeMeta {
	if len(node.Meta) == 0 {
		return nil
	}
	var meta NodeMeta
	if err := json.Unmarshal(node.Meta, &meta); err != nil {
		return nil
	}
	if meta.Namespace != d.cfg.Namespace {
		return nil
	}
	return &meta
}

// LiveNodeCount returns the number of active, verified nodes in the cluster.
func (d *Delegate) LiveNodeCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.liveNodes)
}
