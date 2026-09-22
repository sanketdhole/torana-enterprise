package peers_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	controlplanev1 "github.com/phaselume/torana/api/proto/controlplane/v1"
	"github.com/phaselume/torana/internal/limits"
	"github.com/phaselume/torana/internal/peers"
)

// Helper: generate test mTLS certificate for enrolled peer credential
func generateTestCertificate(nodeID string) *tls.Certificate {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   nodeID,
			Organization: []string{"Torana Gateway"},
		},
		DNSNames:    []string{nodeID, "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		panic(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tlsCert
}

// Helper: mock snapshot store implementing SnapshotProvider and SnapshotConsumer
type mockSnapshotStore struct {
	mu           sync.RWMutex
	activeSnap   *controlplanev1.Snapshot
	version      uint64
	applyHistory []uint64
}

func newMockSnapshotStore(initialSnap *controlplanev1.Snapshot) *mockSnapshotStore {
	var ver uint64
	if initialSnap != nil {
		ver = initialSnap.ConfigVersion
	}
	return &mockSnapshotStore{
		activeSnap:   initialSnap,
		version:      ver,
		applyHistory: make([]uint64, 0),
	}
}

func (s *mockSnapshotStore) GetActiveSnapshot() (*controlplanev1.Snapshot, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeSnap, s.version
}

func (s *mockSnapshotStore) ApplySnapshot(snap *controlplanev1.Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeSnap = snap
	s.version = snap.ConfigVersion
	s.applyHistory = append(s.applyHistory, snap.ConfigVersion)
	return nil
}

func (s *mockSnapshotStore) CurrentVersion() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

// Helper: mock revocation tracker
type mockRevocationTracker struct {
	mu          sync.Mutex
	revocations []*controlplanev1.Revocation
	notifyChan  chan *controlplanev1.Revocation
}

func newMockRevocationTracker() *mockRevocationTracker {
	return &mockRevocationTracker{
		notifyChan: make(chan *controlplanev1.Revocation, 16),
	}
}

func (r *mockRevocationTracker) ApplyRevocation(rev *controlplanev1.Revocation) error {
	r.mu.Lock()
	r.revocations = append(r.revocations, rev)
	r.mu.Unlock()

	select {
	case r.notifyChan <- rev:
	default:
	}
	return nil
}

func (r *mockRevocationTracker) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.revocations)
}

// Helper: mock usage tracker
type mockUsageTracker struct {
	mu      sync.Mutex
	reports map[string][]*controlplanev1.TenantUsage
}

func newMockUsageTracker() *mockUsageTracker {
	return &mockUsageTracker{
		reports: make(map[string][]*controlplanev1.TenantUsage),
	}
}

func (u *mockUsageTracker) ApplyUsageSync(nodeID string, reports []*controlplanev1.TenantUsage) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.reports[nodeID] = reports
	return nil
}

// Helper: generate signed snapshot
func signSnapshot(privKey ed25519.PrivateKey, version uint64, namespace string) *controlplanev1.Snapshot {
	payload := []byte(fmt.Sprintf("config_version:%d", version))
	sig := ed25519.Sign(privKey, payload)

	return &controlplanev1.Snapshot{
		ConfigVersion:    version,
		Ed25519Signature: sig,
		Routes: []*controlplanev1.Route{
			{Id: fmt.Sprintf("route-v%d", version), Path: "/v1/test", UpstreamId: "upstream-1"},
		},
	}
}

// Test 1: 5-node in-process cluster formation
func Test5NodeInProcessCluster(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	initialSnap := signSnapshot(privKey, 1, "default")

	nodes := make([]*peers.Manager, 5)
	stores := make([]*mockSnapshotStore, 5)

	for i := 0; i < 5; i++ {
		nodeID := fmt.Sprintf("node-%d", i+1)
		stores[i] = newMockSnapshotStore(initialSnap)
		cert := generateTestCertificate(nodeID)

		cfg := peers.Config{
			NodeID:           nodeID,
			Namespace:        "default",
			BindAddr:         "127.0.0.1",
			BindPort:         0, // ephemeral
			TLSCertificate:   cert,
			PeerServicePort:  0, // ephemeral
			Ed25519PublicKey: pubKey,
			SnapshotProvider: stores[i],
			SnapshotConsumer: stores[i],
			GossipInterval:   50 * time.Millisecond,
			PushPullInterval: 100 * time.Millisecond,
		}

		mgr, err := peers.NewManager(cfg, nil)
		if err != nil {
			t.Fatalf("failed to create node %s: %v", nodeID, err)
		}
		defer mgr.Close()
		nodes[i] = mgr

		_ = mgr.BroadcastConfigVersion(1)
	}

	// Join all nodes to Node 1
	node1Addr := nodes[0].LocalAddr()
	for i := 1; i < 5; i++ {
		_, err := nodes[i].Join([]string{node1Addr})
		if err != nil {
			t.Fatalf("node %d failed to join node 1: %v", i+1, err)
		}
	}

	// Verify all 5 nodes detect a 5-node cluster
	ctx := context.Background()
	deadline := time.Now().Add(5 * time.Second)
	for i, mgr := range nodes {
		for time.Now().Before(deadline) {
			if mgr.LivePeerCount(ctx) == 5 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if count := mgr.LivePeerCount(ctx); count != 5 {
			t.Errorf("node %d peer count = %d, expected 5", i+1, count)
		}
	}
}

// Test 2: Lagging node catch-up when platform link is down
func TestLaggingNodeCatchUp_PlatformLinkDown(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	v1Snap := signSnapshot(privKey, 1, "default")
	v2Snap := signSnapshot(privKey, 2, "default")

	nodes := make([]*peers.Manager, 5)
	stores := make([]*mockSnapshotStore, 5)

	// Node 1 starts with v2
	stores[0] = newMockSnapshotStore(v2Snap)
	cert1 := generateTestCertificate("node-1")
	mgr1, err := peers.NewManager(peers.Config{
		NodeID:           "node-1",
		Namespace:        "default",
		BindAddr:         "127.0.0.1",
		BindPort:         0,
		TLSCertificate:   cert1,
		PeerServicePort:  0,
		Ed25519PublicKey: pubKey,
		SnapshotProvider: stores[0],
		SnapshotConsumer: stores[0],
		GossipInterval:   50 * time.Millisecond,
		PushPullInterval: 100 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatalf("failed to create node-1: %v", err)
	}
	defer mgr1.Close()
	nodes[0] = mgr1
	_ = mgr1.BroadcastConfigVersion(2)

	// Nodes 2..5 start lagging on v1
	for i := 1; i < 5; i++ {
		nodeID := fmt.Sprintf("node-%d", i+1)
		stores[i] = newMockSnapshotStore(v1Snap)
		cert := generateTestCertificate(nodeID)

		mgr, err := peers.NewManager(peers.Config{
			NodeID:           nodeID,
			Namespace:        "default",
			BindAddr:         "127.0.0.1",
			BindPort:         0,
			TLSCertificate:   cert,
			PeerServicePort:  0,
			Ed25519PublicKey: pubKey,
			SnapshotProvider: stores[i],
			SnapshotConsumer: stores[i],
			GossipInterval:   50 * time.Millisecond,
			PushPullInterval: 100 * time.Millisecond,
		}, nil)
		if err != nil {
			t.Fatalf("failed to create %s: %v", nodeID, err)
		}
		defer mgr.Close()
		nodes[i] = mgr
		_ = mgr.BroadcastConfigVersion(1)

		// Join to Node 1
		_, err = mgr.Join([]string{mgr1.LocalAddr()})
		if err != nil {
			t.Fatalf("node %d failed to join node 1: %v", i+1, err)
		}
	}

	// Zero platform connectivity - nodes must autonomously converge to v2
	deadline := time.Now().Add(5 * time.Second)
	for i := 1; i < 5; i++ {
		for time.Now().Before(deadline) {
			if stores[i].CurrentVersion() == 2 && nodes[i].AppliedVersion() == 2 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}

		if ver := stores[i].CurrentVersion(); ver != 2 {
			t.Errorf("node %d failed to converge to v2, still on v%d", i+1, ver)
		}
		if ver := nodes[i].AppliedVersion(); ver != 2 {
			t.Errorf("node %d manager applied version = %d, expected 2", i+1, ver)
		}
	}
}

// Test 3: Unsigned or forged snapshot rejection: peers must NEVER be able to introduce unsigned config
func TestRejectUnsignedOrForgedSnapshot(t *testing.T) {
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	_, attackerPrivKey, _ := ed25519.GenerateKey(rand.Reader)

	// Legitimate node at v1
	v1Snap := &controlplanev1.Snapshot{
		ConfigVersion: 1,
	}
	legitStore := newMockSnapshotStore(v1Snap)
	legitCert := generateTestCertificate("legit-node")
	legitMgr, err := peers.NewManager(peers.Config{
		NodeID:           "legit-node",
		Namespace:        "default",
		BindAddr:         "127.0.0.1",
		BindPort:         0,
		TLSCertificate:   legitCert,
		PeerServicePort:  0,
		Ed25519PublicKey: pubKey,
		SnapshotProvider: legitStore,
		SnapshotConsumer: legitStore,
		GossipInterval:   50 * time.Millisecond,
		PushPullInterval: 100 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatalf("failed to create legit node: %v", err)
	}
	defer legitMgr.Close()
	_ = legitMgr.BroadcastConfigVersion(1)

	// Rogue node serves forged v3 snapshot (signed by wrong key or unsigned)
	forgedPayload := []byte(fmt.Sprintf("config_version:%d", 3))
	forgedSig := ed25519.Sign(attackerPrivKey, forgedPayload) // attacker key, not platform key!

	rogueSnap := &controlplanev1.Snapshot{
		ConfigVersion:    3,
		Ed25519Signature: forgedSig,
		Routes: []*controlplanev1.Route{
			{Id: "malicious-route", Path: "/steal-data", UpstreamId: "evil-upstream"},
		},
	}
	rogueStore := newMockSnapshotStore(rogueSnap)
	rogueCert := generateTestCertificate("rogue-node")
	rogueMgr, err := peers.NewManager(peers.Config{
		NodeID:           "rogue-node",
		Namespace:        "default",
		BindAddr:         "127.0.0.1",
		BindPort:         0,
		TLSCertificate:   rogueCert,
		PeerServicePort:  0,
		Ed25519PublicKey: pubKey,
		SnapshotProvider: rogueStore,
		SnapshotConsumer: rogueStore,
		GossipInterval:   50 * time.Millisecond,
		PushPullInterval: 100 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatalf("failed to create rogue node: %v", err)
	}
	defer rogueMgr.Close()

	// Rogue node joins cluster and broadcasts v3
	_, err = rogueMgr.Join([]string{legitMgr.LocalAddr()})
	if err != nil {
		t.Fatalf("rogue node failed to join: %v", err)
	}
	_ = rogueMgr.BroadcastConfigVersion(3)

	// Wait for gossip and attempted catch-up
	time.Sleep(1 * time.Second)

	// Verify legit node rejected v3 and remained on v1
	if legitStore.CurrentVersion() != 1 {
		t.Fatalf("SECURITY VIOLATION: legit node accepted forged snapshot v%d!", legitStore.CurrentVersion())
	}
	if legitMgr.AppliedVersion() != 1 {
		t.Fatalf("SECURITY VIOLATION: legit node updated applied version to %d!", legitMgr.AppliedVersion())
	}

	// Also test explicit catch up attempt with completely unsigned snapshot
	unsignedSnap := &controlplanev1.Snapshot{
		ConfigVersion:    4,
		Ed25519Signature: nil, // completely missing signature
	}
	rogueStore.ApplySnapshot(unsignedSnap)
	_ = rogueMgr.BroadcastConfigVersion(4)

	time.Sleep(500 * time.Millisecond)

	if legitStore.CurrentVersion() != 1 {
		t.Fatalf("SECURITY VIOLATION: legit node accepted unsigned snapshot v%d!", legitStore.CurrentVersion())
	}
}

// Test 4: Fast fan-out of Revocation events
func TestFastFanOutRevocation(t *testing.T) {
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	nodes := make([]*peers.Manager, 5)
	trackers := make([]*mockRevocationTracker, 5)

	for i := 0; i < 5; i++ {
		nodeID := fmt.Sprintf("node-%d", i+1)
		trackers[i] = newMockRevocationTracker()
		cert := generateTestCertificate(nodeID)

		mgr, err := peers.NewManager(peers.Config{
			NodeID:             nodeID,
			Namespace:          "default",
			BindAddr:           "127.0.0.1",
			BindPort:           0,
			TLSCertificate:     cert,
			PeerServicePort:    0,
			Ed25519PublicKey:   pubKey,
			RevocationConsumer: trackers[i],
			GossipInterval:     30 * time.Millisecond,
			PushPullInterval:   60 * time.Millisecond,
		}, nil)
		if err != nil {
			t.Fatalf("failed to create node %s: %v", nodeID, err)
		}
		defer mgr.Close()
		nodes[i] = mgr
	}

	// Form 5-node cluster
	node1Addr := nodes[0].LocalAddr()
	for i := 1; i < 5; i++ {
		_, _ = nodes[i].Join([]string{node1Addr})
	}
	time.Sleep(300 * time.Millisecond)

	// Broadcast Revocation from Node 1
	rev := &controlplanev1.Revocation{
		RevokedTokens: []string{"jwt-compromised-token-12345"},
		RevokedKeys:   []string{"api-key-leaked-67890"},
	}

	start := time.Now()
	err := nodes[0].BroadcastRevocation(rev)
	if err != nil {
		t.Fatalf("failed to broadcast revocation: %v", err)
	}

	// Verify all 4 peer nodes receive and apply the revocation rapidly (< 1.5 seconds)
	for i := 1; i < 5; i++ {
		select {
		case r := <-trackers[i].notifyChan:
			if len(r.RevokedTokens) == 0 || r.RevokedTokens[0] != "jwt-compromised-token-12345" {
				t.Errorf("node %d received unexpected revocation: %+v", i+1, r)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("node %d timed out waiting for revocation fan-out", i+1)
		}
	}

	t.Logf("fast fan-out of revocation to all 4 peers completed in %v", time.Since(start))
}

// Test 5: Live peer count & usage sync integration with internal/limits
func TestLimitsPeerCountAndUsageSync(t *testing.T) {
	pubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	cert1 := generateTestCertificate("node-1")
	cert2 := generateTestCertificate("node-2")

	usageTracker := newMockUsageTracker()

	mgr1, err := peers.NewManager(peers.Config{
		NodeID:           "node-1",
		Namespace:        "default",
		BindAddr:         "127.0.0.1",
		BindPort:         0,
		TLSCertificate:   cert1,
		PeerServicePort:  0,
		Ed25519PublicKey: pubKey,
		UsageHandler:     usageTracker,
		GossipInterval:   50 * time.Millisecond,
		PushPullInterval: 100 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatalf("failed to create node-1: %v", err)
	}
	defer mgr1.Close()

	mgr2, err := peers.NewManager(peers.Config{
		NodeID:           "node-2",
		Namespace:        "default",
		BindAddr:         "127.0.0.1",
		BindPort:         0,
		TLSCertificate:   cert2,
		PeerServicePort:  0,
		Ed25519PublicKey: pubKey,
		GossipInterval:   50 * time.Millisecond,
		PushPullInterval: 100 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatalf("failed to create node-2: %v", err)
	}
	defer mgr2.Close()

	// Initial single node peer count = 1
	if count := mgr1.LivePeerCount(context.Background()); count != 1 {
		t.Errorf("initial peer count = %d, expected 1", count)
	}

	// Integrate with limits.LocalCounterStore: quota share = total / live_peer_count
	counterStore := limits.NewLocalCounterStore(mgr1, 1*time.Minute)
	defer counterStore.Close()

	// With 1 peer, local quota for limit 1000 is 1000
	res1, err := counterStore.Reserve(context.Background(), "tenant-a", 600, 1000, limits.WindowMinute)
	if err != nil || !res1.Allowed {
		t.Fatalf("failed reserve 1: %v, allowed: %v", err, res1.Allowed)
	}

	// Join node 2 -> live peers becomes 2
	_, _ = mgr2.Join([]string{mgr1.LocalAddr()})
	time.Sleep(300 * time.Millisecond)

	if count := mgr1.LivePeerCount(context.Background()); count != 2 {
		t.Errorf("joined peer count = %d, expected 2", count)
	}

	// With 2 peers, quota share = 1000 / 2 = 500. Now requesting 600 against remaining should fail!
	res2, err := counterStore.Reserve(context.Background(), "tenant-b", 600, 1000, limits.WindowMinute)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res2.Allowed {
		t.Errorf("expected 600 to exceed local quota share of 500 across 2 peers")
	}

	// Test Usage Sync broadcast from Node 2 to Node 1
	reports := []*controlplanev1.TenantUsage{
		{TenantId: "tenant-a", PromptTokens: 1000, CompletionTokens: 250, TotalRequests: 42},
	}
	err = mgr2.BroadcastUsageSync(reports)
	if err != nil {
		t.Fatalf("failed to broadcast usage sync: %v", err)
	}

	time.Sleep(500 * time.Millisecond)
	usageTracker.mu.Lock()
	received := usageTracker.reports["node-2"]
	usageTracker.mu.Unlock()

	if len(received) == 0 || received[0].PromptTokens != 1000 {
		t.Errorf("node 1 failed to receive usage sync from node 2: %+v", received)
	}
}

// Test 6: Network partition and heal
func TestPartitionAndHeal(t *testing.T) {
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	v1Snap := signSnapshot(privKey, 1, "default")
	v2Snap := signSnapshot(privKey, 2, "default")

	nodes := make([]*peers.Manager, 5)
	stores := make([]*mockSnapshotStore, 5)

	for i := 0; i < 5; i++ {
		nodeID := fmt.Sprintf("node-%d", i+1)
		stores[i] = newMockSnapshotStore(v1Snap)
		cert := generateTestCertificate(nodeID)

		mgr, err := peers.NewManager(peers.Config{
			NodeID:           nodeID,
			Namespace:        "default",
			BindAddr:         "127.0.0.1",
			BindPort:         0,
			TLSCertificate:   cert,
			PeerServicePort:  0,
			Ed25519PublicKey: pubKey,
			SnapshotProvider: stores[i],
			SnapshotConsumer: stores[i],
			GossipInterval:   40 * time.Millisecond,
			PushPullInterval: 80 * time.Millisecond,
		}, nil)
		if err != nil {
			t.Fatalf("failed to create node %s: %v", nodeID, err)
		}
		defer mgr.Close()
		nodes[i] = mgr
		_ = mgr.BroadcastConfigVersion(1)
	}

	// Form full 5-node cluster initially
	node1Addr := nodes[0].LocalAddr()
	for i := 1; i < 5; i++ {
		_, _ = nodes[i].Join([]string{node1Addr})
	}

	// Verify all 5 see 5 nodes
	time.Sleep(400 * time.Millisecond)
	if count := nodes[0].LivePeerCount(context.Background()); count != 5 {
		t.Fatalf("initial cluster size = %d, expected 5", count)
	}

	// Partition: Node 5 leaves cluster (simulating network partition / isolation)
	_ = nodes[4].Close()

	// While partitioned, Partition A (Node 1) upgrades to signed v2
	stores[0].ApplySnapshot(v2Snap)
	_ = nodes[0].BroadcastConfigVersion(2)

	// Nodes 2, 3, 4 catch up to v2
	deadline := time.Now().Add(3 * time.Second)
	for i := 1; i < 4; i++ {
		for time.Now().Before(deadline) {
			if stores[i].CurrentVersion() == 2 {
				break
			}
			time.Sleep(40 * time.Millisecond)
		}
		if ver := stores[i].CurrentVersion(); ver != 2 {
			t.Fatalf("node %d failed to reach v2 during partition: v%d", i+1, ver)
		}
	}

	// Heal partition: Restart Node 5 (still on v1) and rejoin the cluster
	stores[4] = newMockSnapshotStore(v1Snap)
	cert5 := generateTestCertificate("node-5-healed")
	healedNode5, err := peers.NewManager(peers.Config{
		NodeID:           "node-5-healed",
		Namespace:        "default",
		BindAddr:         "127.0.0.1",
		BindPort:         0,
		TLSCertificate:   cert5,
		PeerServicePort:  0,
		Ed25519PublicKey: pubKey,
		SnapshotProvider: stores[4],
		SnapshotConsumer: stores[4],
		GossipInterval:   40 * time.Millisecond,
		PushPullInterval: 80 * time.Millisecond,
	}, nil)
	if err != nil {
		t.Fatalf("failed to create healed node 5: %v", err)
	}
	defer healedNode5.Close()

	_, err = healedNode5.Join([]string{node1Addr})
	if err != nil {
		t.Fatalf("healed node 5 failed to rejoin: %v", err)
	}

	// Verify healed node catches up to v2 and cluster size is 5 again
	deadline = time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if stores[4].CurrentVersion() == 2 && healedNode5.LivePeerCount(context.Background()) == 5 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if ver := stores[4].CurrentVersion(); ver != 2 {
		t.Errorf("healed node 5 failed to converge to v2, still on v%d", ver)
	}
	if count := healedNode5.LivePeerCount(context.Background()); count != 5 {
		t.Errorf("healed node 5 live peer count = %d, expected 5", count)
	}
}
