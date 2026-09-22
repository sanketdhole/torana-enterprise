package controlplane_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	controlplanev1 "github.com/phaselume/torana/api/proto/controlplane/v1"
	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/control"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mockTransport struct {
	mu       sync.Mutex
	sentMsgs []*controlplanev1.NodeMessage
	recvChan chan *controlplanev1.ControlMessage
	closed   bool
}

func newMockTransport() *mockTransport {
	return &mockTransport{
		recvChan: make(chan *controlplanev1.ControlMessage, 32),
	}
}

func (m *mockTransport) Send(msg *controlplanev1.NodeMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentMsgs = append(m.sentMsgs, msg)
	return nil
}

func (m *mockTransport) Recv() (*controlplanev1.ControlMessage, error) {
	msg, ok := <-m.recvChan
	if !ok {
		return nil, io.EOF
	}
	return msg, nil
}

func (m *mockTransport) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.recvChan)
	}
	return nil
}

func (m *mockTransport) SentMessages() []*controlplanev1.NodeMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := make([]*controlplanev1.NodeMessage, len(m.sentMsgs))
	copy(copied, m.sentMsgs)
	return copied
}

func (m *mockTransport) Push(msg *controlplanev1.ControlMessage) {
	m.recvChan <- msg
}

type testConsumer struct {
	mu        sync.Mutex
	snapshots []*config.Snapshot
	ready     bool
}

func (c *testConsumer) UpdateSnapshot(snap *config.Snapshot) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if snap == nil || snap.Version == 0 {
		return errors.New("invalid snapshot")
	}
	for _, r := range snap.Routes {
		if r.Path == "" {
			return errors.New("empty route path")
		}
	}
	c.snapshots = append(c.snapshots, snap)
	return nil
}

func (c *testConsumer) SetReady(ready bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ready = ready
}

func (c *testConsumer) IsReady() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ready
}

func (c *testConsumer) LastSnapshot() *config.Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.snapshots) == 0 {
		return nil
	}
	return c.snapshots[len(c.snapshots)-1]
}

type testRevocationConsumer struct {
	mu          sync.Mutex
	revocations []*controlplanev1.Revocation
}

func (r *testRevocationConsumer) ApplyRevocation(rev *controlplanev1.Revocation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revocations = append(r.revocations, rev)
	return nil
}

func (r *testRevocationConsumer) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.revocations)
}

func TestControl_EnrollmentAndCredentialPersistence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "torana_state_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	tokenFile := filepath.Join(tempDir, "enroll_token.txt")
	_ = os.WriteFile(tokenFile, []byte("test-one-time-token-secret"), 0600)

	cfg := control.Config{
		Namespace:       "tenant-alpha",
		NodeID:          "gateway-node-1",
		StateDir:        tempDir,
		EnrollTokenFile: tokenFile,
	}

	mgr := control.NewEnrollmentManager(cfg, nil, nil)
	defer mgr.Close()

	// 1. Execute initial enrollment
	ctx := context.Background()
	if err := mgr.EnsureEnrolled(ctx); err != nil {
		t.Fatalf("enrollment failed: %v", err)
	}

	// 2. Verify credentials in memory
	cred := mgr.Credential()
	if cred == nil || cred.ClusterID == "" {
		t.Fatalf("expected non-nil credential with cluster ID")
	}
	if mgr.TLSCertificate() == nil {
		t.Fatalf("expected active TLS certificate in enrollment manager")
	}

	// 3. Verify 0600 file permissions strictly
	credFilePath := filepath.Join(tempDir, "credential.json")
	fileInfo, err := os.Stat(credFilePath)
	if err != nil {
		t.Fatalf("credential.json was not created: %v", err)
	}
	if fileInfo.Mode().Perm() != 0600 {
		t.Fatalf("expected file permission 0600, got %o", fileInfo.Mode().Perm())
	}

	// 4. Verify reload from disk on subsequent startup
	mgr2 := control.NewEnrollmentManager(cfg, nil, nil)
	defer mgr2.Close()

	if err := mgr2.EnsureEnrolled(ctx); err != nil {
		t.Fatalf("failed to reload persisted credential: %v", err)
	}
	if mgr2.Credential().ClusterID != cred.ClusterID {
		t.Fatalf("expected reloaded cluster ID %q, got %q", cred.ClusterID, mgr2.Credential().ClusterID)
	}
}

func TestControl_StreamSnapshotAndAck(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	transport := newMockTransport()
	consumer := &testConsumer{}

	cfg := control.Config{
		Namespace:        "tenant-prod",
		NodeID:           "node-test-1",
		Ed25519PublicKey: pub,
	}

	client := control.NewClient(cfg, consumer, nil, nil)
	client.SetCustomTransport(transport)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = client.Start(ctx)
	defer client.Stop()

	// Allow client to send initial Hello
	time.Sleep(20 * time.Millisecond)
	msgs := transport.SentMessages()
	if len(msgs) == 0 {
		t.Fatalf("expected client to send Hello message")
	}
	hello := msgs[0].GetHello()
	if hello == nil {
		t.Fatalf("expected first message to be Hello")
	}

	// 1. Control plane pushes valid Snapshot v1
	signPayload := []byte("tenant-prod:config_version:1")
	sig := ed25519.Sign(priv, signPayload)

	transport.Push(&controlplanev1.ControlMessage{
		MessageId: "tenant-prod:msg-snap-1",
		Payload: &controlplanev1.ControlMessage_Snapshot{
			Snapshot: &controlplanev1.Snapshot{
				ConfigVersion:    1,
				Ed25519Signature: sig,
				CreatedAt:        timestamppb.Now(),
				Routes: []*controlplanev1.Route{
					{Id: "r-chat", Path: "/v1/chat", Method: "POST", UpstreamId: "u-openai"},
				},
				Upstreams: []*controlplanev1.Upstream{
					{Id: "u-openai", Protocol: "http", Endpoints: []string{"http://upstream.local"}},
				},
			},
		},
	})

	// Wait for processing
	time.Sleep(30 * time.Millisecond)

	// 2. Verify snapshot applied and consumer ready
	if client.LastAppliedVersion() != 1 {
		t.Fatalf("expected last applied version 1, got %d", client.LastAppliedVersion())
	}
	if !consumer.IsReady() {
		t.Fatalf("expected consumer readiness to be true")
	}

	// 3. Verify ACK sent
	sent := transport.SentMessages()
	var foundAck bool
	for _, m := range sent {
		if ack := m.GetAck(); ack != nil && ack.AppliedConfigVersion == 1 {
			foundAck = true
			break
		}
	}
	if !foundAck {
		t.Fatalf("expected client to send ACK for version 1")
	}
}

func TestControl_BadSignature_TriggersNACK(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	transport := newMockTransport()
	consumer := &testConsumer{}

	cfg := control.Config{
		Namespace:        "tenant-prod",
		NodeID:           "node-test-1",
		Ed25519PublicKey: pub,
	}

	client := control.NewClient(cfg, consumer, nil, nil)
	client.SetCustomTransport(transport)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = client.Start(ctx)
	defer client.Stop()

	time.Sleep(10 * time.Millisecond)

	// Send Snapshot with corrupt signature
	badSig := make([]byte, 64)
	transport.Push(&controlplanev1.ControlMessage{
		MessageId: "tenant-prod:msg-bad-sig",
		Payload: &controlplanev1.ControlMessage_Snapshot{
			Snapshot: &controlplanev1.Snapshot{
				ConfigVersion:    2,
				Ed25519Signature: badSig,
				Routes: []*controlplanev1.Route{
					{Id: "r1", Path: "/api", Method: "GET", UpstreamId: "u1"},
				},
				Upstreams: []*controlplanev1.Upstream{
					{Id: "u1", Protocol: "http", Endpoints: []string{"http://localhost"}},
				},
			},
		},
	})

	time.Sleep(30 * time.Millisecond)

	// Verify snapshot was NOT applied
	if client.LastAppliedVersion() != 0 {
		t.Fatalf("snapshot with bad signature must not be applied")
	}

	// Verify NACK was sent with INVALID_SIGNATURE
	sent := transport.SentMessages()
	var foundNack bool
	for _, m := range sent {
		if nack := m.GetNack(); nack != nil {
			if nack.RejectedConfigVersion == 2 && nack.ErrorCode == "INVALID_SIGNATURE" {
				foundNack = true
				break
			}
		}
	}
	if !foundNack {
		t.Fatalf("expected client to send NACK with INVALID_SIGNATURE")
	}
}

func TestControl_WrongNamespace_TriggersNACK(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	transport := newMockTransport()
	consumer := &testConsumer{}

	cfg := control.Config{
		Namespace:        "tenant-alpha", // Gateway configured for tenant-alpha
		NodeID:           "node-alpha-1",
		Ed25519PublicKey: pub,
	}

	client := control.NewClient(cfg, consumer, nil, nil)
	client.SetCustomTransport(transport)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = client.Start(ctx)
	defer client.Stop()

	time.Sleep(10 * time.Millisecond)

	// Send Snapshot tagged for tenant-beta
	signPayload := []byte("tenant-beta:config_version:5")
	sig := ed25519.Sign(priv, signPayload)

	transport.Push(&controlplanev1.ControlMessage{
		MessageId: "tenant-beta:msg-5", // Message belonging to different namespace
		Payload: &controlplanev1.ControlMessage_Snapshot{
			Snapshot: &controlplanev1.Snapshot{
				ConfigVersion:    5,
				Ed25519Signature: sig,
			},
		},
	})

	time.Sleep(30 * time.Millisecond)

	// Verify rejected
	if client.LastAppliedVersion() != 0 {
		t.Fatalf("cross-namespace snapshot must not be applied")
	}

	sent := transport.SentMessages()
	var foundNack bool
	for _, m := range sent {
		if nack := m.GetNack(); nack != nil {
			if nack.RejectedConfigVersion == 5 && nack.ErrorCode == "WRONG_NAMESPACE" {
				foundNack = true
				break
			}
		}
	}
	if !foundNack {
		t.Fatalf("expected client to send NACK with WRONG_NAMESPACE")
	}
}

func TestControl_NACKPath_CompileError(t *testing.T) {
	transport := newMockTransport()
	consumer := &testConsumer{}

	cfg := control.Config{
		Namespace: "tenant-prod",
		NodeID:    "node-prod-1",
	}

	client := control.NewClient(cfg, consumer, nil, nil)
	client.SetCustomTransport(transport)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = client.Start(ctx)
	defer client.Stop()

	time.Sleep(10 * time.Millisecond)

	// Send Snapshot with empty path (causes testConsumer.UpdateSnapshot to fail)
	transport.Push(&controlplanev1.ControlMessage{
		MessageId: "tenant-prod:msg-invalid-compile",
		Payload: &controlplanev1.ControlMessage_Snapshot{
			Snapshot: &controlplanev1.Snapshot{
				ConfigVersion: 3,
				Routes: []*controlplanev1.Route{
					{Id: "invalid-route", Path: "", Method: "GET"},
				},
			},
		},
	})

	time.Sleep(30 * time.Millisecond)

	// Verify NACK with COMPILE_FAILED
	sent := transport.SentMessages()
	var foundNack bool
	for _, m := range sent {
		if nack := m.GetNack(); nack != nil {
			if nack.RejectedConfigVersion == 3 && nack.ErrorCode == "COMPILE_FAILED" {
				foundNack = true
				break
			}
		}
	}
	if !foundNack {
		t.Fatalf("expected client to send NACK with COMPILE_FAILED")
	}
}

func TestControl_PriorityRevocation(t *testing.T) {
	transport := newMockTransport()
	consumer := &testConsumer{}
	revConsumer := &testRevocationConsumer{}

	cfg := control.Config{
		Namespace: "tenant-prod",
		NodeID:    "node-prod-1",
	}

	client := control.NewClient(cfg, consumer, revConsumer, nil)
	client.SetCustomTransport(transport)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = client.Start(ctx)
	defer client.Stop()

	// Push a revocation message
	transport.Push(&controlplanev1.ControlMessage{
		MessageId: "tenant-prod:rev-1",
		Payload: &controlplanev1.ControlMessage_Revocation{
			Revocation: &controlplanev1.Revocation{
				RevokedTokens: []string{"revoked-jwt-token-abc"},
				RevokedKeys:   []string{"key-id-123"},
			},
		},
	})

	time.Sleep(30 * time.Millisecond)

	if revConsumer.Count() != 1 {
		t.Fatalf("expected revocation to be applied immediately")
	}
}

func TestControl_DeltaResumption_AndReconnectMidDelta(t *testing.T) {
	transport := newMockTransport()
	consumer := &testConsumer{}

	cfg := control.Config{
		Namespace: "tenant-prod",
		NodeID:    "node-prod-1",
	}

	client := control.NewClient(cfg, consumer, nil, nil)
	client.SetCustomTransport(transport)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = client.Start(ctx)
	defer client.Stop()

	// 1. Send initial Snapshot v1
	transport.Push(&controlplanev1.ControlMessage{
		MessageId: "tenant-prod:msg-1",
		Payload: &controlplanev1.ControlMessage_Snapshot{
			Snapshot: &controlplanev1.Snapshot{
				ConfigVersion: 1,
				Routes: []*controlplanev1.Route{
					{Id: "r1", Path: "/v1/a", Method: "GET", UpstreamId: "u1"},
				},
				Upstreams: []*controlplanev1.Upstream{
					{Id: "u1", Protocol: "http", Endpoints: []string{"http://localhost:8080"}},
				},
			},
		},
	})
	time.Sleep(30 * time.Millisecond)

	if client.LastAppliedVersion() != 1 {
		t.Fatalf("expected version 1, got %d", client.LastAppliedVersion())
	}

	// 2. Send valid Delta (Base: 1 -> Target: 2)
	transport.Push(&controlplanev1.ControlMessage{
		MessageId: "tenant-prod:msg-delta-2",
		Payload: &controlplanev1.ControlMessage_Delta{
			Delta: &controlplanev1.Delta{
				BaseConfigVersion:   1,
				TargetConfigVersion: 2,
				AddedOrUpdatedRoutes: []*controlplanev1.Route{
					{Id: "r2", Path: "/v1/b", Method: "POST", UpstreamId: "u1"},
				},
			},
		},
	})
	time.Sleep(30 * time.Millisecond)

	if client.LastAppliedVersion() != 2 {
		t.Fatalf("expected version 2 after delta, got %d", client.LastAppliedVersion())
	}
	lastSnap := consumer.LastSnapshot()
	if len(lastSnap.Routes) != 2 {
		t.Fatalf("expected 2 routes after delta merge, got %d", len(lastSnap.Routes))
	}

	// 3. Send Delta with base mismatch (reconnection mid-delta simulation: Base 5 -> Target 6 while client is on 2)
	transport.Push(&controlplanev1.ControlMessage{
		MessageId: "tenant-prod:msg-delta-mismatch",
		Payload: &controlplanev1.ControlMessage_Delta{
			Delta: &controlplanev1.Delta{
				BaseConfigVersion:   5, // Mismatch!
				TargetConfigVersion: 6,
			},
		},
	})
	time.Sleep(30 * time.Millisecond)

	// Verify rejected with DELTA_BASE_MISMATCH
	sent := transport.SentMessages()
	var foundMismatchNack bool
	for _, m := range sent {
		if nack := m.GetNack(); nack != nil {
			if nack.RejectedConfigVersion == 6 && nack.ErrorCode == "DELTA_BASE_MISMATCH" {
				foundMismatchNack = true
				break
			}
		}
	}
	if !foundMismatchNack {
		t.Fatalf("expected DELTA_BASE_MISMATCH NACK on out-of-order delta")
	}
}

func TestControl_FailStatic_PlatformOutage(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "torana_lkg_test_*")
	defer os.RemoveAll(tempDir)

	lkgPath := filepath.Join(tempDir, "lkg.json")

	// 1. Create a Last-Known-Good snapshot on disk
	lkgSnap := &config.Snapshot{
		Version: 42,
		Routes: []config.RouteRule{
			{ID: "r-lkg", Path: "/fallback", Method: "GET", UpstreamID: "u-lkg"},
		},
		Upstreams: map[string]config.UpstreamCluster{
			"u-lkg": {ID: "u-lkg", Protocol: "http", Endpoints: []string{"http://localhost"}},
		},
	}
	_ = config.SaveLKG(lkgPath, lkgSnap)

	// 2. Start client pointing to unreachable platform URL with LKG configured
	consumer := &testConsumer{}
	cfg := control.Config{
		Namespace:   "tenant-prod",
		PlatformURL: "passthrough://unreachable:9999",
		LKGPath:     lkgPath,
	}

	client := control.NewClient(cfg, consumer, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = client.Start(ctx)
	defer client.Stop()

	// Verify client loaded LKG and is serving in fail-static mode
	if client.LastAppliedVersion() != 42 {
		t.Fatalf("expected client to serve on LKG version 42, got %d", client.LastAppliedVersion())
	}
	if !consumer.IsReady() {
		t.Fatalf("expected readiness to remain true while serving on valid LKG")
	}
}

func TestControl_OfflineConfigBundle(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "torana_bundle_test_*")
	defer os.RemoveAll(tempDir)

	bundlePath := filepath.Join(tempDir, "bundle.json")
	snap := &config.Snapshot{
		Version: 100,
		Routes: []config.RouteRule{
			{ID: "r-bundle", Path: "/offline", Method: "POST", UpstreamID: "u1"},
		},
		Upstreams: map[string]config.UpstreamCluster{
			"u1": {ID: "u1", Protocol: "http", Endpoints: []string{"http://localhost"}},
		},
	}
	data, _ := json.Marshal(snap)
	_ = os.WriteFile(bundlePath, data, 0644)

	consumer := &testConsumer{}
	cfg := control.Config{
		Namespace:    "tenant-offline",
		ConfigBundle: bundlePath,
		// No PlatformURL: completely offline
	}

	client := control.NewClient(cfg, consumer, nil, nil)
	_ = client.Start(context.Background())
	defer client.Stop()

	if client.LastAppliedVersion() != 100 {
		t.Fatalf("expected version 100 from offline bundle, got %d", client.LastAppliedVersion())
	}
	if !consumer.IsReady() {
		t.Fatalf("expected readiness to be true in offline mode")
	}
}

type testMetricsCollector struct{}

func (m *testMetricsCollector) ActiveConnections() int64    { return 15 }
func (m *testMetricsCollector) ActiveStreams() int64        { return 4 }
func (m *testMetricsCollector) MemoryAllocatedBytes() int64 { return 1024 * 1024 }
func (m *testMetricsCollector) CPUUsagePermille() int64     { return 120 }

type testUsageCollector struct{}

func (u *testUsageCollector) CollectTenantUsage() []*controlplanev1.TenantUsage {
	return []*controlplanev1.TenantUsage{
		{
			TenantId:     "tenant-acme",
			RouteId:      "r-chat",
			Model:        "gpt-4o",
			PromptTokens: 250,
			TotalRequests: 10,
		},
	}
}

func TestControl_HeartbeatAndUsageReport(t *testing.T) {
	transport := newMockTransport()
	consumer := &testConsumer{}

	cfg := control.Config{
		Namespace:          "tenant-prod",
		NodeID:             "node-prod-1",
		HeartbeatInterval:  20 * time.Millisecond,
		UsageFlushInterval: 20 * time.Millisecond,
	}

	client := control.NewClient(cfg, consumer, nil, nil)
	client.SetCustomTransport(transport)
	client.SetMetricsCollector(&testMetricsCollector{})
	client.SetUsageCollector(&testUsageCollector{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = client.Start(ctx)
	defer client.Stop()

	time.Sleep(60 * time.Millisecond)

	sent := transport.SentMessages()
	var foundHeartbeat, foundUsage bool
	for _, m := range sent {
		if hb := m.GetHeartbeat(); hb != nil {
			if hb.ActiveConnections == 15 && hb.MemoryAllocatedBytes == 1024*1024 {
				foundHeartbeat = true
			}
		}
		if usage := m.GetUsageReport(); usage != nil {
			if len(usage.TenantReports) > 0 && usage.TenantReports[0].TenantId == "tenant-acme" {
				foundUsage = true
			}
		}
	}

	if !foundHeartbeat {
		t.Fatalf("expected client to emit heartbeat with collected metrics")
	}
	if !foundUsage {
		t.Fatalf("expected client to emit batched usage report")
	}
}
