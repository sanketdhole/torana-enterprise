package controlplane_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	controlplanev1 "github.com/phaselume/torana/api/proto/controlplane/v1"
	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/controlplane"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mockConsumer struct {
	mu        sync.Mutex
	snapshots []*config.Snapshot
}

func (m *mockConsumer) UpdateSnapshot(snap *config.Snapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snapshots = append(m.snapshots, snap)
	return nil
}

func (m *mockConsumer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.snapshots)
}

type testControlPlaneServer struct {
	controlplanev1.UnimplementedControlPlaneServiceServer
	pubKey  ed25519.PublicKey
	privKey ed25519.PrivateKey
	ackChan chan uint64
}

func (s *testControlPlaneServer) Enroll(_ context.Context, _ *controlplanev1.EnrollRequest) (*controlplanev1.EnrollResponse, error) {
	return &controlplanev1.EnrollResponse{
		Accepted:   true,
		ClusterId:  "test-cluster",
		EnrolledAt: timestamppb.Now(),
	}, nil
}

func (s *testControlPlaneServer) Stream(srv controlplanev1.ControlPlaneService_StreamServer) error {
	// Receive Hello
	_, err := srv.Recv()
	if err != nil {
		return err
	}

	// Send Snapshot v1
	signPayload := []byte("config_version:1")
	sig := ed25519.Sign(s.privKey, signPayload)

	snapMsg := &controlplanev1.ControlMessage{
		MessageId: "msg-1",
		Payload: &controlplanev1.ControlMessage_Snapshot{
			Snapshot: &controlplanev1.Snapshot{
				ConfigVersion:    1,
				Ed25519Signature: sig,
				CreatedAt:        timestamppb.Now(),
				Routes: []*controlplanev1.Route{
					{Id: "r1", Path: "/v1/chat", Method: "POST", UpstreamId: "u1"},
				},
				Upstreams: []*controlplanev1.Upstream{
					{Id: "u1", Protocol: "http", Endpoints: []string{"http://localhost:8080"}},
				},
			},
		},
	}

	if err := srv.Send(snapMsg); err != nil {
		return err
	}

	// Receive Ack
	ackMsg, err := srv.Recv()
	if err != nil {
		return err
	}

	if ack, ok := ackMsg.Payload.(*controlplanev1.NodeMessage_Ack); ok {
		s.ackChan <- ack.Ack.AppliedConfigVersion
	}

	return nil
}

func TestControlPlaneClient_StreamSnapshotAndAck(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}

	ackChan := make(chan uint64, 1)
	mockServer := &testControlPlaneServer{
		pubKey:  pub,
		privKey: priv,
		ackChan: ackChan,
	}

	// In-memory gRPC buffer
	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	controlplanev1.RegisterControlPlaneServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	consumer := &mockConsumer{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := &config.BootstrapConfig{
		PlatformURL: "passthrough://bufnet",
		Namespace:   "test-ns",
	}

	client := controlplane.NewClient(cfg, consumer, logger)
	client.SetPublicKey(pub)

	// Dial in-memory
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer func() { _ = conn.Close() }()

	cpClient := controlplanev1.NewControlPlaneServiceClient(conn)
	enrollResp, err := cpClient.Enroll(ctx, &controlplanev1.EnrollRequest{Namespace: "test-ns", NodeId: "test-node"})
	if err != nil || !enrollResp.Accepted {
		t.Fatalf("enrollment failed: %v", err)
	}

	stream, err := cpClient.Stream(ctx)
	if err != nil {
		t.Fatalf("stream failed: %v", err)
	}

	// Send Hello
	_ = stream.Send(&controlplanev1.NodeMessage{
		NodeId: "test-node",
		Payload: &controlplanev1.NodeMessage_Hello{
			Hello: &controlplanev1.Hello{Version: "0.1.0"},
		},
	})

	// Receive snapshot and handle
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv snapshot failed: %v", err)
	}

	client.HandleControlMessage(stream, msg)

	select {
	case ackVer := <-ackChan:
		if ackVer != 1 {
			t.Errorf("expected ACK for version 1, got %d", ackVer)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for server to receive ACK")
	}

	if consumer.count() != 1 {
		t.Errorf("expected 1 applied snapshot, got %d", consumer.count())
	}
}
