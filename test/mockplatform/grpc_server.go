package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	controlplanev1 "github.com/phaselume/torana/api/proto/controlplane/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ControlPlaneServer implements the controlplane.v1 gRPC service.
type ControlPlaneServer struct {
	controlplanev1.UnimplementedControlPlaneServiceServer
	state  *PlatformState
	logger *slog.Logger
}

// NewControlPlaneServer creates a new gRPC service instance.
func NewControlPlaneServer(state *PlatformState, logger *slog.Logger) *ControlPlaneServer {
	return &ControlPlaneServer{
		state:  state,
		logger: logger,
	}
}

// Enroll handles node registration.
func (s *ControlPlaneServer) Enroll(_ context.Context, req *controlplanev1.EnrollRequest) (*controlplanev1.EnrollResponse, error) {
	s.logger.Info("received enrollment request",
		"node_id", req.NodeId,
		"namespace", req.Namespace,
		"version", req.Version,
	)

	s.state.RegisterNode(req.NodeId, req.Namespace, req.Version, "remote")

	return &controlplanev1.EnrollResponse{
		Accepted:   true,
		ClusterId:  "dev-cluster-local",
		EnrolledAt: timestamppb.Now(),
	}, nil
}

// Stream manages bidirectional communication with the gateway data plane.
func (s *ControlPlaneServer) Stream(srv controlplanev1.ControlPlaneService_StreamServer) error {
	ctx := srv.Context()

	// 1. Read first message (typically Hello)
	firstMsg, err := srv.Recv()
	if err != nil {
		return fmt.Errorf("failed to read initial stream message: %w", err)
	}

	nodeID := firstMsg.NodeId
	if nodeID == "" {
		nodeID = "unknown-node"
	}

	s.logger.Info("node connected to control stream", "node_id", nodeID, "namespace", firstMsg.Namespace)
	s.state.RegisterNode(nodeID, firstMsg.Namespace, "0.1.0", "stream")

	msgChan := s.state.RegisterStream(nodeID)
	defer s.state.UnregisterStream(nodeID)

	// 2. Immediately send current snapshot upon stream connection
	currentSnap := s.state.CurrentSnapshot()
	if currentSnap != nil {
		initialMsg := &controlplanev1.ControlMessage{
			MessageId: fmt.Sprintf("init-snap-%d", currentSnap.ConfigVersion),
			Timestamp: timestamppb.Now(),
			Payload: &controlplanev1.ControlMessage_Snapshot{
				Snapshot: currentSnap,
			},
		}
		if err := srv.Send(initialMsg); err != nil {
			return fmt.Errorf("failed to send initial snapshot: %w", err)
		}
		s.logger.Info("sent initial snapshot to node", "node_id", nodeID, "version", currentSnap.ConfigVersion)
	}

	// 3. Sender loop
	errChan := make(chan error, 2)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-msgChan:
				if !ok {
					return
				}
				if err := srv.Send(msg); err != nil {
					errChan <- err
					return
				}
			}
		}
	}()

	// 4. Receiver loop
	go func() {
		for {
			msg, err := srv.Recv()
			if err != nil {
				if err != io.EOF {
					errChan <- err
				}
				return
			}

			s.handleNodeMessage(msg)
		}
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("node stream context closed", "node_id", nodeID)
		return ctx.Err()
	case err := <-errChan:
		s.logger.Warn("node stream terminated with error", "node_id", nodeID, "error", err)
		return err
	}
}

func (s *ControlPlaneServer) handleNodeMessage(msg *controlplanev1.NodeMessage) {
	nodeID := msg.NodeId

	switch p := msg.Payload.(type) {
	case *controlplanev1.NodeMessage_Ack:
		s.logger.Info("received ACK from node", "node_id", nodeID, "applied_version", p.Ack.AppliedConfigVersion)
		s.state.RecordAck(nodeID, p.Ack.AppliedConfigVersion)

	case *controlplanev1.NodeMessage_Nack:
		s.logger.Error("received NACK from node", "node_id", nodeID, "rejected_version", p.Nack.RejectedConfigVersion, "reason", p.Nack.ErrorMessage)
		s.state.RecordNack(nodeID, p.Nack.RejectedConfigVersion, p.Nack.ErrorMessage)

	case *controlplanev1.NodeMessage_Heartbeat:
		s.logger.Debug("received heartbeat", "node_id", nodeID, "version", p.Heartbeat.CurrentConfigVersion)
		s.state.RecordHeartbeat(nodeID, p.Heartbeat.ActiveConnections, p.Heartbeat.MemoryAllocatedBytes, p.Heartbeat.CurrentConfigVersion)

	case *controlplanev1.NodeMessage_UsageReport:
		s.logger.Info("received usage report", "node_id", nodeID, "tenant_reports_count", len(p.UsageReport.TenantReports))
	}
}
