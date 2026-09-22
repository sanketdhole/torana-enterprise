package controlplane

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	controlplanev1 "github.com/phaselume/torana/api/proto/controlplane/v1"
	"github.com/phaselume/torana/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	// ErrInvalidSignature is returned when snapshot Ed25519 signature verification fails.
	ErrInvalidSignature = errors.New("invalid ed25519 snapshot signature")
)

// SnapshotConsumer is an interface implemented by Supervisor to receive compiled snapshots.
type SnapshotConsumer interface {
	UpdateSnapshot(snap *config.Snapshot) error
}

// Client manages the control plane gRPC stream lifecycle.
type Client struct {
	cfg       *config.BootstrapConfig
	consumer  SnapshotConsumer
	logger    *slog.Logger
	nodeID    string
	pubKey    ed25519.PublicKey // Optional public key for verifying signatures
	stopChan  chan struct{}
	wg        sync.WaitGroup
}

// NewClient creates a new control plane streaming client.
func NewClient(cfg *config.BootstrapConfig, consumer SnapshotConsumer, logger *slog.Logger) *Client {
	hostname, _ := net.LookupHost("localhost")
	nodeID := fmt.Sprintf("gateway-%s-%d", cfg.Namespace, time.Now().UnixNano()%10000)
	if len(hostname) > 0 {
		nodeID = fmt.Sprintf("gateway-%s", nodeID)
	}

	return &Client{
		cfg:      cfg,
		consumer: consumer,
		logger:   logger,
		nodeID:   nodeID,
		stopChan: make(chan struct{}),
	}
}

// SetPublicKey sets the Ed25519 public key for signature verification.
func (c *Client) SetPublicKey(pub ed25519.PublicKey) {
	c.pubKey = pub
}

// Start launches the control plane streaming background worker.
func (c *Client) Start(ctx context.Context) {
	c.wg.Add(1)
	go c.runLoop(ctx)
}

// Stop stops the client worker.
func (c *Client) Stop() {
	close(c.stopChan)
	c.wg.Wait()
}

func (c *Client) runLoop(ctx context.Context) {
	defer c.wg.Done()

	backoff := 1 * time.Second
	maxBackoff := 15 * time.Second

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopChan:
			return
		default:
		}

		err := c.connectAndStream(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			c.logger.Warn("control plane connection lost, reconnecting...",
				"platform_url", c.cfg.PlatformURL,
				"retry_in", backoff.String(),
				"error", err,
			)

			select {
			case <-ctx.Done():
				return
			case <-c.stopChan:
				return
			case <-time.After(backoff):
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
		} else {
			backoff = 1 * time.Second
		}
	}
}

func (c *Client) connectAndStream(ctx context.Context) error {
	addr := c.cfg.PlatformURL
	if strings.HasPrefix(addr, "http://") {
		addr = strings.TrimPrefix(addr, "http://")
	} else if strings.HasPrefix(addr, "grpc://") {
		addr = strings.TrimPrefix(addr, "grpc://")
	}

	c.logger.Info("connecting to control plane platform", "addr", addr)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("grpc dial error: %w", err)
	}
	defer func() { _ = conn.Close() }()

	client := controlplanev1.NewControlPlaneServiceClient(conn)

	// 1. Enroll
	enrollResp, err := client.Enroll(ctx, &controlplanev1.EnrollRequest{
		Namespace:   c.cfg.Namespace,
		NodeId:      c.nodeID,
		EnrollToken: c.cfg.EnrollTokenFile,
		Version:     "0.1.0-dev",
	})
	if err != nil {
		return fmt.Errorf("enrollment RPC failed: %w", err)
	}
	if !enrollResp.Accepted {
		return fmt.Errorf("enrollment rejected: %s", enrollResp.ErrorMessage)
	}

	c.logger.Info("enrollment successful", "cluster_id", enrollResp.ClusterId)

	// 2. Open Stream
	stream, err := client.Stream(ctx)
	if err != nil {
		return fmt.Errorf("stream open failed: %w", err)
	}

	// 3. Send Hello
	helloMsg := &controlplanev1.NodeMessage{
		NodeId:    c.nodeID,
		Namespace: c.cfg.Namespace,
		Timestamp: timestamppb.Now(),
		Payload: &controlplanev1.NodeMessage_Hello{
			Hello: &controlplanev1.Hello{
				Version:   "0.1.0-dev",
				StartTime: timestamppb.Now(),
				SupportedProtocols: []string{"http", "grpc", "ws", "mcp", "a2a"},
			},
		},
	}
	if err := stream.Send(helloMsg); err != nil {
		return fmt.Errorf("failed to send Hello message: %w", err)
	}

	c.logger.Info("established control plane stream, waiting for snapshots")

	// 4. Heartbeat ticker loop
	heartbeatTicker := time.NewTicker(5 * time.Second)
	defer heartbeatTicker.Stop()

	errChan := make(chan error, 2)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.stopChan:
				return
			case <-heartbeatTicker.C:
				hbMsg := &controlplanev1.NodeMessage{
					NodeId:    c.nodeID,
					Namespace: c.cfg.Namespace,
					Timestamp: timestamppb.Now(),
					Payload: &controlplanev1.NodeMessage_Heartbeat{
						Heartbeat: &controlplanev1.Heartbeat{
							ActiveConnections: 0,
							MemoryAllocatedBytes: 0,
						},
					},
				}
				if err := stream.Send(hbMsg); err != nil {
					errChan <- err
					return
				}
			}
		}
	}()

	// 5. Receive loop
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.stopChan:
			return nil
		case err := <-errChan:
			return err
		default:
		}

		msg, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("stream recv error: %w", err)
		}

		c.handleControlMessage(stream, msg)
	}
}

// HandleControlMessage processes an incoming control plane message.
func (c *Client) HandleControlMessage(stream controlplanev1.ControlPlaneService_StreamClient, msg *controlplanev1.ControlMessage) {
	c.handleControlMessage(stream, msg)
}

func (c *Client) handleControlMessage(stream controlplanev1.ControlPlaneService_StreamClient, msg *controlplanev1.ControlMessage) {
	switch p := msg.Payload.(type) {
	case *controlplanev1.ControlMessage_Snapshot:
		pbSnap := p.Snapshot
		c.logger.Info("received config snapshot from control plane", "version", pbSnap.ConfigVersion)

		// Verify signature if key is present
		if len(c.pubKey) > 0 && len(pbSnap.Ed25519Signature) > 0 {
			signPayload := []byte(fmt.Sprintf("config_version:%d", pbSnap.ConfigVersion))
			if !ed25519.Verify(c.pubKey, signPayload, pbSnap.Ed25519Signature) {
				c.logger.Error("rejected snapshot due to invalid signature", "version", pbSnap.ConfigVersion)
				_ = stream.Send(&controlplanev1.NodeMessage{
					NodeId:    c.nodeID,
					Namespace: c.cfg.Namespace,
					Timestamp: timestamppb.Now(),
					Payload: &controlplanev1.NodeMessage_Nack{
						Nack: &controlplanev1.Nack{
							RejectedConfigVersion: pbSnap.ConfigVersion,
							ErrorCode:             "INVALID_SIGNATURE",
							ErrorMessage:          "ed25519 signature verification failed",
						},
					},
				})
				return
			}
		}

		// Convert proto snapshot to internal config.Snapshot
		compiledSnap := convertProtoSnapshot(pbSnap)
		if err := c.consumer.UpdateSnapshot(compiledSnap); err != nil {
			c.logger.Error("failed to compile and apply snapshot", "version", pbSnap.ConfigVersion, "error", err)
			_ = stream.Send(&controlplanev1.NodeMessage{
				NodeId:    c.nodeID,
				Namespace: c.cfg.Namespace,
				Timestamp: timestamppb.Now(),
				Payload: &controlplanev1.NodeMessage_Nack{
					Nack: &controlplanev1.Nack{
						RejectedConfigVersion: pbSnap.ConfigVersion,
						ErrorCode:             "COMPILE_FAILED",
						ErrorMessage:          err.Error(),
					},
				},
			})
			return
		}

		c.logger.Info("applied snapshot successfully, sending ACK", "version", pbSnap.ConfigVersion)
		_ = stream.Send(&controlplanev1.NodeMessage{
			NodeId:    c.nodeID,
			Namespace: c.cfg.Namespace,
			Timestamp: timestamppb.Now(),
			Payload: &controlplanev1.NodeMessage_Ack{
				Ack: &controlplanev1.Ack{
					AppliedConfigVersion: pbSnap.ConfigVersion,
				},
			},
		})
	}
}

func convertProtoSnapshot(p *controlplanev1.Snapshot) *config.Snapshot {
	routes := make([]config.RouteRule, 0, len(p.Routes))
	for _, r := range p.Routes {
		routes = append(routes, config.RouteRule{
			ID:         r.Id,
			Path:       r.Path,
			PathPrefix: r.PathPrefix,
			Method:     r.Method,
			Headers:    r.Headers,
			UpstreamID: r.UpstreamId,
			Timeout:    time.Duration(r.TimeoutMs) * time.Millisecond,
		})
	}

	upstreams := make(map[string]config.UpstreamCluster, len(p.Upstreams))
	for _, u := range p.Upstreams {
		upstreams[u.Id] = config.UpstreamCluster{
			ID:        u.Id,
			Protocol:  u.Protocol,
			Endpoints: u.Endpoints,
			Timeout:   time.Duration(u.TimeoutMs) * time.Millisecond,
			MaxConns:  int(u.MaxConns),
		}
	}

	return &config.Snapshot{
		Version:   p.ConfigVersion,
		Timestamp: p.CreatedAt.AsTime(),
		Routes:    routes,
		Upstreams: upstreams,
	}
}
