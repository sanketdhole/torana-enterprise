package control

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	controlplanev1 "github.com/phaselume/torana/api/proto/controlplane/v1"
	"github.com/phaselume/torana/internal/config"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Client coordinates node enrollment, resilient control plane streaming,
// priority revocations, heartbeats, usage telemetry, and fail-static offline modes.
type Client struct {
	cfg                Config
	consumer           SnapshotConsumer
	revConsumer        RevocationConsumer
	metricsCollector   MetricsCollector
	usageCollector     UsageCollector
	enrollmentMgr      *EnrollmentManager
	logger             *slog.Logger

	mu                 sync.RWMutex
	lastAppliedVersion atomic.Uint64
	activeSnap         atomic.Pointer[config.Snapshot]
	stopChan           chan struct{}
	wg                 sync.WaitGroup
	customTransport    Transport // For testing and in-memory streams
}

// NewClient creates a new control plane client.
func NewClient(
	cfg Config,
	consumer SnapshotConsumer,
	revConsumer RevocationConsumer,
	logger *slog.Logger,
) *Client {
	if cfg.NodeID == "" {
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "gateway"
		}
		cfg.NodeID = fmt.Sprintf("%s-%s-%d", hostname, cfg.Namespace, time.Now().UnixNano()%10000)
	}
	if len(cfg.SupportedProtocols) == 0 {
		cfg.SupportedProtocols = []string{"http", "grpc", "ws", "mcp", "a2a"}
	}
	if len(cfg.SupportedABIs) == 0 {
		cfg.SupportedABIs = []string{"proxy-wasm-v0.2.1"}
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 5 * time.Second
	}
	if cfg.UsageFlushInterval <= 0 {
		cfg.UsageFlushInterval = 10 * time.Second
	}

	c := &Client{
		cfg:         cfg,
		consumer:    consumer,
		revConsumer: revConsumer,
		logger:      logger,
		stopChan:    make(chan struct{}),
	}

	c.enrollmentMgr = NewEnrollmentManager(cfg, nil, logger)
	return c
}

// SetCustomTransport sets an explicit transport (ideal for bufconn in-memory testing).
func (c *Client) SetCustomTransport(t Transport) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.customTransport = t
}

// SetMetricsCollector configures the metrics provider for heartbeats.
func (c *Client) SetMetricsCollector(mc MetricsCollector) {
	c.metricsCollector = mc
}

// SetUsageCollector configures the usage provider for telemetry batches.
func (c *Client) SetUsageCollector(uc UsageCollector) {
	c.usageCollector = uc
}

// Start launches control plane background operations.
func (c *Client) Start(ctx context.Context) error {
	// 1. Check for Offline Mode (--config-bundle)
	if c.cfg.ConfigBundle != "" {
		if err := c.loadOfflineBundle(c.cfg.ConfigBundle); err != nil {
			if c.logger != nil {
				c.logger.Error("failed to load offline config bundle", "path", c.cfg.ConfigBundle, "error", err)
			}
			c.setReady(false)
		} else {
			if c.logger != nil {
				c.logger.Info("operating in offline mode with config bundle", "path", c.cfg.ConfigBundle)
			}
			// If no platform URL is set, run completely offline
			if c.cfg.PlatformURL == "" {
				return nil
			}
		}
	}

	// 2. Fail-Static startup check: attempt LKG load if not ready
	if c.activeSnap.Load() == nil && c.cfg.LKGPath != "" {
		if lkgSnap, err := config.LoadLKG(c.cfg.LKGPath); err == nil && lkgSnap != nil {
			if err := c.applySnapshot(lkgSnap); err == nil {
				if c.logger != nil {
					c.logger.Info("recovered and serving on Last-Known-Good snapshot", "version", lkgSnap.Version)
				}
			}
		}
	}

	// 3. Ensure readiness reflects active config presence
	c.setReady(c.activeSnap.Load() != nil)

	// 4. Launch control plane connection loop
	if c.cfg.PlatformURL != "" || c.customTransport != nil {
		c.wg.Add(1)
		go c.runStreamingLoop(ctx)
	}

	return nil
}

// Stop stops the client and releases resources.
func (c *Client) Stop() {
	close(c.stopChan)
	c.wg.Wait()
	c.enrollmentMgr.Close()
}

// LastAppliedVersion returns the latest configuration version successfully applied.
func (c *Client) LastAppliedVersion() uint64 {
	return c.lastAppliedVersion.Load()
}

func (c *Client) loadOfflineBundle(bundlePath string) error {
	snap, err := config.LoadBundleFromFile(bundlePath)
	if err != nil {
		return err
	}
	return c.applySnapshot(snap)
}

func (c *Client) runStreamingLoop(ctx context.Context) {
	defer c.wg.Done()

	baseBackoff := 500 * time.Millisecond
	maxBackoff := 15 * time.Second
	currentBackoff := baseBackoff

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopChan:
			return
		default:
		}

		err := c.connectAndServe(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			// Exponential backoff with jitter (+- 25%)
			jitter := time.Duration(float64(currentBackoff) * (0.75 + rand.Float64()*0.5))
			if c.logger != nil {
				c.logger.Warn("control plane stream lost, reconnecting with backoff",
					"error", err,
					"retry_in", jitter.String(),
				)
			}

			select {
			case <-ctx.Done():
				return
			case <-c.stopChan:
				return
			case <-time.After(jitter):
				currentBackoff *= 2
				if currentBackoff > maxBackoff {
					currentBackoff = maxBackoff
				}
			}
		} else {
			currentBackoff = baseBackoff
		}
	}
}

func (c *Client) connectAndServe(ctx context.Context) error {
	var transport Transport
	var err error

	c.mu.RLock()
	custom := c.customTransport
	c.mu.RUnlock()

	if custom != nil {
		transport = custom
	} else {
		// Ensure mTLS enrollment credentials
		_ = c.enrollmentMgr.EnsureEnrolled(ctx)
		clientCert := c.enrollmentMgr.TLSCertificate()

		// Attempt 1: gRPC Transport with mTLS
		transport, err = DialGRPCTransport(ctx, c.cfg.PlatformURL, clientCert)
		if err != nil {
			if c.logger != nil {
				c.logger.Warn("grpc control transport failed, trying websocket fallback", "error", err)
			}
			// Attempt 2: WebSocket Fallback Transport
			transport, err = DialWSTransport(ctx, c.cfg.PlatformURL, clientCert)
			if err != nil {
				return fmt.Errorf("all control transports failed: %w", err)
			}
		}
	}
	defer func() { _ = transport.Close() }()

	// Send Hello handshake
	helloMsg := &controlplanev1.NodeMessage{
		NodeId:    c.cfg.NodeID,
		Namespace: c.cfg.Namespace,
		Timestamp: timestamppb.Now(),
		Payload: &controlplanev1.NodeMessage_Hello{
			Hello: &controlplanev1.Hello{
				Version:            "0.1.0-dev",
				SupportedProtocols: c.cfg.SupportedProtocols,
				SupportedPlugins:   c.cfg.PluginInventory,
				StartTime:          timestamppb.Now(),
			},
		},
	}
	if err := transport.Send(helloMsg); err != nil {
		return fmt.Errorf("failed to send Hello: %w", err)
	}

	// Channels for demuxing incoming messages with priority queue for Revocations
	revocationChan := make(chan *controlplanev1.Revocation, 100)
	normalChan := make(chan *controlplanev1.ControlMessage, 100)
	errChan := make(chan error, 3)

	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 1. Recv reader goroutine
	go func() {
		for {
			msg, err := transport.Recv()
			if err != nil {
				if err != io.EOF && !errors.Is(streamCtx.Err(), context.Canceled) {
					errChan <- err
				}
				return
			}

			// Demux priority revocations immediately
			if rev := msg.GetRevocation(); rev != nil {
				select {
				case revocationChan <- rev:
				default:
					// If priority queue full, apply immediately inline
					c.handleRevocation(rev)
				}
			} else {
				select {
				case normalChan <- msg:
				case <-streamCtx.Done():
					return
				}
			}
		}
	}()

	// 2. Heartbeat & Usage Ticker goroutines
	go c.runHeartbeat(streamCtx, transport, errChan)
	go c.runUsageReporting(streamCtx, transport, errChan)

	// 3. Main processing loop with priority revocation consumption
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.stopChan:
			return nil
		case err := <-errChan:
			return err

		// Priority check: Revocations are always consumed first
		case rev := <-revocationChan:
			c.handleRevocation(rev)

		default:
			// Secondary select giving precedence to revocations over normal messages
			select {
			case rev := <-revocationChan:
				c.handleRevocation(rev)

			case msg := <-normalChan:
				c.handleControlMessage(transport, msg)

			case <-ctx.Done():
				return ctx.Err()
			case <-c.stopChan:
				return nil
			case err := <-errChan:
				return err
			}
		}
	}
}

func (c *Client) handleRevocation(rev *controlplanev1.Revocation) {
	if c.revConsumer != nil && rev != nil {
		if c.logger != nil {
			c.logger.Info("processing PRIORITY revocation",
				"revoked_tokens", len(rev.RevokedTokens),
				"revoked_keys", len(rev.RevokedKeys),
			)
		}
		_ = c.revConsumer.ApplyRevocation(rev)
	}
}

func (c *Client) handleControlMessage(transport Transport, msg *controlplanev1.ControlMessage) {
	switch p := msg.Payload.(type) {
	case *controlplanev1.ControlMessage_Snapshot:
		c.handleSnapshot(transport, msg, p.Snapshot)

	case *controlplanev1.ControlMessage_Delta:
		c.handleDelta(transport, msg, p.Delta)

	case *controlplanev1.ControlMessage_Command:
		c.handleCommand(transport, p.Command)
	}
}

func (c *Client) handleSnapshot(transport Transport, msg *controlplanev1.ControlMessage, pbSnap *controlplanev1.Snapshot) {
	version := pbSnap.ConfigVersion

	// 1. Verify Namespace if provided in MessageId (format "namespace:msg-id" or similar)
	if strings.Contains(msg.MessageId, ":") {
		parts := strings.SplitN(msg.MessageId, ":", 2)
		if parts[0] != "" && parts[0] != c.cfg.Namespace && !strings.HasPrefix(parts[0], "msg") && !strings.HasPrefix(parts[0], "init") {
			c.nack(transport, version, "WRONG_NAMESPACE", fmt.Sprintf("namespace mismatch: expected %q, got %q", c.cfg.Namespace, parts[0]))
			return
		}
	}

	// 2. Verify Ed25519 Signature
	if len(c.cfg.Ed25519PublicKey) > 0 {
		if len(pbSnap.Ed25519Signature) == 0 {
			c.nack(transport, version, "MISSING_SIGNATURE", "ed25519 signature missing on snapshot")
			return
		}

		signPayloadNS := []byte(fmt.Sprintf("%s:config_version:%d", c.cfg.Namespace, version))
		signPayloadPlain := []byte(fmt.Sprintf("config_version:%d", version))

		valid := ed25519.Verify(c.cfg.Ed25519PublicKey, signPayloadNS, pbSnap.Ed25519Signature) ||
			ed25519.Verify(c.cfg.Ed25519PublicKey, signPayloadPlain, pbSnap.Ed25519Signature)

		if !valid {
			c.nack(transport, version, "INVALID_SIGNATURE", "ed25519 signature verification failed")
			return
		}
	}

	// 3. Convert and Apply Snapshot
	snap := convertProtoSnapshot(pbSnap)
	if err := c.applySnapshot(snap); err != nil {
		c.nack(transport, version, "COMPILE_FAILED", err.Error())
		return
	}

	c.ack(transport, version)
}

func (c *Client) handleDelta(transport Transport, msg *controlplanev1.ControlMessage, delta *controlplanev1.Delta) {
	targetVersion := delta.TargetConfigVersion
	currentVersion := c.lastAppliedVersion.Load()

	// 1. Verify Namespace if tagged in MessageId
	if strings.Contains(msg.MessageId, ":") {
		parts := strings.SplitN(msg.MessageId, ":", 2)
		if parts[0] != "" && parts[0] != c.cfg.Namespace && !strings.HasPrefix(parts[0], "msg") && !strings.HasPrefix(parts[0], "delta") {
			c.nack(transport, targetVersion, "WRONG_NAMESPACE", fmt.Sprintf("namespace mismatch: expected %q, got %q", c.cfg.Namespace, parts[0]))
			return
		}
	}

	// 2. Verify Delta Base Matches Current Version
	if delta.BaseConfigVersion != currentVersion {
		c.nack(transport, targetVersion, "DELTA_BASE_MISMATCH",
			fmt.Sprintf("delta base %d does not match active version %d; full snapshot required", delta.BaseConfigVersion, currentVersion))
		return
	}

	// 3. Verify Ed25519 Signature
	if len(c.cfg.Ed25519PublicKey) > 0 {
		signPayloadNS := []byte(fmt.Sprintf("%s:delta:%d->%d", c.cfg.Namespace, delta.BaseConfigVersion, targetVersion))
		signPayloadPlain := []byte(fmt.Sprintf("delta:%d->%d", delta.BaseConfigVersion, targetVersion))

		valid := ed25519.Verify(c.cfg.Ed25519PublicKey, signPayloadNS, delta.Ed25519Signature) ||
			ed25519.Verify(c.cfg.Ed25519PublicKey, signPayloadPlain, delta.Ed25519Signature)

		if !valid {
			c.nack(transport, targetVersion, "INVALID_SIGNATURE", "ed25519 delta signature verification failed")
			return
		}
	}

	// 3. Apply Delta onto current active snapshot
	currentSnap := c.activeSnap.Load()
	if currentSnap == nil {
		c.nack(transport, targetVersion, "NO_BASE_SNAPSHOT", "cannot apply delta without active base snapshot")
		return
	}

	mergedSnap := applyDeltaToSnapshot(currentSnap, delta)
	if err := c.applySnapshot(mergedSnap); err != nil {
		c.nack(transport, targetVersion, "COMPILE_FAILED", err.Error())
		return
	}

	c.ack(transport, targetVersion)
}

func (c *Client) handleCommand(_ Transport, cmd *controlplanev1.Command) {
	if cmd == nil {
		return
	}
	if c.logger != nil {
		c.logger.Info("received operational command", "type", cmd.CommandType)
	}
	switch cmd.CommandType {
	case controlplanev1.Command_DRAIN:
		c.setReady(false)
	case controlplanev1.Command_RELOAD:
		if snap := c.activeSnap.Load(); snap != nil {
			_ = c.consumer.UpdateSnapshot(snap)
		}
	}
}

func (c *Client) setReady(ready bool) {
	if rc, ok := c.consumer.(ReadinessConsumer); ok {
		rc.SetReady(ready)
	}
}

func (c *Client) applySnapshot(snap *config.Snapshot) error {
	if err := c.consumer.UpdateSnapshot(snap); err != nil {
		return err
	}

	c.activeSnap.Store(snap)
	c.lastAppliedVersion.Store(snap.Version)
	c.setReady(true)

	// Persist Last-Known-Good to disk
	if c.cfg.LKGPath != "" {
		_ = config.SaveLKG(c.cfg.LKGPath, snap)
	}

	if c.logger != nil {
		c.logger.Info("applied configuration snapshot successfully", "version", snap.Version)
	}
	return nil
}

func (c *Client) ack(transport Transport, version uint64) {
	_ = transport.Send(&controlplanev1.NodeMessage{
		NodeId:    c.cfg.NodeID,
		Namespace: c.cfg.Namespace,
		Timestamp: timestamppb.Now(),
		Payload: &controlplanev1.NodeMessage_Ack{
			Ack: &controlplanev1.Ack{
				AppliedConfigVersion: version,
			},
		},
	})
}

func (c *Client) nack(transport Transport, version uint64, code, msg string) {
	if c.logger != nil {
		c.logger.Warn("sending NACK to control plane", "version", version, "code", code, "reason", msg)
	}
	_ = transport.Send(&controlplanev1.NodeMessage{
		NodeId:    c.cfg.NodeID,
		Namespace: c.cfg.Namespace,
		Timestamp: timestamppb.Now(),
		Payload: &controlplanev1.NodeMessage_Nack{
			Nack: &controlplanev1.Nack{
				RejectedConfigVersion: version,
				ErrorCode:             code,
				ErrorMessage:          msg,
			},
		},
	})
}

func (c *Client) runHeartbeat(ctx context.Context, transport Transport, errChan chan error) {
	ticker := time.NewTicker(c.cfg.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopChan:
			return
		case <-ticker.C:
			var activeConns, activeStreams, memAlloc, cpuUsage int64
			if c.metricsCollector != nil {
				activeConns = c.metricsCollector.ActiveConnections()
				activeStreams = c.metricsCollector.ActiveStreams()
				memAlloc = c.metricsCollector.MemoryAllocatedBytes()
				cpuUsage = c.metricsCollector.CPUUsagePermille()
			}

			hb := &controlplanev1.NodeMessage{
				NodeId:    c.cfg.NodeID,
				Namespace: c.cfg.Namespace,
				Timestamp: timestamppb.Now(),
				Payload: &controlplanev1.NodeMessage_Heartbeat{
					Heartbeat: &controlplanev1.Heartbeat{
						ActiveConnections:    activeConns,
						ActiveStreams:        activeStreams,
						MemoryAllocatedBytes: memAlloc,
						CpuUsagePermille:     cpuUsage,
						CurrentConfigVersion: c.lastAppliedVersion.Load(),
					},
				},
			}

			if err := transport.Send(hb); err != nil {
				select {
				case errChan <- err:
				default:
				}
				return
			}
		}
	}
}

func (c *Client) runUsageReporting(ctx context.Context, transport Transport, errChan chan error) {
	ticker := time.NewTicker(c.cfg.UsageFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopChan:
			return
		case <-ticker.C:
			if c.usageCollector == nil {
				continue
			}

			tenantReports := c.usageCollector.CollectTenantUsage()
			if len(tenantReports) == 0 {
				continue
			}

			usageMsg := &controlplanev1.NodeMessage{
				NodeId:    c.cfg.NodeID,
				Namespace: c.cfg.Namespace,
				Timestamp: timestamppb.Now(),
				Payload: &controlplanev1.NodeMessage_UsageReport{
					UsageReport: &controlplanev1.UsageReport{
						TenantReports: tenantReports,
					},
				},
			}

			if err := transport.Send(usageMsg); err != nil {
				select {
				case errChan <- err:
				default:
				}
				return
			}
		}
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

	snapTime := time.Now()
	if p.CreatedAt != nil {
		snapTime = p.CreatedAt.AsTime()
	}

	return &config.Snapshot{
		Version:   p.ConfigVersion,
		Timestamp: snapTime,
		Routes:    routes,
		Upstreams: upstreams,
	}
}

func applyDeltaToSnapshot(base *config.Snapshot, delta *controlplanev1.Delta) *config.Snapshot {
	// 1. Copy routes, applying deletions and updates
	deletedRoutes := make(map[string]bool)
	for _, id := range delta.DeletedRouteIds {
		deletedRoutes[id] = true
	}

	routeMap := make(map[string]config.RouteRule)
	for _, r := range base.Routes {
		if !deletedRoutes[r.ID] {
			routeMap[r.ID] = r
		}
	}
	for _, r := range delta.AddedOrUpdatedRoutes {
		routeMap[r.Id] = config.RouteRule{
			ID:         r.Id,
			Path:       r.Path,
			PathPrefix: r.PathPrefix,
			Method:     r.Method,
			Headers:    r.Headers,
			UpstreamID: r.UpstreamId,
			Timeout:    time.Duration(r.TimeoutMs) * time.Millisecond,
		}
	}

	newRoutes := make([]config.RouteRule, 0, len(routeMap))
	for _, r := range routeMap {
		newRoutes = append(newRoutes, r)
	}

	// 2. Copy upstreams, applying deletions and updates
	deletedUpstreams := make(map[string]bool)
	for _, id := range delta.DeletedUpstreamIds {
		deletedUpstreams[id] = true
	}

	upstreamMap := make(map[string]config.UpstreamCluster)
	for id, u := range base.Upstreams {
		if !deletedUpstreams[id] {
			upstreamMap[id] = u
		}
	}
	for _, u := range delta.AddedOrUpdatedUpstreams {
		upstreamMap[u.Id] = config.UpstreamCluster{
			ID:        u.Id,
			Protocol:  u.Protocol,
			Endpoints: u.Endpoints,
			Timeout:   time.Duration(u.TimeoutMs) * time.Millisecond,
			MaxConns:  int(u.MaxConns),
		}
	}

	return &config.Snapshot{
		Version:   delta.TargetConfigVersion,
		Timestamp: time.Now(),
		Routes:    newRoutes,
		Upstreams: upstreamMap,
	}
}
