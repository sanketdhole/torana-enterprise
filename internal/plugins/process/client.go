package process

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	pluginv1 "github.com/phaselume/torana/api/proto/plugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// PluginClient coordinates gRPC communication over Unix domain socket or remote mTLS.
type PluginClient struct {
	manifest  *ProcessManifest
	logger    *slog.Logger
	conn      *grpc.ClientConn
	client    pluginv1.PluginServiceClient
	descResp  *pluginv1.DescribeResponse
	target    string
	isRemote  bool
	closed    bool
	mu        sync.RWMutex
	stopChan  chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// NewPluginClient creates and dials a gRPC client to the plugin service.
func NewPluginClient(manifest *ProcessManifest, socketPath string, logger *slog.Logger) (*PluginClient, error) {
	c := &PluginClient{
		manifest: manifest,
		logger:   logger,
		stopChan: make(chan struct{}),
	}

	var dialTarget string
	var dialOpts []grpc.DialOption

	if manifest.Tier == TierRemote {
		c.isRemote = true
		dialTarget = manifest.RemoteEndpoint
		if dialTarget == "" {
			return nil, fmt.Errorf("remote plugin endpoint cannot be empty")
		}

		if manifest.TLS != nil {
			tlsConfig, err := manifest.TLS.ToTLSConfig()
			if err != nil {
				return nil, fmt.Errorf("failed to configure remote plugin mTLS: %w", err)
			}
			dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
		} else {
			dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		}
	} else {
		c.isRemote = false
		dialTarget = "unix://" + socketPath
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	c.target = dialTarget

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, dialTarget, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial plugin at %s: %w", dialTarget, err)
	}
	c.conn = conn
	c.client = pluginv1.NewPluginServiceClient(conn)

	// Perform Handshake
	handshakeResp, err := c.client.Handshake(ctx, &pluginv1.HandshakeRequest{
		GatewayVersion: "1.0.0",
		PluginId:       manifest.Name,
	})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: %v", ErrHandshakeFailed, err)
	}
	if !handshakeResp.Accepted {
		_ = conn.Close()
		return nil, fmt.Errorf("%w: %s", ErrHandshakeFailed, handshakeResp.ErrorMessage)
	}

	// Describe plugin capabilities
	descResp, err := c.client.Describe(ctx, &pluginv1.DescribeRequest{
		PluginId: manifest.Name,
	})
	if err == nil {
		c.descResp = descResp
	}

	// Start Background Health Checker
	if manifest.HealthCheckInterval > 0 {
		c.wg.Add(1)
		go c.healthCheckWorker()
	}

	return c, nil
}

// Client returns the bound gRPC PluginServiceClient stub.
func (c *PluginClient) Client() pluginv1.PluginServiceClient {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.client
}

// DescribeResponse returns the cached handshake description.
func (c *PluginClient) DescribeResponse() *pluginv1.DescribeResponse {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.descResp
}

func (c *PluginClient) healthCheckWorker() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.manifest.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.probeHealth()
		}
	}
}

func (c *PluginClient) probeHealth() {
	c.mu.RLock()
	client := c.client
	closed := c.closed
	c.mu.RUnlock()

	if closed || client == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := client.Describe(ctx, &pluginv1.DescribeRequest{
		PluginId: c.manifest.Name,
	})
	if err != nil && c.logger != nil {
		c.logger.Warn("plugin health check probe failed", "plugin", c.manifest.Name, "error", err)
	}
}

// Close closes the gRPC connection and terminates the health checker.
func (c *PluginClient) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()

		close(c.stopChan)
		c.wg.Wait()

		if c.conn != nil {
			err = c.conn.Close()
		}
	})
	return err
}

// Redial reconnects to the plugin socket or endpoint and performs handshake.
func (c *PluginClient) Redial() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrPluginClosed
	}

	if c.conn != nil {
		_ = c.conn.Close()
	}

	var dialOpts []grpc.DialOption
	if c.isRemote {
		if c.manifest.TLS != nil {
			tlsConfig, err := c.manifest.TLS.ToTLSConfig()
			if err != nil {
				return err
			}
			dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
		} else {
			dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		}
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, c.target, dialOpts...)
	if err != nil {
		return err
	}
	c.conn = conn
	c.client = pluginv1.NewPluginServiceClient(conn)

	// Perform Handshake
	_, _ = c.client.Handshake(ctx, &pluginv1.HandshakeRequest{
		GatewayVersion: "1.0.0",
		PluginId:       c.manifest.Name,
	})

	return nil
}

