package mcp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/egress"
)

// Client manages outbound connections to upstream MCP servers with pooling.
type Client struct {
	mu            sync.RWMutex
	pools         map[string]*http.Client
	defaultClient *http.Client
}

// NewClient creates an outbound MCP egress client.
func NewClient() *Client {
	transport := &http.Transport{
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true, // Preserve SSE chunk framing
	}
	return &Client{
		pools: make(map[string]*http.Client),
		defaultClient: &http.Client{
			Transport: transport,
			Timeout:   60 * time.Second,
		},
	}
}

// Protocol returns "mcp".
func (c *Client) Protocol() string {
	return "mcp"
}

// SetClientForCluster overrides the HTTP client for a specific cluster (ideal for testing).
func (c *Client) SetClientForCluster(clusterID string, httpClient *http.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pools[clusterID] = httpClient
}

func (c *Client) getClient(cluster *config.UpstreamCluster) *http.Client {
	c.mu.RLock()
	client, ok := c.pools[cluster.ID]
	c.mu.RUnlock()
	if ok && client != nil {
		return client
	}
	return c.defaultClient
}

// SendJSONRPC dispatches a single JSON-RPC 2.0 request to the upstream MCP cluster.
func (c *Client) SendJSONRPC(
	ctx context.Context,
	cluster *config.UpstreamCluster,
	path string,
	reqBody []byte,
	upstreamSessionID string,
	headers http.Header,
) ([]byte, http.Header, error) {
	if len(cluster.Endpoints) == 0 {
		return nil, nil, egress.ErrNoEndpoints
	}

	targetURL := cluster.Endpoints[0] + path
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build upstream mcp request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")
	if upstreamSessionID != "" {
		httpReq.Header.Set("Mcp-Session-Id", upstreamSessionID)
	}

	// Propagate caller headers
	for k, vv := range headers {
		if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Host") {
			continue
		}
		for _, v := range vv {
			httpReq.Header.Add(k, v)
		}
	}

	httpClient := c.getClient(cluster)
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("upstream mcp request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.Header, fmt.Errorf("failed to read upstream mcp response: %w", err)
	}

	if resp.StatusCode >= 400 && len(respBody) == 0 {
		return nil, resp.Header, fmt.Errorf("upstream mcp returned http status %d", resp.StatusCode)
	}

	return respBody, resp.Header, nil
}

// Execute fulfills egress.Client for generic HTTP proxying.
func (c *Client) Execute(ctx context.Context, cluster *config.UpstreamCluster, req *egress.Request) (*egress.Response, error) {
	if len(cluster.Endpoints) == 0 {
		return nil, egress.ErrNoEndpoints
	}

	targetURL := cluster.Endpoints[0] + req.Path
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, targetURL, req.Body)
	if err != nil {
		return nil, err
	}
	httpReq.Header = req.Headers

	httpClient := c.getClient(cluster)
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}

	return &egress.Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       resp.Body,
	}, nil
}

// Close closes idle transport connections.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.defaultClient.CloseIdleConnections()
	for _, cl := range c.pools {
		cl.CloseIdleConnections()
	}
	return nil
}
