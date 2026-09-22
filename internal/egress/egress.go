package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/phaselume/torana/internal/config"
)

var (
	// ErrUnsupportedEgressProtocol is returned when an upstream cluster uses an unknown protocol.
	ErrUnsupportedEgressProtocol = errors.New("unsupported egress protocol")
	// ErrNoEndpoints is returned when an upstream cluster has no endpoints configured.
	ErrNoEndpoints = errors.New("no upstream endpoints available")
)

// Request defines an egress invocation request.
type Request struct {
	Method      string
	Path        string
	Headers     http.Header
	Body        io.Reader
	Timeout     time.Duration
	RetryPolicy *config.RetryPolicy
}

// Response defines an egress invocation response.
type Response struct {
	StatusCode int
	Headers    http.Header
	Body       io.ReadCloser
}

// Client represents an egress connector to an upstream service.
type Client interface {
	Protocol() string
	Execute(ctx context.Context, cluster *config.UpstreamCluster, req *Request) (*Response, error)
	Close() error
}

// HTTPClient implements the Client interface with per-upstream connection pools and retry policies.
type HTTPClient struct {
	mu      sync.RWMutex
	pools   map[string]*http.Client
	defaultClient *http.Client
}

// NewHTTPClient creates an HTTP egress client with pooled connections.
func NewHTTPClient() *HTTPClient {
	defaultTransport := &http.Transport{
		MaxIdleConns:        2000,
		MaxIdleConnsPerHost: 200,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true, // Preserve streaming chunks
		ForceAttemptHTTP2:   true,
	}
	return &HTTPClient{
		pools: make(map[string]*http.Client),
		defaultClient: &http.Client{
			Transport: defaultTransport,
		},
	}
}

// Protocol returns "http".
func (c *HTTPClient) Protocol() string {
	return "http"
}

// SetTransportForCluster overrides the HTTP transport for a specific upstream cluster.
func (c *HTTPClient) SetTransportForCluster(clusterID string, transport http.RoundTripper) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pools[clusterID] = &http.Client{Transport: transport}
}

// SetDefaultTransport overrides the fallback HTTP transport.
func (c *HTTPClient) SetDefaultTransport(transport http.RoundTripper) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.defaultClient = &http.Client{Transport: transport}
}

func (c *HTTPClient) getClientForCluster(cluster *config.UpstreamCluster) *http.Client {
	c.mu.RLock()
	client, ok := c.pools[cluster.ID]
	c.mu.RUnlock()
	if ok {
		return client
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if client, ok := c.pools[cluster.ID]; ok {
		return client
	}

	maxConns := cluster.MaxConns
	if maxConns <= 0 {
		maxConns = 100
	}

	transport := &http.Transport{
		MaxIdleConns:        maxConns * 2,
		MaxIdleConnsPerHost: maxConns,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
	}

	client = &http.Client{
		Transport: transport,
	}
	c.pools[cluster.ID] = client
	return client
}

// Execute performs the upstream HTTP request with retries and streaming body forwarding.
func (c *HTTPClient) Execute(ctx context.Context, cluster *config.UpstreamCluster, req *Request) (*Response, error) {
	if len(cluster.Endpoints) == 0 {
		return nil, ErrNoEndpoints
	}

	httpClient := c.getClientForCluster(cluster)
	targetURL := cluster.Endpoints[0] + req.Path

	maxAttempts := 1
	if req.RetryPolicy != nil && req.RetryPolicy.MaxRetries > 0 {
		maxAttempts = req.RetryPolicy.MaxRetries + 1
	}

	var lastErr error
	var lastResp *http.Response

	for attempt := 0; attempt < maxAttempts; attempt++ {
		attemptCtx := ctx
		if req.RetryPolicy != nil && req.RetryPolicy.PerTryTimeout > 0 {
			var cancel context.CancelFunc
			attemptCtx, cancel = context.WithTimeout(ctx, req.RetryPolicy.PerTryTimeout)
			defer cancel()
		}

		httpReq, err := http.NewRequestWithContext(attemptCtx, req.Method, targetURL, req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to create upstream request: %w", err)
		}

		// Copy headers
		for k, vv := range req.Headers {
			for _, v := range vv {
				httpReq.Header.Add(k, v)
			}
		}

		resp, err := httpClient.Do(httpReq)
		if err != nil {
			lastErr = err
			if attempt < maxAttempts-1 {
				if req.RetryPolicy != nil && req.RetryPolicy.Backoff > 0 {
					time.Sleep(req.RetryPolicy.Backoff)
				}
				continue
			}
			return nil, fmt.Errorf("upstream http request failed after %d attempts: %w", maxAttempts, err)
		}

		// Check if status code warrants retry
		if req.RetryPolicy != nil && len(req.RetryPolicy.RetryOnStatusCodes) > 0 {
			shouldRetry := false
			for _, code := range req.RetryPolicy.RetryOnStatusCodes {
				if resp.StatusCode == code {
					shouldRetry = true
					break
				}
			}

			if shouldRetry && attempt < maxAttempts-1 {
				_ = resp.Body.Close()
				lastResp = resp
				if req.RetryPolicy.Backoff > 0 {
					time.Sleep(req.RetryPolicy.Backoff)
				}
				continue
			}
		}

		return &Response{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Body:       resp.Body,
		}, nil
	}

	if lastResp != nil {
		return &Response{
			StatusCode: lastResp.StatusCode,
			Headers:    lastResp.Header,
			Body:       lastResp.Body,
		}, nil
	}

	return nil, lastErr
}

// Close cleans up idle connections across all pools.
func (c *HTTPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.defaultClient.CloseIdleConnections()
	for _, client := range c.pools {
		client.CloseIdleConnections()
	}
	return nil
}

// Registry maintains active egress clients indexed by protocol name.
type Registry struct {
	mu      sync.RWMutex
	clients map[string]Client
}

// NewRegistry initializes an egress registry with default clients.
func NewRegistry() *Registry {
	r := &Registry{
		clients: make(map[string]Client),
	}
	r.Register("http", NewHTTPClient())
	return r
}

// Register registers a new protocol client.
func (r *Registry) Register(protocol string, client Client) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clients[protocol] = client
}

// Get fetches the client for the requested protocol.
func (r *Registry) Get(protocol string) (Client, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.clients[protocol]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedEgressProtocol, protocol)
	}
	return c, nil
}

// Close closes all registered clients.
func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.clients {
		_ = c.Close()
	}
	return nil
}
