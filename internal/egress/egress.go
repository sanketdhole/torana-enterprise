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
	Method  string
	Path    string
	Headers http.Header
	Body    io.Reader
	Timeout time.Duration
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

// HTTPClient implements the Client interface for upstream HTTP/REST AI providers.
type HTTPClient struct {
	httpClient *http.Client
}

// NewHTTPClient creates an HTTP egress client with pooled connections.
func NewHTTPClient() *HTTPClient {
	transport := &http.Transport{
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true, // Preserve streaming chunks
	}
	return &HTTPClient{
		httpClient: &http.Client{
			Transport: transport,
		},
	}
}

// Protocol returns "http".
func (c *HTTPClient) Protocol() string {
	return "http"
}

// Execute performs the upstream HTTP request with streaming body forwarding.
func (c *HTTPClient) Execute(ctx context.Context, cluster *config.UpstreamCluster, req *Request) (*Response, error) {
	if len(cluster.Endpoints) == 0 {
		return nil, ErrNoEndpoints
	}

	targetURL := cluster.Endpoints[0] + req.Path

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, targetURL, req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to create upstream request: %w", err)
	}

	// Copy headers
	for k, vv := range req.Headers {
		for _, v := range vv {
			httpReq.Header.Add(k, v)
		}
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("upstream http request failed: %w", err)
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       resp.Body,
	}, nil
}

// Close cleans up idle connections.
func (c *HTTPClient) Close() error {
	c.httpClient.CloseIdleConnections()
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
