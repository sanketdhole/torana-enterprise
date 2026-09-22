package process

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	pluginv1 "github.com/phaselume/torana/api/proto/plugin/v1"
	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/egress"
)

// EgressConnector adapts a process plugin into an egress.Client connector.
type EgressConnector struct {
	filter   *ProcessFilter
	protocol string
}

// NewEgressConnector wraps a ProcessFilter as an egress.Client.
func NewEgressConnector(protocol string, filter *ProcessFilter) *EgressConnector {
	if protocol == "" {
		protocol = filter.Name()
	}
	return &EgressConnector{
		filter:   filter,
		protocol: protocol,
	}
}

// Protocol returns the egress protocol identifier handled by this plugin connector.
func (c *EgressConnector) Protocol() string {
	return c.protocol
}

// Execute dispatches an egress invocation through the process plugin over gRPC.
func (c *EgressConnector) Execute(ctx context.Context, cluster *config.UpstreamCluster, req *egress.Request) (*egress.Response, error) {
	if !c.filter.circuitBreaker.Allow() {
		return nil, ErrCircuitOpen
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = c.filter.manifest.Timeout
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			c.filter.circuitBreaker.RecordFailure()
			return nil, fmt.Errorf("failed to read egress request body: %w", err)
		}
	}

	headers := make(map[string]string)
	for k, v := range req.Headers {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	upstreamID := ""
	if cluster != nil {
		upstreamID = cluster.ID
	}

	pbEnv := &pluginv1.Envelope{
		RequestId: fmt.Sprintf("egress-%d", time.Now().UnixNano()),
		RouteId:   upstreamID,
		Phase:     pluginv1.Phase_PHASE_REQUEST_BODY,
		Headers:   headers,
		Body:      bodyBytes,
	}

	grpcClient := c.filter.client.Client()
	if grpcClient == nil {
		return nil, ErrPluginClosed
	}

	dec, err := grpcClient.OnRequest(callCtx, pbEnv)
	if err != nil {
		c.filter.circuitBreaker.RecordFailure()
		return nil, fmt.Errorf("egress connector plugin call failed: %w", err)
	}

	c.filter.circuitBreaker.RecordSuccess()

	respHeaders := make(http.Header)
	for k, v := range dec.MutateHeaders {
		respHeaders.Set(k, v)
	}

	statusCode := int(dec.StatusCode)
	if statusCode == 0 {
		statusCode = http.StatusOK
	}

	return &egress.Response{
		StatusCode: statusCode,
		Headers:    respHeaders,
		Body:       io.NopCloser(bytes.NewReader(dec.MutateBody)),
	}, nil
}

// Close gracefully stops the connector.
func (c *EgressConnector) Close() error {
	return c.filter.Close()
}

// IngressConnector adapts a process plugin into an ingress.Listener.
type IngressConnector struct {
	filter   *ProcessFilter
	protocol string
	started  bool
}

// NewIngressConnector wraps a ProcessFilter as an ingress.Listener.
func NewIngressConnector(protocol string, filter *ProcessFilter) *IngressConnector {
	if protocol == "" {
		protocol = filter.Name()
	}
	return &IngressConnector{
		filter:   filter,
		protocol: protocol,
	}
}

// Protocol returns the ingress protocol name.
func (i *IngressConnector) Protocol() string {
	return i.protocol
}

// Start initiates the ingress connector listener.
func (i *IngressConnector) Start(ctx context.Context) error {
	i.started = true
	return nil
}

// Stop stops the ingress connector listener.
func (i *IngressConnector) Stop(ctx context.Context) error {
	i.started = false
	return i.filter.Close()
}
