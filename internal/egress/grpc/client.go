package grpc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/egress"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

// Frame represents raw wire-format bytes of an arbitrary gRPC payload.
type Frame struct {
	Payload []byte
}

// RawCodec provides zero-descriptor raw byte encoding for gRPC streams.
type RawCodec struct{}

// Name returns "proto" so gRPC selects this codec for application/grpc content.
func (RawCodec) Name() string {
	return "proto"
}

// Marshal encodes Frame or byte slice directly to wire format.
func (RawCodec) Marshal(v any) ([]byte, error) {
	switch val := v.(type) {
	case *Frame:
		if val == nil {
			return nil, nil
		}
		return val.Payload, nil
	case Frame:
		return val.Payload, nil
	case []byte:
		return val, nil
	case *[]byte:
		if val == nil {
			return nil, nil
		}
		return *val, nil
	case proto.Message:
		return proto.Marshal(val)
	default:
		return nil, fmt.Errorf("raw codec: unsupported type %T", v)
	}
}

// Unmarshal decodes wire format directly into Frame or byte slice.
func (RawCodec) Unmarshal(data []byte, v any) error {
	switch val := v.(type) {
	case *Frame:
		val.Payload = make([]byte, len(data))
		copy(val.Payload, data)
		return nil
	case *[]byte:
		*val = make([]byte, len(data))
		copy(*val, data)
		return nil
	case proto.Message:
		return proto.Unmarshal(data, val)
	default:
		return fmt.Errorf("raw codec: unsupported destination %T", v)
	}
}

// Client implements a protocol-agnostic gRPC egress client with connection pooling.
type Client struct {
	mu    sync.RWMutex
	conns map[string]*grpc.ClientConn
}

// NewClient creates an egress gRPC client.
func NewClient() *Client {
	return &Client{
		conns: make(map[string]*grpc.ClientConn),
	}
}

// Protocol returns "grpc".
func (c *Client) Protocol() string {
	return "grpc"
}

// SetConnForCluster overrides or injects a ClientConn for a cluster (ideal for testing).
func (c *Client) SetConnForCluster(clusterID string, conn *grpc.ClientConn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conns[clusterID] = conn
}

// getConn retrieves or creates a connection for the given upstream cluster.
func (c *Client) getConn(cluster *config.UpstreamCluster) (*grpc.ClientConn, error) {
	c.mu.RLock()
	conn, ok := c.conns[cluster.ID]
	c.mu.RUnlock()
	if ok && conn != nil {
		return conn, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if conn, ok := c.conns[cluster.ID]; ok && conn != nil {
		return conn, nil
	}

	if len(cluster.Endpoints) == 0 {
		return nil, egress.ErrNoEndpoints
	}

	endpoint := cluster.Endpoints[0]
	endpoint = strings.TrimPrefix(endpoint, "http://")
	endpoint = strings.TrimPrefix(endpoint, "https://")
	endpoint = strings.TrimPrefix(endpoint, "grpc://")
	endpoint = strings.TrimPrefix(endpoint, "grpcs://")

	var creds credentials.TransportCredentials
	if strings.Contains(cluster.Endpoints[0], "https://") || strings.Contains(cluster.Endpoints[0], "grpcs://") {
		creds = credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})
	} else {
		creds = insecure.NewCredentials()
	}

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(RawCodec{})),
	}

	newConn, err := grpc.NewClient(endpoint, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to upstream gRPC cluster %s (%s): %w", cluster.ID, endpoint, err)
	}

	c.conns[cluster.ID] = newConn
	return newConn, nil
}

// ProxyStream proxies an active gRPC server stream to the upstream cluster using raw-bytes framing.
func (c *Client) ProxyStream(
	ctx context.Context,
	cluster *config.UpstreamCluster,
	method string,
	incomingMD metadata.MD,
	serverStream grpc.ServerStream,
) error {
	conn, err := c.getConn(cluster)
	if err != nil {
		return err
	}

	var outgoingMD metadata.MD
	if incomingMD != nil {
		outgoingMD = incomingMD.Copy()
	} else {
		outgoingMD = metadata.MD{}
	}

	clientCtx := metadata.NewOutgoingContext(ctx, outgoingMD)

	desc := &grpc.StreamDesc{
		StreamName:    method,
		ServerStreams: true,
		ClientStreams: true,
	}

	clientStream, err := conn.NewStream(clientCtx, desc, method, grpc.ForceCodec(RawCodec{}))
	if err != nil {
		return err
	}

	fwdErrChan := make(chan error, 1)

	// Goroutine: Forward downstream requests to upstream
	go func() {
		for {
			var frame Frame
			recvErr := serverStream.RecvMsg(&frame)
			if errors.Is(recvErr, io.EOF) {
				_ = clientStream.CloseSend()
				fwdErrChan <- nil
				return
			}
			if recvErr != nil {
				_ = clientStream.CloseSend()
				fwdErrChan <- recvErr
				return
			}
			if sendErr := clientStream.SendMsg(&frame); sendErr != nil {
				fwdErrChan <- sendErr
				return
			}
		}
	}()

	// Propagate response headers from upstream to downstream
	headerMD, err := clientStream.Header()
	if err == nil && headerMD != nil && headerMD.Len() > 0 {
		_ = serverStream.SendHeader(headerMD)
	}

	// Main loop: Forward upstream responses to downstream
	var streamErr error
	for {
		var frame Frame
		recvErr := clientStream.RecvMsg(&frame)
		if errors.Is(recvErr, io.EOF) {
			break
		}
		if recvErr != nil {
			streamErr = recvErr
			break
		}
		if sendErr := serverStream.SendMsg(&frame); sendErr != nil {
			streamErr = sendErr
			break
		}
	}

	// Always propagate trailers from upstream to downstream
	if trailers := clientStream.Trailer(); trailers != nil && trailers.Len() > 0 {
		serverStream.SetTrailer(trailers)
	}

	downstreamErr := <-fwdErrChan

	if streamErr != nil {
		return streamErr
	}
	return downstreamErr
}

// Execute fulfills egress.Client interface for HTTP-to-gRPC transcoding if invoked.
func (c *Client) Execute(ctx context.Context, cluster *config.UpstreamCluster, req *egress.Request) (*egress.Response, error) {
	return nil, errors.New("unary HTTP Execute on gRPC client not directly supported; use ProxyStream")
}

// Close closes all pooled upstream client connections.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var firstErr error
	for id, conn := range c.conns {
		if err := conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(c.conns, id)
	}
	return firstErr
}
