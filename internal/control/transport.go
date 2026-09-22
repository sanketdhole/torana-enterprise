package control

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/coder/websocket"
	controlplanev1 "github.com/phaselume/torana/api/proto/controlplane/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
)

// Transport abstracts bidirectional streaming between the data plane and control plane.
// It allows gRPC with mTLS as the primary transport, and WebSocket/long-poll as a fallback.
type Transport interface {
	Send(msg *controlplanev1.NodeMessage) error
	Recv() (*controlplanev1.ControlMessage, error)
	Close() error
}

// GRPCTransport wraps a gRPC bidirectional stream.
type GRPCTransport struct {
	conn   *grpc.ClientConn
	stream controlplanev1.ControlPlaneService_StreamClient
}

// DialGRPCTransport dials the control plane via gRPC with mTLS or insecure fallback.
func DialGRPCTransport(ctx context.Context, target string, clientCert *tls.Certificate, dialOpts ...grpc.DialOption) (*GRPCTransport, error) {
	addr := strings.TrimPrefix(target, "http://")
	addr = strings.TrimPrefix(addr, "https://")
	addr = strings.TrimPrefix(addr, "grpc://")

	var creds credentials.TransportCredentials
	if clientCert != nil {
		tlsConfig := &tls.Config{
			Certificates:       []tls.Certificate{*clientCert},
			InsecureSkipVerify: true, // For development and internal control planes
		}
		creds = credentials.NewTLS(tlsConfig)
	} else {
		creds = insecure.NewCredentials()
	}

	opts := append([]grpc.DialOption{grpc.WithTransportCredentials(creds)}, dialOpts...)
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("grpc dial failed: %w", err)
	}

	client := controlplanev1.NewControlPlaneServiceClient(conn)
	stream, err := client.Stream(ctx)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to open grpc control stream: %w", err)
	}

	return &GRPCTransport{
		conn:   conn,
		stream: stream,
	}, nil
}

func (t *GRPCTransport) Send(msg *controlplanev1.NodeMessage) error {
	return t.stream.Send(msg)
}

func (t *GRPCTransport) Recv() (*controlplanev1.ControlMessage, error) {
	return t.stream.Recv()
}

func (t *GRPCTransport) Close() error {
	return t.conn.Close()
}

// WSTransport implements Transport using WebSocket as a resilient fallback.
type WSTransport struct {
	conn *websocket.Conn
	ctx  context.Context
}

// DialWSTransport connects via WebSocket to the fallback stream endpoint.
func DialWSTransport(ctx context.Context, wsURL string, clientCert *tls.Certificate) (*WSTransport, error) {
	if !strings.HasPrefix(wsURL, "ws://") && !strings.HasPrefix(wsURL, "wss://") {
		wsURL = "ws://" + wsURL
	}
	if !strings.HasSuffix(wsURL, "/control/stream") {
		wsURL = strings.TrimRight(wsURL, "/") + "/control/stream"
	}

	httpClient := &http.Client{}
	if clientCert != nil {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates:       []tls.Certificate{*clientCert},
				InsecureSkipVerify: true,
			},
		}
	}

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPClient: httpClient,
	})
	if err != nil {
		return nil, fmt.Errorf("websocket control dial failed: %w", err)
	}

	return &WSTransport{
		conn: conn,
		ctx:  ctx,
	}, nil
}

func (t *WSTransport) Send(msg *controlplanev1.NodeMessage) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	return t.conn.Write(t.ctx, websocket.MessageBinary, data)
}

func (t *WSTransport) Recv() (*controlplanev1.ControlMessage, error) {
	msgType, data, err := t.conn.Read(t.ctx)
	if err != nil {
		return nil, err
	}
	if msgType != websocket.MessageBinary {
		return nil, io.ErrUnexpectedEOF
	}

	var ctrlMsg controlplanev1.ControlMessage
	if err := proto.Unmarshal(data, &ctrlMsg); err != nil {
		return nil, err
	}
	return &ctrlMsg, nil
}

func (t *WSTransport) Close() error {
	return t.conn.Close(websocket.StatusNormalClosure, "closed")
}
