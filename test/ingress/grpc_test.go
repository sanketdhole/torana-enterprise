package ingress_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/egress"
	egressgrpc "github.com/phaselume/torana/internal/egress/grpc"
	ingressgrpc "github.com/phaselume/torana/internal/ingress/grpc"
	"github.com/phaselume/torana/internal/pipeline"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// setupGRPCTestEnvironment boots an in-process upstream server and a Torana gRPC ingress listener via bufconn.
func setupGRPCTestEnvironment(t *testing.T, chain *pipeline.Chain) (*grpc.ClientConn, func()) {
	// 1. Upstream gRPC Server
	upstreamLis := bufconn.Listen(1024 * 1024)
	upstreamServer := grpc.NewServer(grpc.ForceServerCodec(egressgrpc.RawCodec{}))

	upstreamServer.RegisterService(&grpc.ServiceDesc{
		ServiceName: "test.TestService",
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Unary",
				Handler: func(srv any, ctx context.Context, dec func(any) error, interp grpc.UnaryServerInterceptor) (any, error) {
					var in egressgrpc.Frame
					if err := dec(&in); err != nil {
						return nil, err
					}

					md, _ := metadata.FromIncomingContext(ctx)
					if len(md.Get("fail-status")) > 0 {
						return nil, status.Error(codes.NotFound, "requested entity not found")
					}

					_ = grpc.SendHeader(ctx, metadata.Pairs("x-upstream-header", "torana-upstream"))
					_ = grpc.SetTrailer(ctx, metadata.Pairs("x-upstream-trailer", "trailer-ok"))

					respPayload := append([]byte("reply:"), in.Payload...)
					return &egressgrpc.Frame{Payload: respPayload}, nil
				},
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "ServerStream",
				ServerStreams: true,
				Handler: func(srv any, stream grpc.ServerStream) error {
					var in egressgrpc.Frame
					if err := stream.RecvMsg(&in); err != nil {
						return err
					}
					for i := 1; i <= 3; i++ {
						reply := fmt.Sprintf("%s-chunk%d", string(in.Payload), i)
						if err := stream.SendMsg(&egressgrpc.Frame{Payload: []byte(reply)}); err != nil {
							return err
						}
					}
					return nil
				},
			},
			{
				StreamName:    "ClientStream",
				ClientStreams: true,
				Handler: func(srv any, stream grpc.ServerStream) error {
					totalLen := 0
					for {
						var in egressgrpc.Frame
						err := stream.RecvMsg(&in)
						if errors.Is(err, io.EOF) {
							break
						}
						if err != nil {
							return err
						}
						totalLen += len(in.Payload)
					}
					summary := fmt.Sprintf("received:%d bytes", totalLen)
					return stream.SendMsg(&egressgrpc.Frame{Payload: []byte(summary)})
				},
			},
			{
				StreamName:    "BidiStream",
				ServerStreams: true,
				ClientStreams: true,
				Handler: func(srv any, stream grpc.ServerStream) error {
					for {
						var in egressgrpc.Frame
						err := stream.RecvMsg(&in)
						if errors.Is(err, io.EOF) {
							return nil
						}
						if err != nil {
							return err
						}
						echo := append([]byte("echo:"), in.Payload...)
						if err := stream.SendMsg(&egressgrpc.Frame{Payload: echo}); err != nil {
							return err
						}
					}
				},
			},
		},
	}, nil)

	go func() {
		_ = upstreamServer.Serve(upstreamLis)
	}()

	upstreamConn, err := grpc.NewClient("passthrough://bufnet-upstream",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return upstreamLis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(egressgrpc.RawCodec{})),
	)
	if err != nil {
		t.Fatalf("failed to connect to upstream bufconn: %v", err)
	}

	// 2. Gateway Snapshot
	holder := config.NewSnapshotHolder()
	snap := &config.Snapshot{
		Version: 1,
		Routes: []config.RouteRule{
			{
				ID:         "r-grpc",
				Path:       "/test.TestService/",
				PathPrefix: true,
				Method:     "POST",
				UpstreamID: "u-grpc",
			},
		},
		Upstreams: map[string]config.UpstreamCluster{
			"u-grpc": {
				ID:        "u-grpc",
				Protocol:  "grpc",
				Endpoints: []string{"bufnet-upstream"},
			},
		},
	}
	_ = holder.Store(snap)

	// 3. Egress Registry & Client with pre-injected upstream connection
	egressReg := egress.NewRegistry()
	grpcEgress := egressgrpc.NewClient()
	grpcEgress.SetConnForCluster("u-grpc", upstreamConn)
	egressReg.Register("grpc", grpcEgress)

	// 4. Ingress Listener via bufconn
	cfg := &config.BootstrapConfig{
		ListenGRPC: ":9090",
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ingressLsnr := ingressgrpc.NewListener(cfg, holder, egressReg, grpcEgress, chain, logger)

	gatewayLis := bufconn.Listen(1024 * 1024)
	go func() {
		_ = ingressLsnr.Server().Serve(gatewayLis)
	}()

	clientConn, err := grpc.NewClient("passthrough://bufnet-gateway",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return gatewayLis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(egressgrpc.RawCodec{})),
	)
	if err != nil {
		t.Fatalf("failed to connect to gateway bufconn: %v", err)
	}

	cleanup := func() {
		_ = clientConn.Close()
		ingressLsnr.Server().Stop()
		_ = gatewayLis.Close()
		_ = upstreamConn.Close()
		upstreamServer.Stop()
		_ = upstreamLis.Close()
		_ = grpcEgress.Close()
	}

	return clientConn, cleanup
}

func TestGRPCProxy_UnaryWithMetadataAndTrailers(t *testing.T) {
	chain := pipeline.NewChain()
	conn, cleanup := setupGRPCTestEnvironment(t, chain)
	defer cleanup()

	ctx := metadata.AppendToOutgoingContext(context.Background(), "x-test-client", "torana-client")
	var headerMD, trailerMD metadata.MD

	var in egressgrpc.Frame
	in.Payload = []byte("hello-torana")
	var out egressgrpc.Frame

	err := conn.Invoke(ctx, "/test.TestService/Unary", &in, &out,
		grpc.Header(&headerMD),
		grpc.Trailer(&trailerMD),
		grpc.ForceCodec(egressgrpc.RawCodec{}),
	)
	if err != nil {
		t.Fatalf("unary invoke failed: %v", err)
	}

	expected := "reply:hello-torana"
	if string(out.Payload) != expected {
		t.Errorf("expected payload %q, got %q", expected, string(out.Payload))
	}

	if vals := headerMD.Get("x-upstream-header"); len(vals) == 0 || vals[0] != "torana-upstream" {
		t.Errorf("expected header x-upstream-header=torana-upstream, got %v", headerMD)
	}
	if vals := trailerMD.Get("x-upstream-trailer"); len(vals) == 0 || vals[0] != "trailer-ok" {
		t.Errorf("expected trailer x-upstream-trailer=trailer-ok, got %v", trailerMD)
	}
}

func TestGRPCProxy_ServerStreaming(t *testing.T) {
	chain := pipeline.NewChain()
	conn, cleanup := setupGRPCTestEnvironment(t, chain)
	defer cleanup()

	desc := &grpc.StreamDesc{
		StreamName:    "ServerStream",
		ServerStreams: true,
	}
	stream, err := conn.NewStream(context.Background(), desc, "/test.TestService/ServerStream", grpc.ForceCodec(egressgrpc.RawCodec{}))
	if err != nil {
		t.Fatalf("failed to create server stream: %v", err)
	}

	if err := stream.SendMsg(&egressgrpc.Frame{Payload: []byte("item")}); err != nil {
		t.Fatalf("sendMsg failed: %v", err)
	}
	_ = stream.CloseSend()

	var chunks []string
	for {
		var out egressgrpc.Frame
		err := stream.RecvMsg(&out)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("recvMsg error: %v", err)
		}
		chunks = append(chunks, string(out.Payload))
	}

	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks, got %d: %v", len(chunks), chunks)
	}
	if chunks[0] != "item-chunk1" || chunks[1] != "item-chunk2" || chunks[2] != "item-chunk3" {
		t.Errorf("unexpected chunk sequence: %v", chunks)
	}
}

func TestGRPCProxy_ClientStreaming(t *testing.T) {
	chain := pipeline.NewChain()
	conn, cleanup := setupGRPCTestEnvironment(t, chain)
	defer cleanup()

	desc := &grpc.StreamDesc{
		StreamName:    "ClientStream",
		ClientStreams: true,
	}
	stream, err := conn.NewStream(context.Background(), desc, "/test.TestService/ClientStream", grpc.ForceCodec(egressgrpc.RawCodec{}))
	if err != nil {
		t.Fatalf("failed to create client stream: %v", err)
	}

	for i := 1; i <= 5; i++ {
		msg := fmt.Sprintf("frame-%d", i)
		if err := stream.SendMsg(&egressgrpc.Frame{Payload: []byte(msg)}); err != nil {
			t.Fatalf("failed to send frame %d: %v", i, err)
		}
	}
	_ = stream.CloseSend()

	var out egressgrpc.Frame
	if err := stream.RecvMsg(&out); err != nil {
		t.Fatalf("failed to receive summary from upstream: %v", err)
	}

	expected := "received:35 bytes"
	if string(out.Payload) != expected {
		t.Errorf("expected summary %q, got %q", expected, string(out.Payload))
	}
}

func TestGRPCProxy_BidirectionalStreaming(t *testing.T) {
	chain := pipeline.NewChain()
	conn, cleanup := setupGRPCTestEnvironment(t, chain)
	defer cleanup()

	desc := &grpc.StreamDesc{
		StreamName:    "BidiStream",
		ServerStreams: true,
		ClientStreams: true,
	}
	stream, err := conn.NewStream(context.Background(), desc, "/test.TestService/BidiStream", grpc.ForceCodec(egressgrpc.RawCodec{}))
	if err != nil {
		t.Fatalf("failed to create bidi stream: %v", err)
	}

	for i := 1; i <= 3; i++ {
		msg := fmt.Sprintf("ping-%d", i)
		if err := stream.SendMsg(&egressgrpc.Frame{Payload: []byte(msg)}); err != nil {
			t.Fatalf("send failed: %v", err)
		}

		var out egressgrpc.Frame
		if err := stream.RecvMsg(&out); err != nil {
			t.Fatalf("recv failed: %v", err)
		}
		expected := fmt.Sprintf("echo:ping-%d", i)
		if string(out.Payload) != expected {
			t.Errorf("expected %q, got %q", expected, string(out.Payload))
		}
	}
	_ = stream.CloseSend()
}

func TestGRPCProxy_UpstreamStatusPassThrough(t *testing.T) {
	chain := pipeline.NewChain()
	conn, cleanup := setupGRPCTestEnvironment(t, chain)
	defer cleanup()

	ctx := metadata.AppendToOutgoingContext(context.Background(), "fail-status", "true")

	var in egressgrpc.Frame
	in.Payload = []byte("fail")
	var out egressgrpc.Frame

	err := conn.Invoke(ctx, "/test.TestService/Unary", &in, &out, grpc.ForceCodec(egressgrpc.RawCodec{}))
	if err == nil {
		t.Fatalf("expected error from upstream, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.NotFound {
		t.Errorf("expected codes.NotFound, got %v", st.Code())
	}
	if st.Message() != "requested entity not found" {
		t.Errorf("expected error message 'requested entity not found', got %q", st.Message())
	}
}

// mockHaltFilter simulates an authn/authz filter rejecting unauthorized requests or rate limiting.
type mockHaltFilter struct {
	statusCode int
	reason     string
	headers    map[string]string
}

func (m *mockHaltFilter) Name() string                         { return "mock_halt" }
func (m *mockHaltFilter) Phase() pipeline.Phase                { return pipeline.PhaseRequestHeaders }
func (m *mockHaltFilter) BodyMode() pipeline.BodyMode          { return pipeline.BodyModeNone }
func (m *mockHaltFilter) FailurePolicy() pipeline.FailurePolicy { return pipeline.FailurePolicyFailClosed }
func (m *mockHaltFilter) Close() error                         { return nil }
func (m *mockHaltFilter) Process(ctx context.Context, env *pipeline.Envelope) (pipeline.Decision, error) {
	d := pipeline.HaltDecision(m.statusCode, m.reason)
	d.MutateHeaders = m.headers
	return d, errors.New(m.reason)
}

func TestGRPCProxy_PipelineFilterHaltMapping(t *testing.T) {
	t.Run("401 Unauthorized maps to codes.Unauthenticated", func(t *testing.T) {
		chain := pipeline.NewChain(&mockHaltFilter{
			statusCode: 401,
			reason:     "invalid or expired bearer token",
		})
		conn, cleanup := setupGRPCTestEnvironment(t, chain)
		defer cleanup()

		var in, out egressgrpc.Frame
		err := conn.Invoke(context.Background(), "/test.TestService/Unary", &in, &out, grpc.ForceCodec(egressgrpc.RawCodec{}))
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.Unauthenticated {
			t.Errorf("expected codes.Unauthenticated, got %v (%v)", st.Code(), err)
		}
	})

	t.Run("403 Forbidden maps to codes.PermissionDenied", func(t *testing.T) {
		chain := pipeline.NewChain(&mockHaltFilter{
			statusCode: 403,
			reason:     "cel policy denied access to route",
		})
		conn, cleanup := setupGRPCTestEnvironment(t, chain)
		defer cleanup()

		var in, out egressgrpc.Frame
		err := conn.Invoke(context.Background(), "/test.TestService/Unary", &in, &out, grpc.ForceCodec(egressgrpc.RawCodec{}))
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.PermissionDenied {
			t.Errorf("expected codes.PermissionDenied, got %v (%v)", st.Code(), err)
		}
	})

	t.Run("429 TooManyRequests maps to codes.ResourceExhausted with retry-after trailer", func(t *testing.T) {
		chain := pipeline.NewChain(&mockHaltFilter{
			statusCode: 429,
			reason:     "token budget exceeded for window",
			headers: map[string]string{
				"Retry-After": "30",
			},
		})
		conn, cleanup := setupGRPCTestEnvironment(t, chain)
		defer cleanup()

		var in, out egressgrpc.Frame
		var trailerMD metadata.MD
		err := conn.Invoke(context.Background(), "/test.TestService/Unary", &in, &out, grpc.Trailer(&trailerMD), grpc.ForceCodec(egressgrpc.RawCodec{}))
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.ResourceExhausted {
			t.Errorf("expected codes.ResourceExhausted, got %v (%v)", st.Code(), err)
		}
		if vals := trailerMD.Get("retry-after"); len(vals) == 0 || vals[0] != "30" {
			t.Errorf("expected trailer retry-after=30, got %v", trailerMD)
		}
	})
}

func BenchmarkGRPCProxy_Unary(b *testing.B) {
	chain := pipeline.NewChain()
	conn, cleanup := setupGRPCTestEnvironment(&testing.T{}, chain)
	defer cleanup()

	ctx := context.Background()
	var in egressgrpc.Frame
	in.Payload = []byte("benchmark-payload-bytes")
	var out egressgrpc.Frame

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = conn.Invoke(ctx, "/test.TestService/Unary", &in, &out, grpc.ForceCodec(egressgrpc.RawCodec{}))
	}
}
