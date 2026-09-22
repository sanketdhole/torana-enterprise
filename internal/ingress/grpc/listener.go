package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/egress"
	egressgrpc "github.com/phaselume/torana/internal/egress/grpc"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/router"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Listener manages the gRPC ingress protocol listener.
type Listener struct {
	addr       string
	server     *grpc.Server
	holder     *config.SnapshotHolder
	egressReg  *egress.Registry
	grpcEgress *egressgrpc.Client
	chain      *pipeline.Chain
	logger     *slog.Logger
	routerPtr  atomic.Pointer[router.Router]
	ready      atomic.Bool
}

// NewListener creates a new protocol-agnostic gRPC ingress listener.
func NewListener(
	cfg *config.BootstrapConfig,
	holder *config.SnapshotHolder,
	egressReg *egress.Registry,
	grpcEgress *egressgrpc.Client,
	chain *pipeline.Chain,
	logger *slog.Logger,
) *Listener {
	l := &Listener{
		addr:       cfg.GRPCAddress(),
		holder:     holder,
		egressReg:  egressReg,
		grpcEgress: grpcEgress,
		chain:      chain,
		logger:     logger,
	}

	srv := grpc.NewServer(
		grpc.ForceServerCodec(egressgrpc.RawCodec{}),
		grpc.UnknownServiceHandler(l.unknownServiceHandler),
	)
	l.server = srv
	return l
}

// Protocol returns "grpc".
func (l *Listener) Protocol() string {
	return "grpc"
}

// Server returns the underlying grpc.Server.
func (l *Listener) Server() *grpc.Server {
	return l.server
}

// UpdateRouter updates the active compiled router.
func (l *Listener) UpdateRouter(r *router.Router) {
	l.routerPtr.Store(r)
}

// SetReady sets the readiness flag.
func (l *Listener) SetReady(ready bool) {
	l.ready.Store(ready)
}

// Start starts listening and serving gRPC requests.
func (l *Listener) Start(ctx context.Context) error {
	lis, err := net.Listen("tcp", l.addr)
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC address %s: %w", l.addr, err)
	}

	if l.logger != nil {
		l.logger.Info("started gRPC ingress listener", "addr", l.addr)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := l.server.Serve(lis); err != nil && err != grpc.ErrServerStopped {
			errChan <- err
		}
	}()

	select {
	case <-ctx.Done():
		return l.Stop(context.Background())
	case err := <-errChan:
		return err
	}
}

// Stop gracefully stops the gRPC server.
func (l *Listener) Stop(ctx context.Context) error {
	stopped := make(chan struct{})
	go func() {
		l.server.GracefulStop()
		close(stopped)
	}()

	select {
	case <-stopped:
		return nil
	case <-ctx.Done():
		l.server.Stop()
		return ctx.Err()
	}
}

// unknownServiceHandler intercepts all incoming gRPC calls (unary & streaming).
func (l *Listener) unknownServiceHandler(srv any, serverStream grpc.ServerStream) error {
	method, ok := grpc.MethodFromServerStream(serverStream)
	if !ok {
		return status.Error(codes.InvalidArgument, "unable to determine gRPC method")
	}

	ctx := serverStream.Context()

	// 1. Extract metadata from stream context
	incomingMD, _ := metadata.FromIncomingContext(ctx)
	headers := make(http.Header)
	for k, vv := range incomingMD {
		for _, v := range vv {
			headers.Add(k, v)
		}
	}

	// 2. Route matching
	var routeRule *config.RouteRule
	var upstreamCluster *config.UpstreamCluster

	rtr := l.routerPtr.Load()
	if rtr != nil {
		criteria := router.MatchCriteria{
			Method: "POST",
			Path:   method,
			Header: headers,
		}
		match, err := rtr.Match(criteria)
		if err != nil {
			return status.Errorf(codes.NotFound, "route not found for gRPC method: %s", method)
		}
		routeRule = match.Route
		upstreamCluster = match.Upstream
	} else if l.holder != nil && l.holder.HasSnapshot() {
		snap, err := l.holder.Load()
		if err == nil && snap != nil {
			for _, r := range snap.Routes {
				if r.Path == method || (r.PathPrefix && strings.HasPrefix(method, r.Path)) {
					rCopy := r
					routeRule = &rCopy
					if up, ok := snap.Upstreams[r.UpstreamID]; ok {
						upCopy := up
						upstreamCluster = &upCopy
					}
					break
				}
			}
		}
	}

	if routeRule == nil || upstreamCluster == nil {
		return status.Errorf(codes.NotFound, "no route matching gRPC method: %s", method)
	}

	// 3. Map into pipeline.Envelope for authn, authz, and rate-limiting
	requestID := headers.Get("x-request-id")
	if requestID == "" {
		requestID = fmt.Sprintf("grpc-%d", time.Now().UnixNano())
	}

	env := pipeline.GetEnvelope(requestID, pipeline.PhaseRequestHeaders, "POST", method, headers, nil)
	defer pipeline.PutEnvelope(env)

	env.Route = routeRule
	env.Upstream = upstreamCluster
	env.PeerInfo = pipeline.PeerInfo{
		Protocol: "grpc",
	}

	// 4. Run PhaseAuthn
	if l.chain != nil {
		decision, err := l.chain.ExecutePhase(ctx, env, pipeline.PhaseAuthn, 0)
		if err != nil || decision.Action == pipeline.ActionHalt || decision.Action == pipeline.ActionDrop {
			return mapHaltToGRPC(decision, serverStream)
		}
	}

	// 5. Run PhaseRequestHeaders (Authz, limits, token budget pre-checks)
	if l.chain != nil {
		decision, err := l.chain.ExecutePhase(ctx, env, pipeline.PhaseRequestHeaders, 0)
		if err != nil || decision.Action == pipeline.ActionHalt || decision.Action == pipeline.ActionDrop {
			return mapHaltToGRPC(decision, serverStream)
		}
	}

	// 6. Forward to gRPC Egress Client
	egressClient := l.grpcEgress
	if egressClient == nil && l.egressReg != nil {
		if c, err := l.egressReg.Get("grpc"); err == nil {
			if gc, ok := c.(*egressgrpc.Client); ok {
				egressClient = gc
			}
		}
	}

	if egressClient == nil {
		return status.Error(codes.Unavailable, "grpc egress client unavailable")
	}

	return egressClient.ProxyStream(ctx, upstreamCluster, method, incomingMD, serverStream)
}

// mapHaltToGRPC maps pipeline decisions (HTTP status codes) to standard gRPC status codes.
func mapHaltToGRPC(d pipeline.Decision, stream grpc.ServerStream) error {
	var code codes.Code
	switch d.StatusCode {
	case http.StatusUnauthorized:
		code = codes.Unauthenticated
	case http.StatusForbidden:
		code = codes.PermissionDenied
	case http.StatusTooManyRequests:
		code = codes.ResourceExhausted
		if d.MutateHeaders != nil {
			if retryAfter, ok := d.MutateHeaders["Retry-After"]; ok {
				stream.SetTrailer(metadata.Pairs("retry-after", retryAfter))
			}
		}
	case http.StatusGatewayTimeout, http.StatusRequestTimeout:
		code = codes.DeadlineExceeded
	case http.StatusNotFound:
		code = codes.NotFound
	case http.StatusBadRequest:
		code = codes.InvalidArgument
	default:
		code = codes.Internal
	}

	reason := d.Reason
	if reason == "" {
		reason = http.StatusText(d.StatusCode)
	}
	return status.Error(code, reason)
}
