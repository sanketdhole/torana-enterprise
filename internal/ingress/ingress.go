package ingress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/egress"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/router"
	"github.com/phaselume/torana/internal/telemetry"
)

var (
	// ErrServerClosed is returned when the listener is closed.
	ErrServerClosed = http.ErrServerClosed
)

// Listener defines the lifecycle for an ingress protocol listener (HTTP, gRPC, WS, MCP, A2A).
type Listener interface {
	Protocol() string
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// HTTPListener handles incoming HTTP/1.1 & HTTP/2 ingress traffic.
type HTTPListener struct {
	addr       string
	server     *http.Server
	holder     *config.SnapshotHolder
	egressReg  *egress.Registry
	emitter    *telemetry.Emitter
	logger     *slog.Logger
	chain      *pipeline.Chain
	ready      atomic.Bool
	routerPtr  atomic.Pointer[router.Router]
}

// NewHTTPListener creates an HTTP ingress listener.
func NewHTTPListener(
	cfg *config.BootstrapConfig,
	holder *config.SnapshotHolder,
	egressReg *egress.Registry,
	emitter *telemetry.Emitter,
	chain *pipeline.Chain,
	logger *slog.Logger,
) *HTTPListener {
	hl := &HTTPListener{
		addr:      cfg.HTTPAddress(),
		holder:    holder,
		egressReg: egressReg,
		emitter:   emitter,
		chain:     chain,
		logger:    logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", hl.handleHealthz)
	mux.HandleFunc("GET /readyz", hl.handleReadyz)
	mux.HandleFunc("/", hl.handleGateway)

	hl.server = &http.Server{
		Addr:         hl.addr,
		Handler:      mux,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	return hl
}

// Protocol returns "http".
func (l *HTTPListener) Protocol() string {
	return "http"
}

// UpdateRouter atomically updates the pre-compiled router.
func (l *HTTPListener) UpdateRouter(r *router.Router) {
	l.routerPtr.Store(r)
}

// SetReady marks the listener as ready to serve traffic.
func (l *HTTPListener) SetReady(ready bool) {
	l.ready.Store(ready)
}

// Start runs the HTTP server.
func (l *HTTPListener) Start(_ context.Context) error {
	l.logger.Info("starting http ingress listener", "addr", l.addr)
	err := l.server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http ingress error: %w", err)
	}
	return nil
}

// Stop gracefully shuts down the listener.
func (l *HTTPListener) Stop(ctx context.Context) error {
	l.SetReady(false)
	l.logger.Info("stopping http ingress listener")
	return l.server.Shutdown(ctx)
}

func (l *HTTPListener) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"UP"}`))
}

func (l *HTTPListener) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if !l.ready.Load() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status":"NOT_READY"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"READY"}`))
}

// handleGateway processes the hot-path gateway requests.
func (l *HTTPListener) handleGateway(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// 1. Hot path lock-free router fetch
	rtr := l.routerPtr.Load()
	if rtr == nil {
		http.Error(w, `{"error":"gateway not ready"}`, http.StatusServiceUnavailable)
		return
	}

	// 2. Lock-free route resolution
	match, err := rtr.Match(r.Method, r.URL.Path)
	if err != nil {
		http.Error(w, `{"error":"route not found"}`, http.StatusNotFound)
		return
	}

	// 3. Build RequestContext
	reqCtx := pipeline.NewRequestContext(r.Context(), r.Method, r.URL.Path, r.Header.Clone(), r.Body)
	reqCtx.Route = match.Route
	reqCtx.Upstream = match.Upstream

	// 4. Run Filter Chain (authn, authz, ratelimit, etc.)
	if l.chain != nil {
		if err := l.chain.Execute(reqCtx); err != nil {
			status := http.StatusForbidden
			if errors.Is(err, pipeline.ErrUnauthorized) {
				status = http.StatusUnauthorized
			}
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), status)

			// Emit telemetry event for rejected request
			l.emitTelemetry(reqCtx, status, time.Since(startTime), err.Error())
			return
		}
	}

	// 5. Fetch egress client by upstream protocol
	egressClient, err := l.egressReg.Get(match.Upstream.Protocol)
	if err != nil {
		http.Error(w, `{"error":"upstream protocol unsupported"}`, http.StatusBadGateway)
		l.emitTelemetry(reqCtx, http.StatusBadGateway, time.Since(startTime), err.Error())
		return
	}

	// 6. Execute Egress invocation with streaming body
	egressReq := &egress.Request{
		Method:  reqCtx.Method,
		Path:    reqCtx.Path,
		Headers: reqCtx.Headers,
		Body:    reqCtx.RequestBody,
		Timeout: match.Route.Timeout,
	}

	resp, err := egressClient.Execute(reqCtx.Ctx, match.Upstream, egressReq)
	if err != nil {
		http.Error(w, `{"error":"upstream call failed"}`, http.StatusBadGateway)
		l.emitTelemetry(reqCtx, http.StatusBadGateway, time.Since(startTime), err.Error())
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// 7. Stream response headers and body back to client
	for k, vv := range resp.Headers {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	_, _ = io.Copy(w, resp.Body)

	// 8. Emit telemetry metadata
	l.emitTelemetry(reqCtx, resp.StatusCode, time.Since(startTime), "")
}

func (l *HTTPListener) emitTelemetry(reqCtx *pipeline.RequestContext, status int, duration time.Duration, errStr string) {
	if l.emitter == nil {
		return
	}

	routeID := ""
	upstreamID := ""
	if reqCtx.Route != nil {
		routeID = reqCtx.Route.ID
	}
	if reqCtx.Upstream != nil {
		upstreamID = reqCtx.Upstream.ID
	}

	tenantID, _ := reqCtx.GetMetadata("tenant_id")
	model, _ := reqCtx.GetMetadata("model")

	l.emitter.Emit(telemetry.Event{
		Timestamp:  reqCtx.StartTime,
		RouteID:    routeID,
		UpstreamID: upstreamID,
		Method:     reqCtx.Method,
		Path:       reqCtx.Path,
		StatusCode: status,
		DurationMs: duration.Milliseconds(),
		Model:      model,
		TenantID:   tenantID,
		Error:      errStr,
		CustomMeta: reqCtx.Metadata,
	})
}
