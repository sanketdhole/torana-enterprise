package ingress

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/egress"
	"github.com/phaselume/torana/internal/ingress/a2a"
	"github.com/phaselume/torana/internal/ingress/mcp"
	"github.com/phaselume/torana/internal/ingress/ws"
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
	wsHandler  *ws.Handler
	mcpHandler *mcp.Handler
	a2aHandler *a2a.Handler
}

// SetWSHandler configures the WebSocket upgrade handler.
func (l *HTTPListener) SetWSHandler(h *ws.Handler) {
	l.wsHandler = h
}

// SetMCPHandler configures the Model Context Protocol handler.
func (l *HTTPListener) SetMCPHandler(h *mcp.Handler) {
	l.mcpHandler = h
}

// SetA2AHandler configures the Agent-to-Agent protocol handler.
func (l *HTTPListener) SetA2AHandler(h *a2a.Handler) {
	l.a2aHandler = h
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

// ServeHTTP implements http.Handler for testing and direct dispatch.
func (l *HTTPListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.server.Handler.ServeHTTP(w, r)
}

// Server returns the underlying http.Server.
func (l *HTTPListener) Server() *http.Server {
	return l.server
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

// handleGateway processes hot-path requests with pooled envelopes and SSE flushes.
func (l *HTTPListener) handleGateway(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// 1. Fetch pre-compiled router atomically
	rtr := l.routerPtr.Load()
	if rtr == nil {
		http.Error(w, `{"error":"gateway not ready"}`, http.StatusServiceUnavailable)
		return
	}

	// 2. Extract matching criteria with zero allocations on hot path
	criteria := router.MatchCriteria{
		Host:   r.Host,
		Method: r.Method,
		Path:   r.URL.Path,
		Header: r.Header,
	}

	var claimsMap map[string]string
	if claimHdr := r.Header.Get("X-Identity-Claims"); claimHdr != "" {
		claimsMap = make(map[string]string)
		for _, pair := range strings.Split(claimHdr, ",") {
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) == 2 {
				claimsMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
		criteria.Claims = claimsMap
	}

	// 3. Lock-free route resolution
	match, err := rtr.Match(criteria)
	if err != nil {
		http.Error(w, `{"error":"route not found"}`, http.StatusNotFound)
		return
	}

	// 4. Get recycled Envelope from pool
	env := pipeline.GetEnvelope(
		r.Header.Get("X-Request-ID"),
		pipeline.PhaseRequestHeaders,
		r.Method,
		r.URL.Path,
		r.Header,
		r.Body,
	)
	defer pipeline.PutEnvelope(env)

	env.Route = match.Route
	env.Upstream = match.Upstream
	env.Claims = claimsMap
	env.PeerInfo = pipeline.PeerInfo{
		RemoteIP: r.RemoteAddr,
		Protocol: r.Proto,
		TLS:      r.TLS,
	}

	// 5. Run Phase 0: Authn
	if l.chain != nil {
		decision, err := l.chain.ExecutePhase(r.Context(), env, pipeline.PhaseAuthn, 0)
		if err != nil || decision.Action == pipeline.ActionHalt || decision.Action == pipeline.ActionDrop {
			l.handleHalt(w, env, decision, startTime, err)
			return
		}
	}

	// 6. Run Phase 1: Request Headers
	if l.chain != nil {
		decision, err := l.chain.ExecutePhase(r.Context(), env, pipeline.PhaseRequestHeaders, 0)
		if err != nil || decision.Action == pipeline.ActionHalt || decision.Action == pipeline.ActionDrop {
			l.handleHalt(w, env, decision, startTime, err)
			return
		}
	}

	// Check for WebSocket upgrade
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") && l.wsHandler != nil {
		l.wsHandler.Handle(w, r, &match, env)
		l.emitTelemetry(env, http.StatusSwitchingProtocols, time.Since(startTime), "")
		return
	}

	// Check for MCP protocol
	if l.mcpHandler != nil && (match.Upstream.Protocol == "mcp" || r.Header.Get("Mcp-Session-Id") != "" || strings.HasSuffix(r.URL.Path, "/sse")) {
		l.mcpHandler.ServeHTTP(w, r, match.Upstream, env)
		l.emitTelemetry(env, http.StatusOK, time.Since(startTime), "")
		return
	}

	// Check for A2A protocol
	if l.a2aHandler != nil && (match.Upstream.Protocol == "a2a" || strings.HasPrefix(r.URL.Path, "/.well-known/agent") || strings.Contains(r.URL.Path, "/tasks") || strings.Contains(r.URL.Path, "/messages")) {
		l.a2aHandler.ServeHTTP(w, r, match.Upstream, env)
		l.emitTelemetry(env, http.StatusOK, time.Since(startTime), "")
		return
	}

	// 6. Run Phase 2: Request Body
	if l.chain != nil {
		decision, err := l.chain.ExecutePhase(r.Context(), env, pipeline.PhaseRequestBody, 0)
		if err != nil || decision.Action == pipeline.ActionHalt || decision.Action == pipeline.ActionDrop {
			l.handleHalt(w, env, decision, startTime, err)
			return
		}
	}

	// 7. Resolve Egress Client
	egressClient, err := l.egressReg.Get(match.Upstream.Protocol)
	if err != nil {
		http.Error(w, `{"error":"upstream protocol unsupported"}`, http.StatusBadGateway)
		l.emitTelemetry(env, http.StatusBadGateway, time.Since(startTime), err.Error())
		return
	}

	// 8. Egress invocation
	egressReq := &egress.Request{
		Method:      env.Method,
		Path:        env.Path,
		Headers:     env.Headers,
		Body:        env.Body,
		Timeout:     match.Route.Timeout,
		RetryPolicy: match.RetryPolicy,
	}

	resp, err := egressClient.Execute(r.Context(), match.Upstream, egressReq)
	if err != nil {
		http.Error(w, `{"error":"upstream call failed"}`, http.StatusBadGateway)
		l.emitTelemetry(env, http.StatusBadGateway, time.Since(startTime), err.Error())
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// 9. Run Phase 3: Response Headers
	if l.chain != nil {
		respEnv := pipeline.GetEnvelope(env.RequestID, pipeline.PhaseResponseHeaders, env.Method, env.Path, resp.Headers, resp.Body)
		defer pipeline.PutEnvelope(respEnv)

		decision, err := l.chain.ExecutePhase(r.Context(), respEnv, pipeline.PhaseResponseHeaders, 0)
		if err != nil || decision.Action == pipeline.ActionHalt || decision.Action == pipeline.ActionDrop {
			l.handleHalt(w, env, decision, startTime, err)
			return
		}
	}

	// 10. Copy response headers to client
	for k, vv := range resp.Headers {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// 11. Streaming pass-through with flusher for SSE (text/event-stream) and chunked bodies
	flusher, isFlusher := w.(http.Flusher)
	isSSE := strings.Contains(resp.Headers.Get("Content-Type"), "text/event-stream")

	bufPtr := pipeline.GetBuffer()
	defer pipeline.PutBuffer(bufPtr)
	buf := *bufPtr

	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			_, _ = w.Write(buf[:n])
			if isFlusher && (isSSE || n < len(buf)) {
				flusher.Flush()
			}
		}
		if readErr != nil {
			break
		}
	}

	// 12. Emit telemetry metadata
	l.emitTelemetry(env, resp.StatusCode, time.Since(startTime), "")
}

func (l *HTTPListener) handleHalt(w http.ResponseWriter, env *pipeline.Envelope, d pipeline.Decision, start time.Time, err error) {
	status := d.StatusCode
	if status == 0 {
		status = http.StatusForbidden
	}
	msg := d.Reason
	if msg == "" && err != nil {
		msg = err.Error()
	}
	http.Error(w, fmt.Sprintf(`{"error":%q}`, msg), status)
	l.emitTelemetry(env, status, time.Since(start), msg)
}

func (l *HTTPListener) emitTelemetry(env *pipeline.Envelope, status int, duration time.Duration, errStr string) {
	if l.emitter == nil {
		return
	}

	routeID := ""
	upstreamID := ""
	if env.Route != nil {
		routeID = env.Route.ID
	}
	if env.Upstream != nil {
		upstreamID = env.Upstream.ID
	}

	tenantID, _ := env.GetMetadata("tenant_id")
	model, _ := env.GetMetadata("model")

	l.emitter.Emit(telemetry.Event{
		Timestamp:  env.StartTime,
		RouteID:    routeID,
		UpstreamID: upstreamID,
		Method:     env.Method,
		Path:       env.Path,
		StatusCode: status,
		DurationMs: duration.Milliseconds(),
		Model:      model,
		TenantID:   tenantID,
		Error:      errStr,
		CustomMeta: env.Metadata,
	})
}
