package ws

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/router"
	"github.com/phaselume/torana/internal/security/authn"
)

// Options configures WebSocket proxy timeouts and buffer capacities.
type Options struct {
	QueueCapacity int
	PingInterval  time.Duration
	PingTimeout   time.Duration
	IdleTimeout   time.Duration
	MaxLifetime   time.Duration
	WriteTimeout  time.Duration
}

// DefaultOptions returns production defaults for WebSocket proxying.
func DefaultOptions() Options {
	return Options{
		QueueCapacity: 128,
		PingInterval:  30 * time.Second,
		PingTimeout:   5 * time.Second,
		IdleTimeout:   60 * time.Second,
		MaxLifetime:   1 * time.Hour,
		WriteTimeout:  5 * time.Second,
	}
}

type wsMessage struct {
	msgType websocket.MessageType
	data    []byte
}

// Handler handles incoming WebSocket upgrade requests and proxies traffic.
type Handler struct {
	opts       Options
	chain      *pipeline.Chain
	revList    *authn.RevocationList
	logger     *slog.Logger
	httpClient *http.Client
}

// NewHandler creates a new WebSocket ingress handler.
func NewHandler(
	opts Options,
	chain *pipeline.Chain,
	revList *authn.RevocationList,
	logger *slog.Logger,
) *Handler {
	if opts.QueueCapacity <= 0 {
		opts.QueueCapacity = 128
	}
	if opts.PingInterval <= 0 {
		opts.PingInterval = 30 * time.Second
	}
	if opts.PingTimeout <= 0 {
		opts.PingTimeout = 5 * time.Second
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 60 * time.Second
	}
	if opts.MaxLifetime <= 0 {
		opts.MaxLifetime = 1 * time.Hour
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = 5 * time.Second
	}

	return &Handler{
		opts:    opts,
		chain:   chain,
		revList: revList,
		logger:  logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetHTTPClient overrides the HTTP client used for upstream websocket dials and HTTP backends.
func (h *Handler) SetHTTPClient(client *http.Client) {
	if client != nil {
		h.httpClient = client
	}
}

// isRevoked inspects the envelope for revoked credentials (token, key, or subject).
func (h *Handler) isRevoked(env *pipeline.Envelope) bool {
	if h.revList == nil || env == nil {
		return false
	}

	for k, vv := range env.Headers {
		if len(vv) == 0 {
			continue
		}
		val := vv[0]
		if strings.EqualFold(k, "Authorization") {
			tok := strings.TrimPrefix(val, "Bearer ")
			tok = strings.TrimSpace(tok)
			if h.revList.IsTokenRevoked(tok) || h.revList.IsRevoked(tok) {
				return true
			}
		} else if strings.EqualFold(k, "X-API-Key") {
			key := strings.TrimSpace(val)
			if h.revList.IsKeyRevoked(key) || h.revList.IsRevoked(key) {
				return true
			}
		}
	}

	// 3. Check Claims (jti, sub)
	if jti, ok := env.Claims["jti"]; ok && jti != "" {
		if h.revList.IsTokenRevoked(jti) || h.revList.IsRevoked(jti) {
			return true
		}
	}
	if sub, ok := env.Claims["sub"]; ok && sub != "" {
		if h.revList.IsRevoked(sub) {
			return true
		}
	}

	// 4. Check Identity struct if set
	if ident, ok := env.Identity.(*authn.Identity); ok && ident != nil {
		if h.revList.IsRevoked(ident.Subject) {
			return true
		}
	}

	return false
}

// applyChunkHooks runs all registered ChunkHook filters over a raw frame payload.
func (h *Handler) applyChunkHooks(ctx context.Context, env *pipeline.Envelope, chunk []byte) ([]byte, error) {
	if h.chain == nil {
		return chunk, nil
	}
	current := chunk
	for _, f := range h.chain.Filters() {
		if hook, ok := f.(pipeline.ChunkHook); ok {
			modified, err := hook.OnChunk(ctx, env, current)
			if err != nil {
				return nil, err
			}
			current = modified
		}
	}
	return current, nil
}

// IsRevoked inspects the envelope for revoked credentials (token, key, or subject).
func (h *Handler) IsRevoked(env *pipeline.Envelope) bool {
	return h.isRevoked(env)
}

// ApplyChunkHooks runs all registered ChunkHook filters over a raw frame payload.
func (h *Handler) ApplyChunkHooks(ctx context.Context, env *pipeline.Envelope, chunk []byte) ([]byte, error) {
	return h.applyChunkHooks(ctx, env, chunk)
}

// Handle upgrades the HTTP connection to WebSocket and initiates proxying.
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request, match *router.MatchResult, env *pipeline.Envelope) {
	// Re-verify revocation before accepting upgrade
	if h.isRevoked(env) {
		http.Error(w, `{"error":"unauthorized: credential revoked"}`, http.StatusUnauthorized)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		if h.logger != nil {
			h.logger.Error("failed to accept websocket upgrade", "error", err)
		}
		return
	}
	defer conn.Close(websocket.StatusInternalError, "connection closed")

	// Apply MaxLifetime constraint
	connCtx, cancel := context.WithTimeout(r.Context(), h.opts.MaxLifetime)
	defer cancel()

	// Track idle timeout via atomic unix timestamp
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())

	// 1. Live Revocation Monitor: Closes connection immediately if credential is added to RevocationList
	if h.revList != nil {
		subCh, unsub := h.revList.Subscribe()
		defer unsub()
		go func() {
			for {
				select {
				case <-connCtx.Done():
					return
				case <-subCh:
					if h.isRevoked(env) {
						if h.logger != nil {
							h.logger.Warn("closing active websocket connection due to live credential revocation", "path", r.URL.Path)
						}
						_ = conn.Close(websocket.StatusPolicyViolation, "credential revoked")
						cancel()
						return
					}
				}
			}
		}()
	}

	// 2. Ping/Pong Keepalive Loop
	go func() {
		ticker := time.NewTicker(h.opts.PingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-connCtx.Done():
				return
			case <-ticker.C:
				pingCtx, pingCancel := context.WithTimeout(connCtx, h.opts.PingTimeout)
				if err := conn.Ping(pingCtx); err != nil {
					pingCancel()
					if h.logger != nil {
						h.logger.Debug("websocket ping failed, closing connection", "error", err)
					}
					_ = conn.Close(websocket.StatusGoingAway, "ping timeout")
					cancel()
					return
				}
				pingCancel()
				lastActivity.Store(time.Now().UnixNano())
			}
		}
	}()

	// 3. Idle Timeout Monitor
	go func() {
		ticker := time.NewTicker(h.opts.IdleTimeout / 2)
		defer ticker.Stop()
		for {
			select {
			case <-connCtx.Done():
				return
			case <-ticker.C:
				last := time.Unix(0, lastActivity.Load())
				if time.Since(last) > h.opts.IdleTimeout {
					if h.logger != nil {
						h.logger.Info("websocket connection idle timeout exceeded", "path", r.URL.Path)
					}
					_ = conn.Close(websocket.StatusNormalClosure, "idle timeout")
					cancel()
					return
				}
			}
		}
	}()

	// Check upstream protocol
	upstreamProto := strings.ToLower(match.Upstream.Protocol)
	isHTTPBackend := upstreamProto == "http" || upstreamProto == "https"
	if len(match.Upstream.Endpoints) > 0 {
		ep := match.Upstream.Endpoints[0]
		if strings.HasPrefix(ep, "http://") || strings.HasPrefix(ep, "https://") {
			if upstreamProto != "ws" && upstreamProto != "wss" {
				isHTTPBackend = true
			}
		}
	}

	if isHTTPBackend {
		h.proxyToHTTPBackend(connCtx, conn, match.Upstream, r, env, &lastActivity)
	} else {
		h.proxyToUpstreamWS(connCtx, conn, match.Upstream, r, env, &lastActivity)
	}
}

// proxyToUpstreamWS handles full-duplex proxying to an upstream WebSocket server with bounded queues.
func (h *Handler) proxyToUpstreamWS(
	ctx context.Context,
	downstream *websocket.Conn,
	cluster *config.UpstreamCluster,
	r *http.Request,
	env *pipeline.Envelope,
	lastActivity *atomic.Int64,
) {
	if len(cluster.Endpoints) == 0 {
		_ = downstream.Close(websocket.StatusInternalError, "no upstream endpoints")
		return
	}

	upstreamURL := cluster.Endpoints[0] + r.URL.Path
	if strings.HasPrefix(upstreamURL, "http://") {
		upstreamURL = "ws://" + strings.TrimPrefix(upstreamURL, "http://")
	} else if strings.HasPrefix(upstreamURL, "https://") {
		upstreamURL = "wss://" + strings.TrimPrefix(upstreamURL, "https://")
	} else if !strings.HasPrefix(upstreamURL, "ws://") && !strings.HasPrefix(upstreamURL, "wss://") {
		upstreamURL = "ws://" + upstreamURL
	}

	dialHeaders := make(http.Header)
	for k, vv := range r.Header {
		if strings.EqualFold(k, "Upgrade") || strings.EqualFold(k, "Connection") ||
			strings.EqualFold(k, "Sec-WebSocket-Key") || strings.EqualFold(k, "Sec-WebSocket-Version") ||
			strings.EqualFold(k, "Sec-WebSocket-Extensions") {
			continue
		}
		for _, v := range vv {
			dialHeaders.Add(k, v)
		}
	}

	dialOpts := &websocket.DialOptions{
		HTTPHeader: dialHeaders,
		HTTPClient: h.httpClient,
	}
	upstream, _, err := websocket.Dial(ctx, upstreamURL, dialOpts)
	if err != nil {
		if h.logger != nil {
			h.logger.Error("failed to dial upstream websocket", "url", upstreamURL, "error", err)
		}
		_ = downstream.Close(websocket.StatusBadGateway, "failed to dial upstream websocket")
		return
	}
	defer upstream.Close(websocket.StatusInternalError, "upstream closed")

	// Bounded queues for backpressure
	downstreamQueue := make(chan wsMessage, h.opts.QueueCapacity)
	upstreamQueue := make(chan wsMessage, h.opts.QueueCapacity)

	errChan := make(chan error, 4)

	// Goroutine 1: Writer to Downstream
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-downstreamQueue:
				if !ok {
					return
				}
				writeCtx, writeCancel := context.WithTimeout(ctx, h.opts.WriteTimeout)
				err := downstream.Write(writeCtx, msg.msgType, msg.data)
				writeCancel()
				if err != nil {
					errChan <- err
					return
				}
				lastActivity.Store(time.Now().UnixNano())
			}
		}
	}()

	// Goroutine 2: Writer to Upstream
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-upstreamQueue:
				if !ok {
					return
				}
				writeCtx, writeCancel := context.WithTimeout(ctx, h.opts.WriteTimeout)
				err := upstream.Write(writeCtx, msg.msgType, msg.data)
				writeCancel()
				if err != nil {
					errChan <- err
					return
				}
				lastActivity.Store(time.Now().UnixNano())
			}
		}
	}()

	// Goroutine 3: Reader from Downstream -> enqueue to Upstream
	go func() {
		defer close(upstreamQueue)
		for {
			msgType, data, err := downstream.Read(ctx)
			if err != nil {
				errChan <- err
				return
			}
			lastActivity.Store(time.Now().UnixNano())

			// Run message through ChunkHook filters
			filteredData, filterErr := h.applyChunkHooks(ctx, env, data)
			if filterErr != nil {
				if h.logger != nil {
					h.logger.Warn("chunk hook rejected message", "error", filterErr)
				}
				continue
			}

			// Enqueue with backpressure timeout
			select {
			case upstreamQueue <- wsMessage{msgType: msgType, data: filteredData}:
			case <-time.After(h.opts.WriteTimeout):
				_ = downstream.Close(websocket.StatusPolicyViolation, "backpressure timeout exceeded")
				errChan <- fmt.Errorf("downstream to upstream backpressure timeout exceeded")
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	// Goroutine 4: Reader from Upstream -> enqueue to Downstream
	go func() {
		defer close(downstreamQueue)
		for {
			msgType, data, err := upstream.Read(ctx)
			if err != nil {
				errChan <- err
				return
			}
			lastActivity.Store(time.Now().UnixNano())

			// Run message through ChunkHook filters
			filteredData, filterErr := h.applyChunkHooks(ctx, env, data)
			if filterErr != nil {
				if h.logger != nil {
					h.logger.Warn("chunk hook rejected response message", "error", filterErr)
				}
				continue
			}

			// Enqueue with backpressure timeout
			select {
			case downstreamQueue <- wsMessage{msgType: msgType, data: filteredData}:
			case <-time.After(h.opts.WriteTimeout):
				_ = upstream.Close(websocket.StatusPolicyViolation, "backpressure timeout exceeded")
				errChan <- fmt.Errorf("upstream to downstream backpressure timeout exceeded")
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for any terminal event
	select {
	case <-ctx.Done():
	case <-errChan:
	}

	_ = downstream.Close(websocket.StatusNormalClosure, "session completed")
	_ = upstream.Close(websocket.StatusNormalClosure, "session completed")
}

// proxyToHTTPBackend translates WebSocket messages into HTTP requests against an HTTP upstream backend.
func (h *Handler) proxyToHTTPBackend(
	ctx context.Context,
	conn *websocket.Conn,
	cluster *config.UpstreamCluster,
	r *http.Request,
	env *pipeline.Envelope,
	lastActivity *atomic.Int64,
) {
	if len(cluster.Endpoints) == 0 {
		_ = conn.Close(websocket.StatusInternalError, "no upstream endpoints")
		return
	}

	targetURL := cluster.Endpoints[0] + r.URL.Path

	for {
		msgType, data, err := conn.Read(ctx)
		if err != nil {
			break
		}
		lastActivity.Store(time.Now().UnixNano())

		// Apply message-level filter hook
		filteredData, filterErr := h.applyChunkHooks(ctx, env, data)
		if filterErr != nil {
			continue
		}

		// Dispatch HTTP POST to upstream backend
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(filteredData))
		if err != nil {
			_ = conn.Close(websocket.StatusInternalError, "failed to create backend request")
			return
		}

		httpReq.Header.Set("Content-Type", "application/json")
		if auth := r.Header.Get("Authorization"); auth != "" {
			httpReq.Header.Set("Authorization", auth)
		}

		resp, err := h.httpClient.Do(httpReq)
		if err != nil {
			errMsg := fmt.Sprintf(`{"error":"backend invocation failed: %s"}`, err.Error())
			_ = conn.Write(ctx, websocket.MessageText, []byte(errMsg))
			continue
		}

		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			continue
		}

		// Apply ChunkHook on response body
		filteredResp, hookErr := h.applyChunkHooks(ctx, env, respBody)
		if hookErr != nil {
			continue
		}

		writeCtx, writeCancel := context.WithTimeout(ctx, h.opts.WriteTimeout)
		err = conn.Write(writeCtx, msgType, filteredResp)
		writeCancel()
		if err != nil {
			break
		}
		lastActivity.Store(time.Now().UnixNano())
	}

	_ = conn.Close(websocket.StatusNormalClosure, "closed")
}
