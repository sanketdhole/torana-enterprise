package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/phaselume/torana/internal/config"
	egressmcp "github.com/phaselume/torana/internal/egress/mcp"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/security/authn"
	"github.com/phaselume/torana/internal/security/authz"
)

// Handler processes incoming Model Context Protocol (MCP) JSON-RPC requests and SSE streams.
type Handler struct {
	authzEngine *authz.PolicyEngine
	sessionMgr  *SessionManager
	egressMCP   *egressmcp.Client
	logger      *slog.Logger
}

// NewHandler creates a new JSON-RPC-aware MCP ingress handler.
func NewHandler(
	authzEngine *authz.PolicyEngine,
	sessionMgr *SessionManager,
	egressMCP *egressmcp.Client,
	logger *slog.Logger,
) *Handler {
	if sessionMgr == nil {
		sessionMgr = NewSessionManager(30 * time.Minute)
	}
	if egressMCP == nil {
		egressMCP = egressmcp.NewClient()
	}
	return &Handler{
		authzEngine: authzEngine,
		sessionMgr:  sessionMgr,
		egressMCP:   egressMCP,
		logger:      logger,
	}
}

// SessionManager returns the underlying session manager.
func (h *Handler) SessionManager() *SessionManager {
	return h.sessionMgr
}

// authorizeTool evaluates CEL authorization policy for an MCP tool.
func (h *Handler) authorizeTool(ctx context.Context, env *pipeline.Envelope, toolName, actionName string) bool {
	if h.authzEngine == nil {
		return true // Default allow if no authz engine configured
	}

	var ident *authn.Identity
	if env != nil {
		if id, ok := env.Identity.(*authn.Identity); ok {
			ident = id
		}
	}

	headers := make(map[string]string)
	if env != nil && env.Headers != nil {
		for k, vv := range env.Headers {
			if len(vv) > 0 {
				headers[k] = vv[0]
			}
		}
	}

	path := ""
	if env != nil {
		path = env.Path
	}

	reqAttrs := authz.RequestAttributes{
		Path:    path,
		Method:  "POST",
		Headers: headers,
		Time:    time.Now(),
	}
	res := authz.Resource{
		Type: authz.ResourceTypeMCPTool,
		ID:   toolName,
	}
	act := authz.Action{
		Name:   actionName,
		Method: "POST",
	}

	err := h.authzEngine.Evaluate(ctx, ident, res, act, reqAttrs)
	if err != nil {
		if h.logger != nil {
			h.logger.Debug("mcp tool access denied by policy", "tool", toolName, "action", actionName, "error", err)
		}
		return false
	}
	return true
}

// ServeHTTP handles incoming MCP streamable HTTP requests and legacy SSE handshakes.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, cluster *config.UpstreamCluster, env *pipeline.Envelope) {
	clientSessionID := r.Header.Get("Mcp-Session-Id")
	if clientSessionID == "" {
		clientSessionID = r.URL.Query().Get("sessionId")
	}

	sess := h.sessionMgr.GetOrCreate(clientSessionID, "")

	// 1. Handle Legacy SSE Endpoint Discovery: GET /sse
	if r.Method == http.MethodGet && (r.URL.Path == "/sse" || strings.HasSuffix(r.URL.Path, "/sse")) {
		h.handleSSEDiscovery(w, r, sess)
		return
	}

	// 2. Handle POST JSON-RPC Calls (Streamable HTTP Transport & /message)
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		h.writeError(w, nil, CodeParseError, "failed to read request body")
		return
	}

	// Detect if batch or single JSON-RPC
	if len(bytesTrim(bodyBytes)) > 0 && bytesTrim(bodyBytes)[0] == '[' {
		h.handleBatchRequest(w, r, cluster, env, sess, bodyBytes)
		return
	}

	var req JSONRPCRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		h.writeError(w, nil, CodeParseError, "invalid JSON payload")
		return
	}

	h.handleSingleRequest(w, r, cluster, env, sess, &req, bodyBytes)
}

func (h *Handler) handleSingleRequest(
	w http.ResponseWriter,
	r *http.Request,
	cluster *config.UpstreamCluster,
	env *pipeline.Envelope,
	sess *Session,
	req *JSONRPCRequest,
	rawBody []byte,
) {
	// 1. Handle Cancellation Notification
	if req.Method == "$/cancelRequest" || req.Method == "notifications/cancelled" {
		var cancelParams CancelParams
		if len(req.Params) > 0 {
			_ = json.Unmarshal(req.Params, &cancelParams)
		}
		if cancelParams.RequestID != nil {
			sess.CancelRequest(fmt.Sprint(cancelParams.RequestID))
		}
		if req.IsNotification() {
			w.WriteHeader(http.StatusAccepted)
		} else {
			resp := &JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"status": "cancelled"}}
			h.writeResponse(w, resp, sess.ClientSessionID)
		}
		return
	}

	// 2. Handle Per-Tool Authorization on tools/call
	if req.Method == "tools/call" {
		var toolParams ToolCallParams
		if err := json.Unmarshal(req.Params, &toolParams); err != nil {
			h.writeError(w, req.ID, CodeInvalidParams, "invalid tools/call params")
			return
		}

		if !h.authorizeTool(r.Context(), env, toolParams.Name, "call") {
			h.writeError(w, req.ID, CodeUnauthorized, fmt.Sprintf("unauthorized: access to tool %q denied by policy", toolParams.Name))
			return
		}
	}

	// 3. Setup in-flight request context with cancellation tracking
	reqCtx, cancel := context.WithCancel(r.Context())
	defer cancel()

	if req.ID != nil {
		sess.RegisterCancel(fmt.Sprint(req.ID), cancel)
		defer sess.UnregisterCancel(fmt.Sprint(req.ID))
	}

	// 4. Forward to Upstream MCP Cluster
	respBody, respHeaders, err := h.egressMCP.SendJSONRPC(reqCtx, cluster, r.URL.Path, rawBody, sess.UpstreamSessionID, r.Header)
	if err != nil {
		if errors.Is(reqCtx.Err(), context.Canceled) {
			h.writeError(w, req.ID, CodeInternalError, "request cancelled")
			return
		}
		h.writeError(w, req.ID, CodeInternalError, fmt.Sprintf("upstream mcp error: %s", err.Error()))
		return
	}

	// 5. Intercept "initialize" to sync upstream session IDs
	if req.Method == "initialize" {
		if upSess := respHeaders.Get("Mcp-Session-Id"); upSess != "" {
			sess.UpstreamSessionID = upSess
		}
	}

	// 6. Intercept "tools/list" to filter tools by caller authorization
	if req.Method == "tools/list" {
		var rpcResp JSONRPCResponse
		if err := json.Unmarshal(respBody, &rpcResp); err == nil && rpcResp.Error == nil {
			var listResult ToolsListResult
			resultBytes, _ := json.Marshal(rpcResp.Result)
			if err := json.Unmarshal(resultBytes, &listResult); err == nil {
				filteredTools := make([]Tool, 0, len(listResult.Tools))
				for _, t := range listResult.Tools {
					if h.authorizeTool(r.Context(), env, t.Name, "list") {
						filteredTools = append(filteredTools, t)
					}
				}
				listResult.Tools = filteredTools
				rpcResp.Result = listResult
				modifiedResp, _ := json.Marshal(rpcResp)
				h.writeRawResponse(w, modifiedResp, sess.ClientSessionID)
				return
			}
		}
	}

	// 7. Write transparent upstream response with client session mapping
	h.writeRawResponse(w, respBody, sess.ClientSessionID)
}

func (h *Handler) handleBatchRequest(
	w http.ResponseWriter,
	r *http.Request,
	cluster *config.UpstreamCluster,
	env *pipeline.Envelope,
	sess *Session,
	rawBody []byte,
) {
	var batch []JSONRPCRequest
	if err := json.Unmarshal(rawBody, &batch); err != nil {
		h.writeError(w, nil, CodeParseError, "invalid batch JSON")
		return
	}

	responses := make([]*JSONRPCResponse, 0, len(batch))
	for _, req := range batch {
		if req.Method == "tools/call" {
			var toolParams ToolCallParams
			_ = json.Unmarshal(req.Params, &toolParams)
			if !h.authorizeTool(r.Context(), env, toolParams.Name, "call") {
				responses = append(responses, NewErrorResponse(req.ID, CodeUnauthorized, fmt.Sprintf("unauthorized: access to tool %q denied by policy", toolParams.Name), nil))
				continue
			}
		}

		singleBytes, _ := json.Marshal(req)
		respBody, _, err := h.egressMCP.SendJSONRPC(r.Context(), cluster, r.URL.Path, singleBytes, sess.UpstreamSessionID, r.Header)
		if err != nil {
			responses = append(responses, NewErrorResponse(req.ID, CodeInternalError, err.Error(), nil))
			continue
		}

		var singleResp JSONRPCResponse
		if err := json.Unmarshal(respBody, &singleResp); err == nil {
			responses = append(responses, &singleResp)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Mcp-Session-Id", sess.ClientSessionID)
	_ = json.NewEncoder(w).Encode(responses)
}

// handleSSEDiscovery serves legacy MCP GET /sse endpoint discovery.
func (h *Handler) handleSSEDiscovery(w http.ResponseWriter, r *http.Request, sess *Session) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Mcp-Session-Id", sess.ClientSessionID)

	// Stream initial endpoint registration event
	endpointMsg := fmt.Sprintf("event: endpoint\ndata: /mcp?sessionId=%s\n\n", sess.ClientSessionID)
	_, _ = w.Write([]byte(endpointMsg))
	flusher.Flush()

	// Keep stream alive until client disconnects
	<-r.Context().Done()
}

func (h *Handler) writeError(w http.ResponseWriter, id any, code int, msg string) {
	resp := NewErrorResponse(id, code, msg, nil)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC errors typically return 200 OK with error field
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) writeResponse(w http.ResponseWriter, resp *JSONRPCResponse, clientSessionID string) {
	w.Header().Set("Content-Type", "application/json")
	if clientSessionID != "" {
		w.Header().Set("Mcp-Session-Id", clientSessionID)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) writeRawResponse(w http.ResponseWriter, body []byte, clientSessionID string) {
	w.Header().Set("Content-Type", "application/json")
	if clientSessionID != "" {
		w.Header().Set("Mcp-Session-Id", clientSessionID)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func bytesTrim(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}
