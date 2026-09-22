// Package mcp implements an ingress gateway proxy for the Model Context Protocol (MCP).
//
// Targeted Specifications:
//   - Specification: Model Context Protocol (MCP) Specification
//   - Protocol Version: 2024-11-05 (Linux Foundation Agentic AI Foundation / Anthropic)
//   - Supported Transports:
//       1. Streamable HTTP Transport (SEP-2322): Stateless POST-based JSON-RPC with
//          request-scoped SSE streams and metadata headers (Mcp-Session-Id, Mcp-Method).
//       2. Legacy HTTP+SSE Transport: Endpoint discovery via GET /sse with message
//          dispatch via POST /message.
//   - Core Primitives:
//       - initialize: capability negotiation and protocol version handshake.
//       - tools/list: discover tools provided by server, filtered by caller identity.
//       - tools/call: execute tool with arguments, authorized per-tool via authz (mcp_tool).
//       - resources/*: list, read, and subscribe to context resources.
//       - prompts/*: list and retrieve prompt templates.
//       - $/cancelRequest, notifications/cancelled: cancel active in-flight requests.
package mcp

import (
	"encoding/json"
	"errors"
)

// MCP Protocol Version targeted by this implementation.
const ProtocolVersion = "2024-11-05"

// Standard JSON-RPC 2.0 error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
	CodeUnauthorized   = -32003 // Custom standard application error for policy denial
)

var (
	ErrUnauthorizedTool = errors.New("unauthorized: mcp tool access denied by policy")
	ErrSessionNotFound  = errors.New("mcp session not found or expired")
)

// JSONRPCRequest represents a standard JSON-RPC 2.0 request or notification.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"` // string, number, or null for notifications
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// IsNotification returns true if the request is a notification (no ID present).
func (r *JSONRPCRequest) IsNotification() bool {
	return r.ID == nil
}

// JSONRPCResponse represents a standard JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id"`
	Result  any           `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// JSONRPCError defines structured error details in JSON-RPC 2.0.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// NewErrorResponse formats a JSON-RPC 2.0 error response.
func NewErrorResponse(id any, code int, message string, data any) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
}

// InitializeParams holds parameters sent in the "initialize" request.
type InitializeParams struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities"`
	ClientInfo      ImplementationInfo `json:"clientInfo"`
}

// InitializeResult represents the server response to "initialize".
type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      ImplementationInfo `json:"serverInfo"`
	Instructions    string             `json:"instructions,omitempty"`
}

// ImplementationInfo describes the client or server name and version.
type ImplementationInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ClientCapabilities declares optional client features.
type ClientCapabilities struct {
	Experimental map[string]any `json:"experimental,omitempty"`
	Sampling     map[string]any `json:"sampling,omitempty"`
	Roots        map[string]any `json:"roots,omitempty"`
}

// ServerCapabilities declares optional server features.
type ServerCapabilities struct {
	Experimental map[string]any `json:"experimental,omitempty"`
	Logging      map[string]any `json:"logging,omitempty"`
	Prompts      map[string]any `json:"prompts,omitempty"`
	Resources    map[string]any `json:"resources,omitempty"`
	Tools        map[string]any `json:"tools,omitempty"`
}

// Tool describes an available MCP tool.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema"`
}

// ToolsListResult represents the result payload of a "tools/list" call.
type ToolsListResult struct {
	Tools      []Tool `json:"tools"`
	NextCursor string `json:"nextCursor,omitempty"`
}

// ToolCallParams defines parameters for a "tools/call" invocation.
type ToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// ToolCallResult represents the output of a "tools/call" invocation.
type ToolCallResult struct {
	Content []ToolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// ToolContent holds text or image content returned by a tool.
type ToolContent struct {
	Type string `json:"type"` // "text", "image", "resource"
	Text string `json:"text,omitempty"`
	Data string `json:"data,omitempty"`
}

// CancelParams represents parameters for cancelling an in-flight request.
type CancelParams struct {
	RequestID any    `json:"requestId"`
	Reason    string `json:"reason,omitempty"`
}
