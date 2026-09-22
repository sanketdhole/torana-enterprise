package ingress_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/phaselume/torana/internal/config"
	egressmcp "github.com/phaselume/torana/internal/egress/mcp"
	ingressmcp "github.com/phaselume/torana/internal/ingress/mcp"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/security/authn"
	"github.com/phaselume/torana/internal/security/authz"
	"google.golang.org/grpc/test/bufconn"
)

// setupMCPTestServer creates an in-process upstream MCP fake server via bufconn.
func setupMCPTestServer(t *testing.T) (*bufconn.Listener, func()) {
	lis := bufconn.Listen(1024 * 1024)
	mux := http.NewServeMux()

	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()

		var req ingressmcp.JSONRPCRequest
		_ = json.Unmarshal(bodyBytes, &req)

		switch req.Method {
		case "initialize":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Mcp-Session-Id", "upstream-sess-999")
			resp := ingressmcp.JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: ingressmcp.InitializeResult{
					ProtocolVersion: "2024-11-05",
					Capabilities: ingressmcp.ServerCapabilities{
						Tools: map[string]any{"listChanged": true},
					},
					ServerInfo: ingressmcp.ImplementationInfo{
						Name:    "fake-mcp-server",
						Version: "1.0.0",
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)

		case "tools/list":
			w.Header().Set("Content-Type", "application/json")
			resp := ingressmcp.JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: ingressmcp.ToolsListResult{
					Tools: []ingressmcp.Tool{
						{Name: "tool_public", Description: "Publicly accessible tool"},
						{Name: "tool_admin", Description: "Admin only tool"},
						{Name: "tool_secret", Description: "Strictly secret tool"},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)

		case "tools/call":
			var params ingressmcp.ToolCallParams
			_ = json.Unmarshal(req.Params, &params)
			w.Header().Set("Content-Type", "application/json")
			resp := ingressmcp.JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: ingressmcp.ToolCallResult{
					Content: []ingressmcp.ToolContent{
						{Type: "text", Text: "executed " + params.Name},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)

		case "$/cancelRequest", "notifications/cancelled":
			w.WriteHeader(http.StatusAccepted)

		default:
			w.Header().Set("Content-Type", "application/json")
			resp := ingressmcp.NewErrorResponse(req.ID, ingressmcp.CodeMethodNotFound, "method not found", nil)
			_ = json.NewEncoder(w).Encode(resp)
		}
	})

	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: endpoint\ndata: /mcp\n\n"))
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(lis) }()

	cleanup := func() {
		_ = srv.Close()
		_ = lis.Close()
	}
	return lis, cleanup
}

func setupMCPAuthzEngine(t *testing.T) *authz.PolicyEngine {
	compiler, err := authz.NewCompiler(authz.CompilerConfig{CostLimit: 1000})
	if err != nil {
		t.Fatalf("failed to create compiler: %v", err)
	}
	rules := []authz.Rule{
		{
			ID:         "allow-public-tool",
			Priority:   50,
			Effect:     authz.EffectAllow,
			Expression: `resource.type == 'mcp_tool' && resource.id == 'tool_public'`,
		},
		{
			ID:         "allow-admin-tool",
			Priority:   60,
			Effect:     authz.EffectAllow,
			Expression: `resource.type == 'mcp_tool' && resource.id == 'tool_admin' && identity.claims['role'] == 'admin'`,
		},
		{
			ID:         "deny-secret-tool",
			Priority:   100,
			Effect:     authz.EffectDeny,
			Expression: `resource.type == 'mcp_tool' && resource.id == 'tool_secret'`,
		},
	}

	compiled, err := compiler.CompileRules(rules)
	if err != nil {
		t.Fatalf("failed to compile authz rules: %v", err)
	}
	return authz.NewPolicyEngine(compiled, nil)
}

func TestMCP_InitializeAndSessionMapping(t *testing.T) {
	lis, cleanup := setupMCPTestServer(t)
	defer cleanup()

	egressClient := egressmcp.NewClient()
	upstreamCluster := &config.UpstreamCluster{
		ID:        "u-mcp",
		Protocol:  "mcp",
		Endpoints: []string{"http://bufconn"},
	}

	mockHTTPClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			},
		},
	}
	egressClient.SetClientForCluster("u-mcp", mockHTTPClient)

	handler := ingressmcp.NewHandler(nil, nil, egressClient, nil)

	initReq := ingressmcp.JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2024-11-05","clientInfo":{"name":"test-client","version":"1.0"}}`),
	}
	raw, _ := json.Marshal(initReq)

	req, _ := http.NewRequest(http.MethodPost, "http://torana/mcp", bytes.NewReader(raw))
	req.Header.Set("Mcp-Session-Id", "client-sess-1")
	w := &mockResponseWriter{header: make(http.Header), body: new(bytes.Buffer)}

	env := &pipeline.Envelope{Path: "/mcp", Method: "POST"}
	handler.ServeHTTP(w, req, upstreamCluster, env)

	if w.code != 0 && w.code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.code)
	}

	var rpcResp ingressmcp.JSONRPCResponse
	if err := json.Unmarshal(w.body.Bytes(), &rpcResp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if rpcResp.Error != nil {
		t.Fatalf("unexpected jsonrpc error: %v", rpcResp.Error)
	}

	// Verify session mapping in SessionManager
	sess := handler.SessionManager().GetOrCreate("client-sess-1", "")
	if sess.UpstreamSessionID != "upstream-sess-999" {
		t.Fatalf("expected upstream session 'upstream-sess-999', got %q", sess.UpstreamSessionID)
	}
}

func TestMCP_ToolsListFiltering(t *testing.T) {
	lis, cleanup := setupMCPTestServer(t)
	defer cleanup()

	egressClient := egressmcp.NewClient()
	upstreamCluster := &config.UpstreamCluster{
		ID:        "u-mcp",
		Protocol:  "mcp",
		Endpoints: []string{"http://bufconn"},
	}
	egressClient.SetClientForCluster("u-mcp", &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			},
		},
	})

	authzEngine := setupMCPAuthzEngine(t)
	handler := ingressmcp.NewHandler(authzEngine, nil, egressClient, nil)

	t.Run("Standard User Identity", func(t *testing.T) {
		reqBody := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
		r, _ := http.NewRequest(http.MethodPost, "http://torana/mcp", bytes.NewBufferString(reqBody))
		w := &mockResponseWriter{header: make(http.Header), body: new(bytes.Buffer)}

		userEnv := &pipeline.Envelope{
			Path:   "/mcp",
			Method: "POST",
			Identity: &authn.Identity{
				Subject: "alice",
				Claims:  map[string]any{"role": "user"},
			},
		}

		handler.ServeHTTP(w, r, upstreamCluster, userEnv)

		var resp ingressmcp.JSONRPCResponse
		if err := json.Unmarshal(w.body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		var listResult ingressmcp.ToolsListResult
		resBytes, _ := json.Marshal(resp.Result)
		_ = json.Unmarshal(resBytes, &listResult)

		if len(listResult.Tools) != 1 {
			t.Fatalf("expected 1 tool for user, got %d", len(listResult.Tools))
		}
		if listResult.Tools[0].Name != "tool_public" {
			t.Fatalf("expected tool_public, got %s", listResult.Tools[0].Name)
		}
	})

	t.Run("Admin User Identity", func(t *testing.T) {
		reqBody := `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`
		r, _ := http.NewRequest(http.MethodPost, "http://torana/mcp", bytes.NewBufferString(reqBody))
		w := &mockResponseWriter{header: make(http.Header), body: new(bytes.Buffer)}

		adminEnv := &pipeline.Envelope{
			Path:   "/mcp",
			Method: "POST",
			Identity: &authn.Identity{
				Subject: "admin",
				Claims:  map[string]any{"role": "admin"},
			},
		}

		handler.ServeHTTP(w, r, upstreamCluster, adminEnv)

		var resp ingressmcp.JSONRPCResponse
		_ = json.Unmarshal(w.body.Bytes(), &resp)

		var listResult ingressmcp.ToolsListResult
		resBytes, _ := json.Marshal(resp.Result)
		_ = json.Unmarshal(resBytes, &listResult)

		if len(listResult.Tools) != 2 {
			t.Fatalf("expected 2 tools for admin, got %d", len(listResult.Tools))
		}
		names := map[string]bool{}
		for _, tool := range listResult.Tools {
			names[tool.Name] = true
		}
		if !names["tool_public"] || !names["tool_admin"] {
			t.Fatalf("expected tool_public and tool_admin, got %v", names)
		}
		if names["tool_secret"] {
			t.Fatalf("tool_secret must not be included")
		}
	})
}

func TestMCP_ToolsCallAuthorization(t *testing.T) {
	lis, cleanup := setupMCPTestServer(t)
	defer cleanup()

	egressClient := egressmcp.NewClient()
	upstreamCluster := &config.UpstreamCluster{
		ID:        "u-mcp",
		Protocol:  "mcp",
		Endpoints: []string{"http://bufconn"},
	}
	egressClient.SetClientForCluster("u-mcp", &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			},
		},
	})

	authzEngine := setupMCPAuthzEngine(t)
	handler := ingressmcp.NewHandler(authzEngine, nil, egressClient, nil)

	t.Run("Call tool_public succeeds", func(t *testing.T) {
		reqBody := `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"tool_public","arguments":{"query":"hello"}}}`
		r, _ := http.NewRequest(http.MethodPost, "http://torana/mcp", bytes.NewBufferString(reqBody))
		w := &mockResponseWriter{header: make(http.Header), body: new(bytes.Buffer)}

		env := &pipeline.Envelope{
			Path:   "/mcp",
			Method: "POST",
			Identity: &authn.Identity{
				Subject: "bob",
				Claims:  map[string]any{"role": "user"},
			},
		}

		handler.ServeHTTP(w, r, upstreamCluster, env)

		var resp ingressmcp.JSONRPCResponse
		_ = json.Unmarshal(w.body.Bytes(), &resp)

		if resp.Error != nil {
			t.Fatalf("unexpected error: %v", resp.Error)
		}
	})

	t.Run("Call tool_admin denied for user", func(t *testing.T) {
		reqBody := `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"tool_admin","arguments":{}}}`
		r, _ := http.NewRequest(http.MethodPost, "http://torana/mcp", bytes.NewBufferString(reqBody))
		w := &mockResponseWriter{header: make(http.Header), body: new(bytes.Buffer)}

		env := &pipeline.Envelope{
			Path:   "/mcp",
			Method: "POST",
			Identity: &authn.Identity{
				Subject: "bob",
				Claims:  map[string]any{"role": "user"},
			},
		}

		handler.ServeHTTP(w, r, upstreamCluster, env)

		var resp ingressmcp.JSONRPCResponse
		_ = json.Unmarshal(w.body.Bytes(), &resp)

		if resp.Error == nil {
			t.Fatalf("expected error, got success: %v", resp.Result)
		}
		if resp.Error.Code != ingressmcp.CodeUnauthorized {
			t.Fatalf("expected code %d, got %d", ingressmcp.CodeUnauthorized, resp.Error.Code)
		}
	})

	t.Run("Call tool_admin allowed for admin", func(t *testing.T) {
		reqBody := `{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"tool_admin","arguments":{}}}`
		r, _ := http.NewRequest(http.MethodPost, "http://torana/mcp", bytes.NewBufferString(reqBody))
		w := &mockResponseWriter{header: make(http.Header), body: new(bytes.Buffer)}

		env := &pipeline.Envelope{
			Path:   "/mcp",
			Method: "POST",
			Identity: &authn.Identity{
				Subject: "admin-root",
				Claims:  map[string]any{"role": "admin"},
			},
		}

		handler.ServeHTTP(w, r, upstreamCluster, env)

		var resp ingressmcp.JSONRPCResponse
		_ = json.Unmarshal(w.body.Bytes(), &resp)

		if resp.Error != nil {
			t.Fatalf("unexpected error for admin: %v", resp.Error)
		}
	})
}

func TestMCP_Cancellation(t *testing.T) {
	handler := ingressmcp.NewHandler(nil, nil, nil, nil)
	sess := handler.SessionManager().GetOrCreate("test-sess", "")

	cancelled := false
	cancelFunc := func() { cancelled = true }
	sess.RegisterCancel("req-123", cancelFunc)

	cancelReq := ingressmcp.JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "$/cancelRequest",
		Params:  json.RawMessage(`{"requestId":"req-123","reason":"user aborted"}`),
	}
	raw, _ := json.Marshal(cancelReq)

	req, _ := http.NewRequest(http.MethodPost, "http://torana/mcp", bytes.NewReader(raw))
	req.Header.Set("Mcp-Session-Id", "test-sess")
	w := &mockResponseWriter{header: make(http.Header), body: new(bytes.Buffer)}

	handler.ServeHTTP(w, req, &config.UpstreamCluster{}, &pipeline.Envelope{})

	if !cancelled {
		t.Fatalf("expected request cancellation func to be invoked")
	}
}

// mockResponseWriter implements http.ResponseWriter and http.Flusher for unit testing.
type mockResponseWriter struct {
	header  http.Header
	body    *bytes.Buffer
	code    int
	flushed bool
}

func (m *mockResponseWriter) Header() http.Header {
	if m.header == nil {
		m.header = make(http.Header)
	}
	return m.header
}

func (m *mockResponseWriter) Write(b []byte) (int, error) {
	return m.body.Write(b)
}

func (m *mockResponseWriter) WriteHeader(statusCode int) {
	m.code = statusCode
}

func (m *mockResponseWriter) Flush() {
	m.flushed = true
}

func BenchmarkMCP_ToolsCall(b *testing.B) {
	lis, cleanup := setupMCPTestServer(&testing.T{})
	defer cleanup()

	egressClient := egressmcp.NewClient()
	upstreamCluster := &config.UpstreamCluster{
		ID:        "u-mcp",
		Protocol:  "mcp",
		Endpoints: []string{"http://bufconn"},
	}
	egressClient.SetClientForCluster("u-mcp", &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			},
		},
	})

	authzEngine := setupMCPAuthzEngine(&testing.T{})
	handler := ingressmcp.NewHandler(authzEngine, nil, egressClient, nil)

	env := &pipeline.Envelope{
		Path:   "/mcp",
		Method: "POST",
		Identity: &authn.Identity{
			Subject: "bob",
			Claims:  map[string]any{"role": "user"},
		},
	}

	payload := []byte(`{"jsonrpc":"2.0","id":100,"method":"tools/call","params":{"name":"tool_public","arguments":{"query":"test"}}}`)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, _ := http.NewRequest(http.MethodPost, "http://torana/mcp", bytes.NewReader(payload))
		w := &mockResponseWriter{header: make(http.Header), body: new(bytes.Buffer)}
		handler.ServeHTTP(w, r, upstreamCluster, env)
	}
}

