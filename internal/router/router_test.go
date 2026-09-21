package router

import (
	"testing"
	"time"

	"github.com/phaselume/torana/internal/config"
)

func sampleSnapshot() *config.Snapshot {
	return &config.Snapshot{
		Version: 1,
		Upstreams: map[string]config.UpstreamCluster{
			"llm-openai": {
				ID:        "llm-openai",
				Protocol:  "http",
				Endpoints: []string{"https://api.openai.com"},
				Timeout:   30 * time.Second,
			},
			"llm-anthropic": {
				ID:        "llm-anthropic",
				Protocol:  "http",
				Endpoints: []string{"https://api.anthropic.com"},
				Timeout:   30 * time.Second,
			},
			"mcp-server": {
				ID:        "mcp-server",
				Protocol:  "mcp",
				Endpoints: []string{"http://localhost:5000"},
				Timeout:   10 * time.Second,
			},
		},
		Routes: []config.RouteRule{
			{
				ID:         "route-chat",
				Path:       "/v1/chat/completions",
				Method:     "POST",
				UpstreamID: "llm-openai",
			},
			{
				ID:         "route-models",
				Path:       "/v1/models",
				Method:     "GET",
				UpstreamID: "llm-openai",
			},
			{
				ID:         "route-anthropic-prefix",
				Path:       "/v1/anthropic/",
				PathPrefix: true,
				Method:     "POST",
				UpstreamID: "llm-anthropic",
			},
			{
				ID:         "route-mcp-wildcard",
				Path:       "/mcp/",
				PathPrefix: true,
				Method:     "", // Any method
				UpstreamID: "mcp-server",
			},
		},
	}
}

func TestRouter_Match(t *testing.T) {
	r := Compile(sampleSnapshot())

	tests := []struct {
		name          string
		method        string
		path          string
		expectedRoute string
		expectedUpstr string
		expectError   bool
	}{
		{
			name:          "exact match POST /v1/chat/completions",
			method:        "POST",
			path:          "/v1/chat/completions",
			expectedRoute: "route-chat",
			expectedUpstr: "llm-openai",
			expectError:   false,
		},
		{
			name:          "exact match wrong method GET /v1/chat/completions",
			method:        "GET",
			path:          "/v1/chat/completions",
			expectError:   true,
		},
		{
			name:          "exact match GET /v1/models",
			method:        "GET",
			path:          "/v1/models",
			expectedRoute: "route-models",
			expectedUpstr: "llm-openai",
			expectError:   false,
		},
		{
			name:          "prefix match POST /v1/anthropic/v1/messages",
			method:        "POST",
			path:          "/v1/anthropic/v1/messages",
			expectedRoute: "route-anthropic-prefix",
			expectedUpstr: "llm-anthropic",
			expectError:   false,
		},
		{
			name:          "prefix match wildcard method GET /mcp/tools",
			method:        "GET",
			path:          "/mcp/tools",
			expectedRoute: "route-mcp-wildcard",
			expectedUpstr: "mcp-server",
			expectError:   false,
		},
		{
			name:          "prefix match wildcard method POST /mcp/invoke",
			method:        "POST",
			path:          "/mcp/invoke",
			expectedRoute: "route-mcp-wildcard",
			expectedUpstr: "mcp-server",
			expectError:   false,
		},
		{
			name:        "non-existent route",
			method:      "GET",
			path:        "/unknown/path",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := r.Match(tt.method, tt.path)
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got matched route %s", res.Route.ID)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected match error: %v", err)
			}

			if res.Route.ID != tt.expectedRoute {
				t.Errorf("expected route ID '%s', got '%s'", tt.expectedRoute, res.Route.ID)
			}
			if res.Upstream.ID != tt.expectedUpstr {
				t.Errorf("expected upstream ID '%s', got '%s'", tt.expectedUpstr, res.Upstream.ID)
			}
		})
	}
}

func BenchmarkRouter_MatchExact(b *testing.B) {
	r := Compile(sampleSnapshot())

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			res, err := r.Match("POST", "/v1/chat/completions")
			if err != nil || res.Route == nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkRouter_MatchPrefix(b *testing.B) {
	r := Compile(sampleSnapshot())

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			res, err := r.Match("POST", "/v1/anthropic/v1/messages")
			if err != nil || res.Route == nil {
				b.Fatal(err)
			}
		}
	})
}
