package fuzz_test

import (
	"testing"

	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/router"
)

// FuzzRouterMatch exercises the router's Match function with random
// host/method/path combinations against a compiled routing table.
// Must never panic regardless of input.
func FuzzRouterMatch(f *testing.F) {
	// Seed corpus: valid inputs
	f.Add("example.com", "GET", "/v1/chat/completions")
	f.Add("example.com", "POST", "/v1/embeddings")
	f.Add("", "GET", "/healthz")
	f.Add("*.internal.net", "DELETE", "/api/v1/models/abc")
	f.Add("", "", "")
	f.Add("host:8080", "PATCH", "/a/b/c/d/e/f/g/h")
	f.Add("evil\x00host", "POST", "/v1/../../../etc/passwd")
	f.Add("a]b[c", "GET", "/(.*)")

	snap := &config.Snapshot{
		Version: 1,
		Routes: []config.RouteRule{
			{ID: "exact", Path: "/v1/chat/completions", Method: "POST", UpstreamID: "up1"},
			{ID: "embed", Path: "/v1/embeddings", Method: "POST", UpstreamID: "up1"},
			{ID: "models", Path: "/v1/models", Method: "GET", UpstreamID: "up1"},
			{ID: "health", Path: "/healthz", Method: "GET", UpstreamID: "up1"},
			{ID: "prefix", Path: "/api/", PathPrefix: true, UpstreamID: "up1"},
			{ID: "wildcard", Path: "/", Method: "*", UpstreamID: "up1"},
		},
		Upstreams: map[string]config.UpstreamCluster{
			"up1": {ID: "up1", Protocol: "http", Endpoints: []string{"http://localhost:9999"}},
		},
	}

	rtr := router.Compile(snap)

	f.Fuzz(func(t *testing.T, host, method, path string) {
		// Must not panic. Either returns a valid result or ErrNoRouteMatched.
		result, err := rtr.Match(router.MatchCriteria{
			Host:   host,
			Method: method,
			Path:   path,
		})
		if err != nil && err != router.ErrNoRouteMatched {
			// Unexpected error type — this is a bug.
			t.Errorf("unexpected error type: %v", err)
		}
		if err == nil && result.Route == nil {
			t.Error("match returned nil route without error")
		}
	})
}
