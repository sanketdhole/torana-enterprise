package router_test

import (
	"testing"
	"time"

	"github.com/phaselume/torana/internal/config"
	"github.com/phaselume/torana/internal/router"
)

func sampleAdvancedSnapshot() *config.Snapshot {
	return &config.Snapshot{
		Version: 1,
		Upstreams: map[string]config.UpstreamCluster{
			"u-openai-prod": {
				ID:        "u-openai-prod",
				Protocol:  "http",
				Endpoints: []string{"https://api.openai.com"},
			},
			"u-openai-canary": {
				ID:        "u-openai-canary",
				Protocol:  "http",
				Endpoints: []string{"https://canary.openai.com"},
			},
			"u-anthropic": {
				ID:        "u-anthropic",
				Protocol:  "http",
				Endpoints: []string{"https://api.anthropic.com"},
			},
		},
		Routes: []config.RouteRule{
			{
				ID:         "route-host-specific",
				Host:       "api.torana.ai",
				Path:       "/v1/chat/completions",
				Method:     "POST",
				UpstreamID: "u-openai-prod",
			},
			{
				ID:         "route-wildcard-host",
				Host:       "*.internal.net",
				Path:       "/v1/chat/completions",
				Method:     "POST",
				UpstreamID: "u-anthropic",
			},
			{
				ID:     "route-weighted-canary",
				Path:   "/v1/canary",
				Method: "POST",
				WeightedUpstreams: []config.WeightedUpstream{
					{UpstreamID: "u-openai-prod", Weight: 80},
					{UpstreamID: "u-openai-canary", Weight: 20},
				},
				RetryPolicy: &config.RetryPolicy{
					MaxRetries:         3,
					RetryOnStatusCodes: []int{502, 503, 504},
					PerTryTimeout:      5 * time.Second,
				},
			},
			{
				ID:     "route-claim-specific",
				Path:   "/v1/enterprise",
				Method: "GET",
				Claims: map[string]string{
					"tier": "platinum",
				},
				UpstreamID: "u-openai-prod",
			},
			{
				ID:         "route-prefix-models",
				Path:       "/v1/models/",
				PathPrefix: true,
				Method:     "GET",
				UpstreamID: "u-openai-prod",
			},
		},
	}
}

func TestRouter_MultiCriteriaMatching(t *testing.T) {
	r := router.Compile(sampleAdvancedSnapshot())

	tests := []struct {
		name          string
		criteria      router.MatchCriteria
		expectedRoute string
		expectedUpstr string
		expectError   bool
	}{
		{
			name: "exact host and path match",
			criteria: router.MatchCriteria{
				Host:   "api.torana.ai",
				Method: "POST",
				Path:   "/v1/chat/completions",
			},
			expectedRoute: "route-host-specific",
			expectedUpstr: "u-openai-prod",
		},
		{
			name: "wildcard host match",
			criteria: router.MatchCriteria{
				Host:   "gateway.internal.net",
				Method: "POST",
				Path:   "/v1/chat/completions",
			},
			expectedRoute: "route-wildcard-host",
			expectedUpstr: "u-anthropic",
		},
		{
			name: "claims matching tier=platinum",
			criteria: router.MatchCriteria{
				Method: "GET",
				Path:   "/v1/enterprise",
				Claims: map[string]string{"tier": "platinum"},
			},
			expectedRoute: "route-claim-specific",
			expectedUpstr: "u-openai-prod",
		},
		{
			name: "claims mismatch rejects route",
			criteria: router.MatchCriteria{
				Method: "GET",
				Path:   "/v1/enterprise",
				Claims: map[string]string{"tier": "free"},
			},
			expectError: true,
		},
		{
			name: "prefix match /v1/models/gpt-4o",
			criteria: router.MatchCriteria{
				Method: "GET",
				Path:   "/v1/models/gpt-4o",
			},
			expectedRoute: "route-prefix-models",
			expectedUpstr: "u-openai-prod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := r.Match(tt.criteria)
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got route %s", res.Route.ID)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected match error: %v", err)
			}
			if res.Route.ID != tt.expectedRoute {
				t.Errorf("expected route %s, got %s", tt.expectedRoute, res.Route.ID)
			}
			if res.Upstream.ID != tt.expectedUpstr {
				t.Errorf("expected upstream %s, got %s", tt.expectedUpstr, res.Upstream.ID)
			}
		})
	}
}

func TestRouter_WeightedSplitDistribution(t *testing.T) {
	r := router.Compile(sampleAdvancedSnapshot())

	counts := make(map[string]int)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		res, err := r.Match(router.MatchCriteria{
			Method: "POST",
			Path:   "/v1/canary",
		})
		if err != nil {
			t.Fatalf("unexpected match error: %v", err)
		}
		counts[res.Upstream.ID]++
	}

	// 80/20 split: verify ~800 prod and ~200 canary (with tolerance)
	prodCount := counts["u-openai-prod"]
	canaryCount := counts["u-openai-canary"]

	if prodCount < 700 || prodCount > 900 {
		t.Errorf("expected prod count ~800, got %d", prodCount)
	}
	if canaryCount < 100 || canaryCount > 300 {
		t.Errorf("expected canary count ~200, got %d", canaryCount)
	}
}

func TestRouter_RegexMatchingAndRetryBudget(t *testing.T) {
	snap := &config.Snapshot{
		Version: 1,
		Upstreams: map[string]config.UpstreamCluster{
			"u1": {ID: "u1", Protocol: "http", Endpoints: []string{"http://localhost:8000"}},
		},
		Routes: []config.RouteRule{
			{
				ID:         "regex-path-route",
				Path:       "^/v1/users/[0-9]+/profile$",
				Method:     "GET",
				UpstreamID: "u1",
			},
			{
				ID:         "regex-header-route",
				Path:       "/v1/secure",
				Method:     "GET",
				UpstreamID: "u1",
				Headers: map[string]string{
					"X-API-Key": "^sec_[a-z0-9]{8}$",
				},
				RetryPolicy: &config.RetryPolicy{
					MaxRetries: 2,
				},
			},
			{
				ID:         "regex-host-route",
				Host:       "^gateway-(dev|stage)\\.torana\\.internal$",
				Path:       "/v1/internal",
				Method:     "GET",
				UpstreamID: "u1",
			},
		},
	}

	r := router.Compile(snap)

	// 1. Path regex matching
	res, err := r.Match(router.MatchCriteria{
		Method: "GET",
		Path:   "/v1/users/4281/profile",
	})
	if err != nil || res.Route.ID != "regex-path-route" {
		t.Fatalf("expected regex path match, got err=%v", err)
	}

	// 2. Header regex matching
	res, err = r.Match(router.MatchCriteria{
		Method:  "GET",
		Path:    "/v1/secure",
		Headers: map[string]string{"X-API-Key": "sec_1a2b3c4d"},
	})
	if err != nil || res.Route.ID != "regex-header-route" {
		t.Fatalf("expected regex header match, got err=%v", err)
	}
	if res.RetryBudget == nil {
		t.Fatalf("expected retry budget initialized on route with retry policy")
	}
	if !res.RetryBudget.AllowRetry() {
		t.Errorf("expected retry budget to allow initial retry")
	}

	// 3. Header regex mismatch
	_, err = r.Match(router.MatchCriteria{
		Method:  "GET",
		Path:    "/v1/secure",
		Headers: map[string]string{"X-API-Key": "invalid_key"},
	})
	if err == nil {
		t.Fatalf("expected match error on invalid header regex")
	}

	// 4. Host regex match
	res, err = r.Match(router.MatchCriteria{
		Host:   "gateway-stage.torana.internal",
		Method: "GET",
		Path:   "/v1/internal",
	})
	if err != nil || res.Route.ID != "regex-host-route" {
		t.Fatalf("expected regex host match, got err=%v", err)
	}
}

func BenchmarkRouter_MatchExact(b *testing.B) {
	r := router.Compile(sampleAdvancedSnapshot())
	criteria := router.MatchCriteria{
		Host:   "api.torana.ai",
		Method: "POST",
		Path:   "/v1/chat/completions",
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			res, err := r.Match(criteria)
			if err != nil || res.Route == nil {
				b.Fatal(err)
			}
		}
	})
}
