package limits_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/limits"
	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/security/authn"
)

type dynamicPeerCount struct {
	count atomic.Int64
}

func (d *dynamicPeerCount) LivePeerCount(_ context.Context) int {
	return int(d.count.Load())
}

func TestTokenBucket_RateLimiting(t *testing.T) {
	// Rate: 10 req/s, Burst: 5
	tb := limits.NewTokenBucket(10.0, 5)

	// Consume all 5 burst tokens
	for i := 0; i < 5; i++ {
		allowed, _ := tb.Allow()
		if !allowed {
			t.Fatalf("expected burst token %d to be allowed", i+1)
		}
	}

	// 6th request should be denied
	allowed, retryAfter := tb.Allow()
	if allowed {
		t.Fatal("expected 6th request to be denied after burst exhaustion")
	}
	if retryAfter <= 0 {
		t.Errorf("expected positive retry-after duration, got %v", retryAfter)
	}

	// Wait for token replenishment (150ms should replenish 1.5 tokens)
	time.Sleep(150 * time.Millisecond)
	allowed, _ = tb.Allow()
	if !allowed {
		t.Error("expected request to be allowed after token bucket refill")
	}
}

func TestLimiter_TwoStageAccounting(t *testing.T) {
	store := limits.NewLocalCounterStore(limits.StaticPeerCount{Count: 1}, 1*time.Minute)
	defer func() { _ = store.Close() }()

	budget := &limits.BudgetRule{
		Limits: map[limits.Window]int64{
			limits.WindowMinute: 10000,
			limits.WindowDay:    100000,
		},
	}

	limiter := limits.NewLimiter(limits.LimiterConfig{
		Store:         store,
		DefaultBudget: budget,
	})
	defer func() { _ = limiter.Close() }()

	ctx := context.Background()
	keys := limits.DimensionKeys{
		Identity: "user-123",
		Team:     "team-alpha",
		Route:    "/v1/chat",
		Model:    "gpt-4o",
	}

	// Stage 1: Pre-Check Reservation of 3,000 estimated tokens
	res, rErr := limiter.PreCheck(ctx, keys, 3000)
	if rErr != nil {
		t.Fatalf("pre-check reservation failed: %v", rErr)
	}
	if res == nil || res.ID == "" {
		t.Fatal("expected valid reservation ID")
	}
	if res.ReservedTokens != 3000 {
		t.Errorf("expected 3000 reserved tokens, got %d", res.ReservedTokens)
	}

	// Stage 2: Reconcile with actual usage (e.g., actual tokens = 1,800, refunding 1,200)
	err := limiter.Reconcile(ctx, res.ID, 1800)
	if err != nil {
		t.Fatalf("reconciliation failed: %v", err)
	}

	// Verify next reservation of 8,000 tokens succeeds because 10,000 - 1,800 = 8,200 available
	res2, rErr := limiter.PreCheck(ctx, keys, 8000)
	if rErr != nil {
		t.Fatalf("expected reservation of 8000 tokens to succeed, got: %v", rErr)
	}

	// But an additional reservation of 1,000 should fail (1,800 + 8,000 + 1,000 = 10,800 > 10,000)
	_, rErrExceeded := limiter.PreCheck(ctx, keys, 1000)
	if rErrExceeded == nil {
		t.Fatal("expected token budget to be exceeded, got nil")
	}
	if rErrExceeded.Code != "TOKEN_BUDGET_EXCEEDED" {
		t.Errorf("expected TOKEN_BUDGET_EXCEEDED, got %s", rErrExceeded.Code)
	}
	if rErrExceeded.RetryAfter <= 0 {
		t.Errorf("expected positive RetryAfter, got %d", rErrExceeded.RetryAfter)
	}

	_ = limiter.Reconcile(ctx, res2.ID, 8000)
}

func TestLimiter_LocalStoreQuotaShare(t *testing.T) {
	peerCount := &dynamicPeerCount{}
	peerCount.count.Store(4) // 4 live peers

	store := limits.NewLocalCounterStore(peerCount, 1*time.Minute)
	defer func() { _ = store.Close() }()

	// Total quota is 10,000 tokens per minute -> Local share per peer is 2,500
	budget := &limits.BudgetRule{
		Limits: map[limits.Window]int64{
			limits.WindowMinute: 10000,
		},
	}

	limiter := limits.NewLimiter(limits.LimiterConfig{
		Store:         store,
		DefaultBudget: budget,
	})
	defer func() { _ = limiter.Close() }()

	ctx := context.Background()
	keys := limits.DimensionKeys{
		Identity: "peer-user",
		Team:     "shared-team",
		Model:    "claude-3-5",
	}

	// Reserving 2,000 on this local node should succeed (2,000 <= 2,500)
	res, rErr := limiter.PreCheck(ctx, keys, 2000)
	if rErr != nil {
		t.Fatalf("expected 2000 tokens to be reserved within local share of 2500: %v", rErr)
	}

	// Reserving another 1,000 on this local node should exceed local share (2,000 + 1,000 = 3,000 > 2,500)
	_, rErrExceeded := limiter.PreCheck(ctx, keys, 1000)
	if rErrExceeded == nil {
		t.Fatal("expected local quota share to be exceeded, got nil")
	}

	_ = limiter.Reconcile(ctx, res.ID, 2000)
}

func TestLimits_PreCheckAndReconciliationFilters(t *testing.T) {
	store := limits.NewLocalCounterStore(limits.StaticPeerCount{Count: 1}, 1*time.Minute)
	defer func() { _ = store.Close() }()

	budget := &limits.BudgetRule{
		Limits: map[limits.Window]int64{
			limits.WindowMinute: 5000,
		},
	}
	rate := &limits.RateLimitRule{
		Rate:  100,
		Burst: 10,
	}

	limiter := limits.NewLimiter(limits.LimiterConfig{
		Store:         store,
		DefaultBudget: budget,
		DefaultRate:   rate,
	})
	defer func() { _ = limiter.Close() }()

	preCheckFilter := limits.NewPreCheckFilter(limiter, 1000)
	reconcileFilter := limits.NewReconciliationFilter(limiter)

	chain := pipeline.NewChain(preCheckFilter, reconcileFilter)

	t.Run("successful request with reservation and reconciliation", func(t *testing.T) {
		env := pipeline.GetEnvelope("req-lim-1", pipeline.PhaseRequestHeaders, "POST", "/v1/chat", nil, nil)
		env.Headers.Set("X-Estimated-Tokens", "1500")
		authn.SetIdentity(env, authn.NewIdentity("user-filter", "tenant-filter", "jwt"))

		// 1. Run Pre-Check Filter
		decision, err := chain.ExecutePhase(context.Background(), env, pipeline.PhaseRequestHeaders, 0)
		if err != nil {
			t.Fatalf("expected precheck continue, got error: %v", err)
		}
		if decision.Action != pipeline.ActionContinue {
			t.Errorf("expected ActionContinue, got %v", decision.Action)
		}

		resID, ok := env.GetMetadata("limits.reservation_id")
		if !ok || resID == "" {
			t.Fatal("expected limits.reservation_id in envelope metadata")
		}

		// 2. Simulate upstream response with actual token usage
		respBody := `{"id":"chat-1","choices":[],"usage":{"prompt_tokens":300,"completion_tokens":400,"total_tokens":700}}`
		env.BufferedBody = []byte(respBody)

		// 3. Run Reconciliation Filter
		respDecision, err := chain.ExecutePhase(context.Background(), env, pipeline.PhaseResponseHeaders, 0)
		if err != nil {
			t.Fatalf("expected reconciliation continue, got error: %v", err)
		}
		if respDecision.Action != pipeline.ActionContinue {
			t.Errorf("expected ActionContinue on response, got %v", respDecision.Action)
		}
	})

	t.Run("exceeded budget returns standard 429 with Retry-After and JSON body", func(t *testing.T) {
		env := pipeline.GetEnvelope("req-lim-overflow", pipeline.PhaseRequestHeaders, "POST", "/v1/chat", nil, nil)
		// Request 10,000 tokens when budget is 5,000
		env.Headers.Set("X-Estimated-Tokens", "10000")
		authn.SetIdentity(env, authn.NewIdentity("user-overflow", "tenant-overflow", "jwt"))

		decision, err := chain.ExecutePhase(context.Background(), env, pipeline.PhaseRequestHeaders, 0)
		if err == nil {
			t.Fatal("expected rate limit error, got nil")
		}
		if decision.Action != pipeline.ActionHalt {
			t.Errorf("expected ActionHalt, got %v", decision.Action)
		}
		if decision.StatusCode != http.StatusTooManyRequests {
			t.Errorf("expected HTTP 429, got %d", decision.StatusCode)
		}

		// Check Retry-After header
		retryAfter := env.Headers.Get("Retry-After")
		if retryAfter == "" {
			t.Error("expected Retry-After header to be set")
		}

		// Check machine-readable JSON body
		if len(decision.MutateBody) == 0 {
			t.Fatal("expected JSON error body in decision")
		}

		var errPayload limits.RateLimitError
		if err := json.Unmarshal(decision.MutateBody, &errPayload); err != nil {
			t.Fatalf("failed to parse 429 JSON response: %v", err)
		}
		if errPayload.Code != "TOKEN_BUDGET_EXCEEDED" {
			t.Errorf("expected TOKEN_BUDGET_EXCEEDED, got %s", errPayload.Code)
		}
		if errPayload.RetryAfter <= 0 {
			t.Errorf("expected positive RetryAfter in JSON, got %d", errPayload.RetryAfter)
		}
	})
}

func TestLimits_ConcurrencyRace(t *testing.T) {
	store := limits.NewLocalCounterStore(limits.StaticPeerCount{Count: 1}, 1*time.Minute)
	defer func() { _ = store.Close() }()

	budget := &limits.BudgetRule{
		Limits: map[limits.Window]int64{
			limits.WindowMinute: 1_000_000,
		},
	}
	rate := &limits.RateLimitRule{
		Rate:  10000,
		Burst: 5000,
	}

	limiter := limits.NewLimiter(limits.LimiterConfig{
		Store:         store,
		DefaultBudget: budget,
		DefaultRate:   rate,
	})
	defer func() { _ = limiter.Close() }()

	const numGoroutines = 50
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			ctx := context.Background()
			keys := limits.DimensionKeys{
				Identity: fmt.Sprintf("user-%d", gid%5),
				Team:     "concurrent-team",
				Model:    "gpt-4o",
			}

			for i := 0; i < iterations; i++ {
				res, rErr := limiter.PreCheck(ctx, keys, 100)
				if rErr == nil && res != nil && res.ID != "" {
					_ = limiter.Reconcile(ctx, res.ID, 80)
				}
			}
		}(g)
	}

	wg.Wait()
}

func BenchmarkPreCheck_TokenBucket(b *testing.B) {
	tb := limits.NewTokenBucket(1_000_000, 500_000)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = tb.Allow()
	}
}

func BenchmarkTwoStageAccounting(b *testing.B) {
	store := limits.NewLocalCounterStore(limits.StaticPeerCount{Count: 1}, 10*time.Minute)
	defer func() { _ = store.Close() }()

	budget := &limits.BudgetRule{
		Limits: map[limits.Window]int64{
			limits.WindowMinute: 100_000_000,
		},
	}

	limiter := limits.NewLimiter(limits.LimiterConfig{
		Store:         store,
		DefaultBudget: budget,
	})
	defer func() { _ = limiter.Close() }()

	ctx := context.Background()
	keys := limits.DimensionKeys{
		Identity: "bench-user",
		Team:     "bench-team",
		Model:    "gpt-4o",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		res, rErr := limiter.PreCheck(ctx, keys, 100)
		if rErr != nil {
			b.Fatalf("precheck failed: %v", rErr)
		}
		if err := limiter.Reconcile(ctx, res.ID, 90); err != nil {
			b.Fatalf("reconcile failed: %v", err)
		}
	}
}
