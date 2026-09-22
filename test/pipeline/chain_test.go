package pipeline_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/pipeline"
)

type mockPhaseAuthFilter struct {
	token  string
	phase  pipeline.Phase
	policy pipeline.FailurePolicy
}

func (m *mockPhaseAuthFilter) Name() string                         { return "mock_phase_auth" }
func (m *mockPhaseAuthFilter) Phase() pipeline.Phase                 { return m.phase }
func (m *mockPhaseAuthFilter) BodyMode() pipeline.BodyMode           { return pipeline.BodyModeNone }
func (m *mockPhaseAuthFilter) FailurePolicy() pipeline.FailurePolicy { return m.policy }
func (m *mockPhaseAuthFilter) Process(_ context.Context, env *pipeline.Envelope) (pipeline.Decision, error) {
	if env.Headers.Get("Authorization") != "Bearer "+m.token {
		return pipeline.HaltDecision(http.StatusUnauthorized, "invalid token"), nil
	}
	env.SetMetadata("user_id", "u_789")
	return pipeline.ContinueDecision(), nil
}
func (m *mockPhaseAuthFilter) Close() error { return nil }

type mockSlowFilter struct {
	delay  time.Duration
	policy pipeline.FailurePolicy
}

func (m *mockSlowFilter) Name() string                         { return "mock_slow" }
func (m *mockSlowFilter) Phase() pipeline.Phase                 { return pipeline.PhaseRequestHeaders }
func (m *mockSlowFilter) BodyMode() pipeline.BodyMode           { return pipeline.BodyModeNone }
func (m *mockSlowFilter) FailurePolicy() pipeline.FailurePolicy { return m.policy }
func (m *mockSlowFilter) Process(ctx context.Context, _ *pipeline.Envelope) (pipeline.Decision, error) {
	select {
	case <-time.After(m.delay):
		return pipeline.ContinueDecision(), nil
	case <-ctx.Done():
		return pipeline.HaltDecision(504, "timeout"), ctx.Err()
	}
}
func (m *mockSlowFilter) Close() error { return nil }

type mockFailingFilter struct {
	fails  int
	policy pipeline.FailurePolicy
}

func (m *mockFailingFilter) Name() string                         { return "mock_failing" }
func (m *mockFailingFilter) Phase() pipeline.Phase                 { return pipeline.PhaseRequestHeaders }
func (m *mockFailingFilter) BodyMode() pipeline.BodyMode           { return pipeline.BodyModeNone }
func (m *mockFailingFilter) FailurePolicy() pipeline.FailurePolicy { return m.policy }
func (m *mockFailingFilter) Process(_ context.Context, _ *pipeline.Envelope) (pipeline.Decision, error) {
	m.fails++
	return pipeline.HaltDecision(500, "internal plugin error"), errors.New("plugin crashed")
}
func (m *mockFailingFilter) Close() error { return nil }

func TestChain_PhaseExecutionAndBudgets(t *testing.T) {
	t.Run("phase latency budget exceeded", func(t *testing.T) {
		slowFilter := &mockSlowFilter{delay: 50 * time.Millisecond, policy: pipeline.FailurePolicyFailClosed}
		chain := pipeline.NewChain(slowFilter)

		env := pipeline.GetEnvelope("req-slow", pipeline.PhaseRequestHeaders, "POST", "/v1/chat", nil, nil)
		defer pipeline.PutEnvelope(env)

		decision, err := chain.ExecutePhase(context.Background(), env, pipeline.PhaseRequestHeaders, 10*time.Millisecond)
		if err == nil {
			t.Fatalf("expected error due to latency budget timeout")
		}
		if decision.StatusCode != 504 {
			t.Errorf("expected status 504, got %d", decision.StatusCode)
		}
	})

	t.Run("circuit breaker fail open policy", func(t *testing.T) {
		failingFilter := &mockFailingFilter{policy: pipeline.FailurePolicyFailOpen}
		chain := pipeline.NewChain(failingFilter)

		env := pipeline.GetEnvelope("req-failopen", pipeline.PhaseRequestHeaders, "POST", "/v1/chat", nil, nil)
		defer pipeline.PutEnvelope(env)

		decision, err := chain.ExecutePhase(context.Background(), env, pipeline.PhaseRequestHeaders, 0)
		if err != nil {
			t.Fatalf("expected no error under FailOpen policy, got %v", err)
		}
		if decision.Action != pipeline.ActionContinue {
			t.Errorf("expected ActionContinue under FailOpen, got %v", decision.Action)
		}
	})

	t.Run("phase matching only executes matching filters", func(t *testing.T) {
		reqFilter := &mockPhaseAuthFilter{token: "tok", phase: pipeline.PhaseRequestHeaders, policy: pipeline.FailurePolicyFailClosed}
		respFilter := &mockPhaseAuthFilter{token: "tok", phase: pipeline.PhaseResponseHeaders, policy: pipeline.FailurePolicyFailClosed}
		chain := pipeline.NewChain(reqFilter, respFilter)

		// Execute for ResponseHeaders phase: reqFilter should be skipped
		headers := make(http.Header)
		headers.Set("Authorization", "Bearer wrong-tok")
		env := pipeline.GetEnvelope("req-resp-phase", pipeline.PhaseResponseHeaders, "POST", "/v1/chat", headers, nil)
		defer pipeline.PutEnvelope(env)

		// In PhaseRequestHeaders, wrong token will halt
		decisionReq, _ := chain.ExecutePhase(context.Background(), env, pipeline.PhaseRequestHeaders, 0)
		if decisionReq.Action != pipeline.ActionHalt {
			t.Errorf("expected ActionHalt in RequestHeaders phase with invalid token")
		}

		// With valid token in ResponseHeaders phase
		headers.Set("Authorization", "Bearer tok")
		decisionResp, err := chain.ExecutePhase(context.Background(), env, pipeline.PhaseResponseHeaders, 0)
		if err != nil || decisionResp.Action != pipeline.ActionContinue {
			t.Errorf("expected ActionContinue in ResponseHeaders phase")
		}
	})
}

func BenchmarkPipeline_ExecutePhase(b *testing.B) {
	authFilter := &mockPhaseAuthFilter{token: "valid-tok", phase: pipeline.PhaseRequestHeaders, policy: pipeline.FailurePolicyFailClosed}
	chain := pipeline.NewChain(authFilter)

	headers := make(http.Header)
	headers.Set("Authorization", "Bearer valid-tok")

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			env := pipeline.GetEnvelope("req-bench", pipeline.PhaseRequestHeaders, "POST", "/v1/chat", headers, nil)
			_, _ = chain.ExecutePhase(context.Background(), env, pipeline.PhaseRequestHeaders, 0)
			pipeline.PutEnvelope(env)
		}
	})
}

func BenchmarkEnvelopePool(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			env := pipeline.GetEnvelope("req-bench", pipeline.PhaseRequestHeaders, "POST", "/v1/chat", nil, nil)
			env.SetMetadata("k", "v")
			pipeline.PutEnvelope(env)
		}
	})
}
