package pipeline

import (
	"context"
	"net/http"
	"testing"
)

type mockAuthFilter struct {
	token string
}

func (m *mockAuthFilter) Name() string     { return "mock_auth" }
func (m *mockAuthFilter) Phase() Phase     { return PhaseRequestHeaders }
func (m *mockAuthFilter) BodyMode() BodyMode { return BodyModeNone }
func (m *mockAuthFilter) Process(_ context.Context, env *Envelope) (Decision, error) {
	if env.Headers.Get("Authorization") != "Bearer "+m.token {
		return HaltDecision(http.StatusUnauthorized, "invalid token"), nil
	}
	env.SetMetadata("user_id", "u_456")
	return ContinueDecision(), nil
}
func (m *mockAuthFilter) Close() error { return nil }

type mockMutateFilter struct{}

func (m *mockMutateFilter) Name() string     { return "mock_mutate" }
func (m *mockMutateFilter) Phase() Phase     { return PhaseRequestHeaders }
func (m *mockMutateFilter) BodyMode() BodyMode { return BodyModeNone }
func (m *mockMutateFilter) Process(_ context.Context, _ *Envelope) (Decision, error) {
	return Decision{
		Action: ActionMutate,
		MutateHeaders: map[string]string{
			"X-Injected-Header": "Gateway-Torana",
		},
		MutateMetadata: map[string]string{
			"injected": "true",
		},
	}, nil
}
func (m *mockMutateFilter) Close() error { return nil }

func TestChain_Execute(t *testing.T) {
	chain := NewChain(
		&mockAuthFilter{token: "valid-secret"},
		&mockMutateFilter{},
	)

	t.Run("auth failure halts chain", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("Authorization", "Bearer wrong-token")
		env := NewEnvelope("req-1", PhaseRequestHeaders, "POST", "/v1/chat", headers, nil)

		decision, err := chain.Execute(context.Background(), env)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Action != ActionHalt {
			t.Errorf("expected ActionHalt, got %v", decision.Action)
		}
		if decision.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", decision.StatusCode)
		}
		if env.Headers.Get("X-Injected-Header") != "" {
			t.Errorf("expected mutated header not to be present on halted chain")
		}
	})

	t.Run("auth success applies mutations", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("Authorization", "Bearer valid-secret")
		env := NewEnvelope("req-2", PhaseRequestHeaders, "POST", "/v1/chat", headers, nil)

		decision, err := chain.Execute(context.Background(), env)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Action != ActionContinue {
			t.Errorf("expected ActionContinue, got %v", decision.Action)
		}
		if env.Headers.Get("X-Injected-Header") != "Gateway-Torana" {
			t.Errorf("expected header 'Gateway-Torana', got %s", env.Headers.Get("X-Injected-Header"))
		}
		if val, ok := env.GetMetadata("user_id"); !ok || val != "u_456" {
			t.Errorf("expected metadata user_id=u_456, got %s", val)
		}
		if val, ok := env.GetMetadata("injected"); !ok || val != "true" {
			t.Errorf("expected metadata injected=true, got %s", val)
		}
	})
}

func BenchmarkChain_Execute(b *testing.B) {
	chain := NewChain(
		&mockAuthFilter{token: "valid-secret"},
		&mockMutateFilter{},
	)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			headers := make(http.Header)
			headers.Set("Authorization", "Bearer valid-secret")
			env := NewEnvelope("req-bench", PhaseRequestHeaders, "POST", "/v1/chat", headers, nil)
			_, err := chain.Execute(context.Background(), env)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
