package pipeline_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/phaselume/torana/internal/pipeline"
)

type sampleFilter struct {
	name   string
	phase  pipeline.Phase
	mode   pipeline.BodyMode
	policy pipeline.FailurePolicy
}

func (s *sampleFilter) Name() string                         { return s.name }
func (s *sampleFilter) Phase() pipeline.Phase                 { return s.phase }
func (s *sampleFilter) BodyMode() pipeline.BodyMode           { return s.mode }
func (s *sampleFilter) FailurePolicy() pipeline.FailurePolicy { return s.policy }
func (s *sampleFilter) Process(_ context.Context, env *pipeline.Envelope) (pipeline.Decision, error) {
	if env.Headers.Get("X-Block") == "true" {
		return pipeline.HaltDecision(http.StatusForbidden, "blocked by sample filter"), nil
	}
	return pipeline.ContinueDecision(), nil
}
func (s *sampleFilter) Close() error { return nil }

func TestFilterLifecycle(t *testing.T) {
	filter := &sampleFilter{
		name:   "sample_filter",
		phase:  pipeline.PhaseRequestHeaders,
		mode:   pipeline.BodyModeNone,
		policy: pipeline.FailurePolicyFailClosed,
	}

	if filter.Name() != "sample_filter" {
		t.Errorf("expected name 'sample_filter', got %s", filter.Name())
	}
	if filter.Phase() != pipeline.PhaseRequestHeaders {
		t.Errorf("expected phase %v, got %v", pipeline.PhaseRequestHeaders, filter.Phase())
	}

	t.Run("continue decision", func(t *testing.T) {
		headers := make(http.Header)
		env := pipeline.GetEnvelope("req-1", pipeline.PhaseRequestHeaders, "POST", "/v1/chat", headers, nil)
		defer pipeline.PutEnvelope(env)

		decision, err := filter.Process(context.Background(), env)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Action != pipeline.ActionContinue {
			t.Errorf("expected ActionContinue, got %v", decision.Action)
		}
	})

	t.Run("envelope recycling pool", func(t *testing.T) {
		env := pipeline.GetEnvelope("req-pool", pipeline.PhaseRequestHeaders, "GET", "/test", nil, nil)
		env.SetMetadata("test_key", "test_val")
		pipeline.PutEnvelope(env)

		env2 := pipeline.GetEnvelope("req-pool-2", pipeline.PhaseRequestHeaders, "POST", "/test2", nil, nil)
		if len(env2.Metadata) != 0 {
			t.Errorf("expected metadata to be clean after pool get, got %v", env2.Metadata)
		}
		pipeline.PutEnvelope(env2)
	})
}
