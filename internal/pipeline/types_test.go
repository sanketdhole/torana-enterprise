package pipeline

import (
	"context"
	"net/http"
	"testing"
)

type sampleFilter struct {
	name  string
	phase Phase
	mode  BodyMode
}

func (s *sampleFilter) Name() string     { return s.name }
func (s *sampleFilter) Phase() Phase     { return s.phase }
func (s *sampleFilter) BodyMode() BodyMode { return s.mode }
func (s *sampleFilter) Process(_ context.Context, env *Envelope) (Decision, error) {
	if env.Headers.Get("X-Block") == "true" {
		return HaltDecision(http.StatusForbidden, "blocked by sample filter"), nil
	}
	return ContinueDecision(), nil
}
func (s *sampleFilter) Close() error { return nil }

func TestFilterLifecycle(t *testing.T) {
	filter := &sampleFilter{
		name:  "sample_filter",
		phase: PhaseRequestHeaders,
		mode:  BodyModeNone,
	}

	if filter.Name() != "sample_filter" {
		t.Errorf("expected name 'sample_filter', got %s", filter.Name())
	}
	if filter.Phase() != PhaseRequestHeaders {
		t.Errorf("expected phase %v, got %v", PhaseRequestHeaders, filter.Phase())
	}
	if filter.Phase().String() != "request_headers" {
		t.Errorf("expected string 'request_headers', got %s", filter.Phase().String())
	}

	t.Run("continue decision", func(t *testing.T) {
		headers := make(http.Header)
		env := NewEnvelope("req-1", PhaseRequestHeaders, "POST", "/v1/chat", headers, nil)
		decision, err := filter.Process(context.Background(), env)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Action != ActionContinue {
			t.Errorf("expected ActionContinue, got %v", decision.Action)
		}
	})

	t.Run("halt decision", func(t *testing.T) {
		headers := make(http.Header)
		headers.Set("X-Block", "true")
		env := NewEnvelope("req-2", PhaseRequestHeaders, "POST", "/v1/chat", headers, nil)
		decision, err := filter.Process(context.Background(), env)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if decision.Action != ActionHalt {
			t.Errorf("expected ActionHalt, got %v", decision.Action)
		}
		if decision.StatusCode != http.StatusForbidden {
			t.Errorf("expected status %d, got %d", http.StatusForbidden, decision.StatusCode)
		}
	})
}
