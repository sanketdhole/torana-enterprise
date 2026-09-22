package limits

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/security/authn"
)

// PreCheckFilter evaluates rate limits and reserves estimated token budgets before upstream dispatch.
type PreCheckFilter struct {
	limiter          *Limiter
	defaultMaxTokens int64
	phase            pipeline.Phase
}

// NewPreCheckFilter constructs an upstream rate limit pre-check filter.
func NewPreCheckFilter(limiter *Limiter, defaultMaxTokens int64) *PreCheckFilter {
	if defaultMaxTokens <= 0 {
		defaultMaxTokens = 1000
	}
	return &PreCheckFilter{
		limiter:          limiter,
		defaultMaxTokens: defaultMaxTokens,
		phase:            pipeline.PhaseRequestHeaders,
	}
}

func (f *PreCheckFilter) Name() string {
	return "limits_precheck_filter"
}

func (f *PreCheckFilter) Phase() pipeline.Phase {
	return f.phase
}

func (f *PreCheckFilter) BodyMode() pipeline.BodyMode {
	return pipeline.BodyModeNone
}

func (f *PreCheckFilter) FailurePolicy() pipeline.FailurePolicy {
	return pipeline.FailurePolicyFailClosed
}

// Process evaluates request rate and reserves token budget.
func (f *PreCheckFilter) Process(ctx context.Context, env *pipeline.Envelope) (pipeline.Decision, error) {
	keys := f.extractDimensions(env)

	// Estimate token requirement
	estimatedTokens := f.estimateTokens(env)

	res, err := f.limiter.PreCheck(ctx, keys, estimatedTokens)
	if err != nil {
		// Rate limit or budget exceeded: return standard HTTP 429
		retryAfterStr := strconv.Itoa(err.RetryAfter)
		jsonBody := err.ToJSON()

		env.Headers.Set("Retry-After", retryAfterStr)

		decision := pipeline.Decision{
			Action:     pipeline.ActionHalt,
			StatusCode: http.StatusTooManyRequests,
			Reason:     err.Reason,
			MutateHeaders: map[string]string{
				"Retry-After":  retryAfterStr,
				"Content-Type": "application/json",
			},
			MutateBody: jsonBody,
		}
		return decision, fmt.Errorf("%w: %s", ErrRateLimitExceeded, err.Reason)
	}

	// Attach reservation details to envelope metadata
	if res != nil && res.ID != "" {
		env.SetMetadata("limits.reservation_id", res.ID)
		env.SetMetadata("limits.reserved_tokens", strconv.FormatInt(res.ReservedTokens, 10))
	}

	return pipeline.ContinueDecision(), nil
}

func (f *PreCheckFilter) Close() error {
	return nil
}

func (f *PreCheckFilter) extractDimensions(env *pipeline.Envelope) DimensionKeys {
	keys := DimensionKeys{
		Identity: env.PeerInfo.ClientIdentity,
		Route:    env.Path,
	}

	if env.Route != nil && env.Route.ID != "" {
		keys.Route = env.Route.ID
	}

	// Try extracting from Identity struct if attached
	if ident, ok := authn.GetIdentity(env); ok && ident != nil {
		if keys.Identity == "" {
			keys.Identity = ident.Subject
		}
		keys.Team = ident.Tenant
	}

	// Model extraction: check metadata, headers
	if m, ok := env.Metadata["model"]; ok && m != "" {
		keys.Model = m
	} else if h := env.Headers.Get("X-Model-ID"); h != "" {
		keys.Model = h
	}

	if t := env.Headers.Get("X-Team-ID"); t != "" && keys.Team == "" {
		keys.Team = t
	}

	return keys
}

func (f *PreCheckFilter) estimateTokens(env *pipeline.Envelope) int64 {
	// Check header hint
	if hint := env.Headers.Get("X-Estimated-Tokens"); hint != "" {
		if parsed, err := strconv.ParseInt(hint, 10, 64); err == nil && parsed > 0 {
			return parsed
		}
	}

	if len(env.BufferedBody) > 0 {
		return EstimateTokens(env.BufferedBody, f.defaultMaxTokens)
	}

	return f.defaultMaxTokens
}

// ReconciliationFilter reconciles reserved token budgets with actual usage post-response.
type ReconciliationFilter struct {
	limiter *Limiter
	phase   pipeline.Phase
}

// NewReconciliationFilter creates a post-response token reconciliation filter.
func NewReconciliationFilter(limiter *Limiter) *ReconciliationFilter {
	return &ReconciliationFilter{
		limiter: limiter,
		phase:   pipeline.PhaseResponseHeaders,
	}
}

func (f *ReconciliationFilter) Name() string {
	return "limits_reconciliation_filter"
}

func (f *ReconciliationFilter) Phase() pipeline.Phase {
	return f.phase
}

func (f *ReconciliationFilter) BodyMode() pipeline.BodyMode {
	return pipeline.BodyModeNone
}

func (f *ReconciliationFilter) FailurePolicy() pipeline.FailurePolicy {
	// Post-response accounting failure should not fail the user's completed request
	return pipeline.FailurePolicyFailOpen
}

// Process reconciles actual token usage with the active reservation.
func (f *ReconciliationFilter) Process(ctx context.Context, env *pipeline.Envelope) (pipeline.Decision, error) {
	reservationID, ok := env.GetMetadata("limits.reservation_id")
	if !ok || reservationID == "" {
		return pipeline.ContinueDecision(), nil
	}

	var actualTokens int64
	var foundUsage bool

	// 1. Check response headers
	if h := env.Headers.Get("x-total-tokens"); h != "" {
		if parsed, err := strconv.ParseInt(h, 10, 64); err == nil {
			actualTokens = parsed
			foundUsage = true
		}
	} else if h := env.Headers.Get("openai-processing-tokens"); h != "" {
		if parsed, err := strconv.ParseInt(h, 10, 64); err == nil {
			actualTokens = parsed
			foundUsage = true
		}
	}

	// 2. Check buffered body if available
	if !foundUsage && len(env.BufferedBody) > 0 {
		if usage, ok := ParseUsageFromBody(env.BufferedBody); ok {
			actualTokens = usage.TotalTokens
			foundUsage = true
		}
	}

	// If no usage found, assume actual == reserved to prevent drift
	if !foundUsage {
		if rStr, ok := env.GetMetadata("limits.reserved_tokens"); ok {
			if parsed, err := strconv.ParseInt(rStr, 10, 64); err == nil {
				actualTokens = parsed
			}
		}
	}

	_ = f.limiter.Reconcile(ctx, reservationID, actualTokens)
	return pipeline.ContinueDecision(), nil
}

func (f *ReconciliationFilter) Close() error {
	return nil
}
