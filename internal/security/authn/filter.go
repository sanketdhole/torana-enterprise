package authn

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/phaselume/torana/internal/pipeline"
)

// FilterConfig configures the authentication filter.
type FilterConfig struct {
	Name           string
	Providers      []Provider
	RevocationList *RevocationList
	RequireAuth    bool
	Phase          pipeline.Phase
}

// Filter is a pipeline filter that executes authentication at the authn phase.
type Filter struct {
	name           string
	providers      []Provider
	revocationList *RevocationList
	requireAuth    bool
	phase          pipeline.Phase
}

// NewFilter creates an authentication filter.
func NewFilter(cfg FilterConfig) *Filter {
	name := cfg.Name
	if name == "" {
		name = "authn_filter"
	}
	phase := cfg.Phase
	if phase == 0 {
		phase = pipeline.PhaseAuthn
	}
	return &Filter{
		name:           name,
		providers:      cfg.Providers,
		revocationList: cfg.RevocationList,
		requireAuth:    cfg.RequireAuth,
		phase:          phase,
	}
}

// Name returns the filter name.
func (f *Filter) Name() string {
	return f.name
}

// Phase returns the lifecycle phase (PhaseAuthn).
func (f *Filter) Phase() pipeline.Phase {
	return f.phase
}

// BodyMode declares that authn inspects headers/metadata only.
func (f *Filter) BodyMode() pipeline.BodyMode {
	return pipeline.BodyModeNone
}

// FailurePolicy enforces fail-closed on any error.
func (f *Filter) FailurePolicy() pipeline.FailurePolicy {
	return pipeline.FailurePolicyFailClosed
}

// Process evaluates authentication providers against the incoming envelope.
func (f *Filter) Process(ctx context.Context, env *pipeline.Envelope) (pipeline.Decision, error) {
	var lastErr error
	hasCredentials := false

	for _, provider := range f.providers {
		ident, err := provider.Authenticate(ctx, env)
		if err == nil {
			// Check revocation list if configured
			if f.revocationList != nil {
				if f.revocationList.IsRevoked(ident.Subject) {
					return pipeline.HaltDecision(http.StatusUnauthorized, "identity revoked"), ErrRevoked
				}
			}

			// Authentication successful: attach identity to envelope
			SetIdentity(env, ident)
			return pipeline.ContinueDecision(), nil
		}

		if errors.Is(err, ErrNoCredentials) {
			continue
		}

		// Credential was presented but failed validation -> Fail closed immediately!
		hasCredentials = true
		lastErr = err
		statusCode := http.StatusUnauthorized
		return pipeline.HaltDecision(statusCode, err.Error()), fmt.Errorf("authentication provider %q failed: %w", provider.Name(), err)
	}

	// No provider accepted the request
	if f.requireAuth || hasCredentials {
		msg := "unauthorized: authentication required"
		if lastErr != nil {
			msg = lastErr.Error()
		}
		return pipeline.HaltDecision(http.StatusUnauthorized, msg), pipeline.ErrUnauthorized
	}

	return pipeline.ContinueDecision(), nil
}

// Close releases any allocated resources.
func (f *Filter) Close() error {
	return nil
}
