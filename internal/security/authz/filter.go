package authz

import (
	"context"
	"net/http"
	"time"

	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/security/authn"
)

// ResourceResolver extracts the target Resource from the envelope.
type ResourceResolver func(env *pipeline.Envelope) Resource

// DefaultResourceResolver resolves a Resource based on Route metadata or path.
func DefaultResourceResolver(env *pipeline.Envelope) Resource {
	resType := ResourceTypeRoute
	resID := env.Path
	ns := ""

	if env.Route != nil {
		resID = env.Route.ID
		if env.Route.UpstreamID != "" {
			ns = env.Route.UpstreamID
		}
	}

	// Check if envelope metadata specifies a specialized resource type
	if t, ok := env.Metadata["resource_type"]; ok && ResourceType(t).Valid() {
		resType = ResourceType(t)
	}
	if id, ok := env.Metadata["resource_id"]; ok && id != "" {
		resID = id
	}

	props := make(map[string]any, len(env.Metadata))
	for k, v := range env.Metadata {
		props[k] = v
	}

	return Resource{
		Type:       resType,
		ID:         resID,
		Namespace:  ns,
		Properties: props,
	}
}

// Filter is a pipeline filter that evaluates CEL authorization policies.
type Filter struct {
	engine           *PolicyEngine
	resourceResolver ResourceResolver
	phase            pipeline.Phase
}

// NewFilter creates an authorization filter.
func NewFilter(engine *PolicyEngine, resolver ResourceResolver) *Filter {
	if resolver == nil {
		resolver = DefaultResourceResolver
	}
	return &Filter{
		engine:           engine,
		resourceResolver: resolver,
		phase:            pipeline.PhaseRequestHeaders,
	}
}

func (f *Filter) Name() string {
	return "authz_cel_filter"
}

func (f *Filter) Phase() pipeline.Phase {
	return f.phase
}

func (f *Filter) BodyMode() pipeline.BodyMode {
	return pipeline.BodyModeNone
}

func (f *Filter) FailurePolicy() pipeline.FailurePolicy {
	return pipeline.FailurePolicyFailClosed
}

// Process evaluates authorization on the incoming request envelope.
func (f *Filter) Process(ctx context.Context, env *pipeline.Envelope) (pipeline.Decision, error) {
	ident, _ := authn.GetIdentity(env)
	res := f.resourceResolver(env)

	actionName := env.Method
	if a, ok := env.Metadata["action_name"]; ok && a != "" {
		actionName = a
	}

	act := Action{
		Name:   actionName,
		Method: env.Method,
	}

	headers := make(map[string]string)
	for k, vv := range env.Headers {
		if len(vv) > 0 {
			headers[k] = vv[0]
		}
	}

	req := RequestAttributes{
		Path:     env.Path,
		Method:   env.Method,
		RemoteIP: env.PeerInfo.RemoteIP,
		Headers:  headers,
		Time:     time.Now(),
	}

	err := f.engine.Evaluate(ctx, ident, res, act, req)
	if err != nil {
		return pipeline.HaltDecision(http.StatusForbidden, err.Error()), err
	}

	return pipeline.ContinueDecision(), nil
}

func (f *Filter) Close() error {
	return nil
}
