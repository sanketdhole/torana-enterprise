package authz

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/phaselume/torana/internal/security/authn"
)

// PolicyEngine executes pre-compiled CEL authorization rules.
type PolicyEngine struct {
	rules       []*CompiledRule
	auditBuffer *AuditBuffer
}

// NewPolicyEngine creates a PolicyEngine with pre-compiled rules and an async audit buffer.
func NewPolicyEngine(rules []*CompiledRule, auditBuffer *AuditBuffer) *PolicyEngine {
	// Sort rules by priority descending
	sorted := make([]*CompiledRule, len(rules))
	copy(sorted, rules)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].Rule.Priority > sorted[j].Rule.Priority
	})

	return &PolicyEngine{
		rules:       sorted,
		auditBuffer: auditBuffer,
	}
}

// Evaluate performs deny-overrides authorization evaluation over caller identity, resource, action, and request.
func (e *PolicyEngine) Evaluate(ctx context.Context, ident *authn.Identity, res Resource, act Action, req RequestAttributes) error {
	start := time.Now()

	// Validate resource type
	if !res.Type.Valid() {
		e.emitDecision(DecisionLog{
			Timestamp:    start,
			Effect:       EffectDeny,
			Reason:       fmt.Sprintf("invalid resource type %q", res.Type),
			Latency:      time.Since(start),
			Subject:      getSubject(ident),
			Tenant:       getTenant(ident),
			ResourceType: res.Type,
			ResourceID:   res.ID,
			Action:       act.Name,
		})
		return ErrInvalidResourceType
	}

	evalContext := map[string]any{
		"identity": buildIdentityMap(ident),
		"resource": buildResourceMap(res),
		"action":   buildActionMap(act),
		"request":  buildRequestMap(req),
	}

	hasAllow := false
	matchingAllowRuleID := ""

	// Evaluate ordered rules under Deny-Overrides semantics
	for _, cr := range e.rules {
		out, _, err := cr.Program.Eval(evalContext)
		if err != nil {
			// Fail closed on evaluation error
			latency := time.Since(start)
			e.emitDecision(DecisionLog{
				Timestamp:    start,
				RuleID:       cr.Rule.ID,
				Effect:       EffectDeny,
				Reason:       fmt.Sprintf("cel eval error: %v", err),
				Latency:      latency,
				Subject:      getSubject(ident),
				Tenant:       getTenant(ident),
				ResourceType: res.Type,
				ResourceID:   res.ID,
				Action:       act.Name,
			})
			return fmt.Errorf("%w: evaluation error on rule %q: %v", ErrAccessDenied, cr.Rule.ID, err)
		}

		matched, isBool := out.Value().(bool)
		if isBool && matched {
			if cr.Rule.Effect == EffectDeny {
				// Deny overrides allow immediately!
				latency := time.Since(start)
				e.emitDecision(DecisionLog{
					Timestamp:    start,
					RuleID:       cr.Rule.ID,
					Effect:       EffectDeny,
					Reason:       fmt.Sprintf("denied by rule %q", cr.Rule.ID),
					Latency:      latency,
					Subject:      getSubject(ident),
					Tenant:       getTenant(ident),
					ResourceType: res.Type,
					ResourceID:   res.ID,
					Action:       act.Name,
				})
				return fmt.Errorf("%w: matched deny rule %q", ErrAccessDenied, cr.Rule.ID)
			} else if cr.Rule.Effect == EffectAllow {
				hasAllow = true
				if matchingAllowRuleID == "" {
					matchingAllowRuleID = cr.Rule.ID
				}
			}
		}
	}

	latency := time.Since(start)

	if hasAllow {
		e.emitDecision(DecisionLog{
			Timestamp:    start,
			RuleID:       matchingAllowRuleID,
			Effect:       EffectAllow,
			Reason:       fmt.Sprintf("allowed by rule %q", matchingAllowRuleID),
			Latency:      latency,
			Subject:      getSubject(ident),
			Tenant:       getTenant(ident),
			ResourceType: res.Type,
			ResourceID:   res.ID,
			Action:       act.Name,
		})
		return nil
	}

	// Default Deny: no matching allow rule
	e.emitDecision(DecisionLog{
		Timestamp:    start,
		RuleID:       "default_deny",
		Effect:       EffectDeny,
		Reason:       "no matching allow rule found (default deny)",
		Latency:      latency,
		Subject:      getSubject(ident),
		Tenant:       getTenant(ident),
		ResourceType: res.Type,
		ResourceID:   res.ID,
		Action:       act.Name,
	})
	return ErrDefaultDeny
}

func (e *PolicyEngine) emitDecision(entry DecisionLog) {
	if e.auditBuffer != nil {
		e.auditBuffer.Emit(entry)
	}
}

func buildIdentityMap(id *authn.Identity) map[string]any {
	if id == nil {
		return map[string]any{
			"subject":     "",
			"tenant":      "",
			"groups":      []string{},
			"scopes":      []string{},
			"claims":      map[string]any{},
			"auth_method": "",
		}
	}
	claims := id.Claims
	if claims == nil {
		claims = make(map[string]any)
	}
	return map[string]any{
		"subject":     id.Subject,
		"tenant":      id.Tenant,
		"groups":      id.Groups,
		"scopes":      id.Scopes,
		"claims":      claims,
		"auth_method": id.AuthMethod,
	}
}

func buildResourceMap(res Resource) map[string]any {
	props := res.Properties
	if props == nil {
		props = make(map[string]any)
	}
	return map[string]any{
		"type":       string(res.Type),
		"id":         res.ID,
		"namespace":  res.Namespace,
		"properties": props,
	}
}

func buildActionMap(act Action) map[string]any {
	return map[string]any{
		"name":   act.Name,
		"method": act.Method,
	}
}

func buildRequestMap(req RequestAttributes) map[string]any {
	headers := req.Headers
	if headers == nil {
		headers = make(map[string]string)
	}
	return map[string]any{
		"path":      req.Path,
		"method":    req.Method,
		"host":      req.Host,
		"remote_ip": req.RemoteIP,
		"headers":   headers,
	}
}

func getSubject(id *authn.Identity) string {
	if id != nil {
		return id.Subject
	}
	return ""
}

func getTenant(id *authn.Identity) string {
	if id != nil {
		return id.Tenant
	}
	return ""
}
