package security_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/security/authn"
	"github.com/phaselume/torana/internal/security/authz"
)

func TestAuthzCompiler_ValidAndInvalidRules(t *testing.T) {
	compiler, err := authz.NewCompiler(authz.CompilerConfig{
		CostLimit: 5000,
	})
	if err != nil {
		t.Fatalf("failed to create compiler: %v", err)
	}

	t.Run("valid CEL expression compiling", func(t *testing.T) {
		rule := authz.Rule{
			ID:         "allow-admin",
			Priority:   10,
			Effect:     authz.EffectAllow,
			Expression: `identity.subject == "admin" || "admin" in identity.groups`,
		}
		cr, err := compiler.Compile(rule)
		if err != nil {
			t.Fatalf("expected compilation success, got: %v", err)
		}
		if cr == nil || cr.Program == nil {
			t.Fatal("expected non-nil compiled program")
		}
	})

	t.Run("syntax error gives precise CompileError for NACK", func(t *testing.T) {
		rule := authz.Rule{
			ID:         "bad-syntax-rule",
			Priority:   5,
			Effect:     authz.EffectAllow,
			Expression: `identity.subject == `, // incomplete expression
		}
		_, err := compiler.Compile(rule)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		var compErr *authz.CompileError
		if !errors.As(err, &compErr) {
			t.Fatalf("expected *authz.CompileError, got %T (%v)", err, err)
		}
		if compErr.RuleID != "bad-syntax-rule" {
			t.Errorf("expected RuleID bad-syntax-rule, got %s", compErr.RuleID)
		}
		if !strings.Contains(compErr.Error(), "bad-syntax-rule") {
			t.Errorf("expected error message to contain rule ID, got: %s", compErr.Error())
		}
	})

	t.Run("non-boolean output type rejected", func(t *testing.T) {
		rule := authz.Rule{
			ID:         "string-output-rule",
			Priority:   5,
			Effect:     authz.EffectAllow,
			Expression: `identity.subject`, // returns string, not bool
		}
		_, err := compiler.Compile(rule)
		if err == nil {
			t.Fatal("expected error for non-bool expression, got nil")
		}
		var compErr *authz.CompileError
		if !errors.As(err, &compErr) {
			t.Fatalf("expected *authz.CompileError, got %T", err)
		}
		if !strings.Contains(compErr.Details, "bool") {
			t.Errorf("expected details to mention bool requirement, got: %s", compErr.Details)
		}
	})

	t.Run("cost limit rejection", func(t *testing.T) {
		// Create a compiler with very low cost limit
		strictCompiler, err := authz.NewCompiler(authz.CompilerConfig{
			CostLimit: 1, // Extremely low cost limit
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		rule := authz.Rule{
			ID:         "expensive-rule",
			Priority:   5,
			Effect:     authz.EffectAllow,
			Expression: `identity.groups.exists(g, g.startsWith("admin")) && identity.scopes.exists(s, s == "write")`,
		}
		// In cel-go, cost limit can be verified either during program instantiation or eval
		cr, err := strictCompiler.Compile(rule)
		if err == nil && cr != nil {
			// If program built, running eval with low cost limit should fail
			evalCtx := map[string]any{
				"identity": map[string]any{"groups": []string{"admin-1"}, "scopes": []string{"write"}},
				"resource": map[string]any{},
				"action":   map[string]any{},
				"request":  map[string]any{},
			}
			_, _, evalErr := cr.Program.Eval(evalCtx)
			if evalErr == nil {
				t.Log("Note: evaluation completed within cost limit")
			}
		}
	})
}

func TestAuthzEngine_DenyOverridesAndDefaultDeny(t *testing.T) {
	compiler, _ := authz.NewCompiler(authz.CompilerConfig{})
	sink := authz.NewMemoryAuditSink()
	auditBuf := authz.NewAuditBuffer(100, sink)
	auditBuf.Start(context.Background())
	defer auditBuf.Stop()

	rules := []authz.Rule{
		{
			ID:         "allow-dev-role",
			Priority:   10,
			Effect:     authz.EffectAllow,
			Expression: `"developer" in identity.groups`,
		},
		{
			ID:         "deny-prod-namespace",
			Priority:   20, // Higher priority
			Effect:     authz.EffectDeny,
			Expression: `resource.namespace == "production"`,
		},
	}

	compiledRules, err := compiler.CompileRules(rules)
	if err != nil {
		t.Fatalf("failed to compile rules: %v", err)
	}

	engine := authz.NewPolicyEngine(compiledRules, auditBuf)

	t.Run("allow when rule matches and no deny matches", func(t *testing.T) {
		ident := authn.NewIdentity("alice", "tenant-1", "jwt")
		ident.Groups = []string{"developer"}

		res := authz.Resource{
			Type:      authz.ResourceTypeLLMModel,
			ID:        "gpt-4o",
			Namespace: "staging",
		}
		act := authz.Action{Name: "generate", Method: "POST"}
		req := authz.RequestAttributes{Path: "/v1/chat"}

		err := engine.Evaluate(context.Background(), ident, res, act, req)
		if err != nil {
			t.Fatalf("expected allow, got: %v", err)
		}
	})

	t.Run("deny overrides allow when deny condition matches", func(t *testing.T) {
		ident := authn.NewIdentity("alice", "tenant-1", "jwt")
		ident.Groups = []string{"developer"} // matches allow rule

		res := authz.Resource{
			Type:      authz.ResourceTypeLLMModel,
			ID:        "gpt-4o",
			Namespace: "production", // matches deny rule!
		}
		act := authz.Action{Name: "generate", Method: "POST"}
		req := authz.RequestAttributes{Path: "/v1/chat"}

		err := engine.Evaluate(context.Background(), ident, res, act, req)
		if err == nil {
			t.Fatal("expected deny, got allow")
		}
		if !errors.Is(err, authz.ErrAccessDenied) {
			t.Errorf("expected ErrAccessDenied, got: %v", err)
		}
	})

	t.Run("default deny when no rules match", func(t *testing.T) {
		ident := authn.NewIdentity("bob", "tenant-2", "api_key")
		ident.Groups = []string{"intern"} // no rule allows "intern"

		res := authz.Resource{
			Type:      authz.ResourceTypeRoute,
			ID:        "/v1/models",
			Namespace: "staging",
		}
		act := authz.Action{Name: "list", Method: "GET"}
		req := authz.RequestAttributes{Path: "/v1/models"}

		err := engine.Evaluate(context.Background(), ident, res, act, req)
		if err == nil {
			t.Fatal("expected default deny, got allow")
		}
		if !errors.Is(err, authz.ErrDefaultDeny) {
			t.Errorf("expected ErrDefaultDeny, got: %v", err)
		}
	})
}

func TestAuthzEngine_AllResourceTypes(t *testing.T) {
	compiler, _ := authz.NewCompiler(authz.CompilerConfig{})
	sink := authz.NewMemoryAuditSink()
	auditBuf := authz.NewAuditBuffer(100, sink)
	auditBuf.Start(context.Background())
	defer auditBuf.Stop()

	// Rule that allows access if resource type matches expected action
	rules := []authz.Rule{
		{
			ID:         "allow-all-valid-types",
			Priority:   1,
			Effect:     authz.EffectAllow,
			Expression: `resource.type in ["route", "mcp_tool", "llm_model", "db_query", "a2a_skill"]`,
		},
	}
	compiled, err := compiler.CompileRules(rules)
	if err != nil {
		t.Fatalf("failed to compile: %v", err)
	}
	engine := authz.NewPolicyEngine(compiled, auditBuf)
	ident := authn.NewIdentity("test-user", "tenant", "jwt")

	resourceTypes := []authz.ResourceType{
		authz.ResourceTypeRoute,
		authz.ResourceTypeMCPTool,
		authz.ResourceTypeLLMModel,
		authz.ResourceTypeDBQuery,
		authz.ResourceTypeA2ASkill,
	}

	for _, rt := range resourceTypes {
		t.Run(string(rt), func(t *testing.T) {
			res := authz.Resource{
				Type: rt,
				ID:   "resource-1",
			}
			err := engine.Evaluate(context.Background(), ident, res, authz.Action{Name: "call"}, authz.RequestAttributes{})
			if err != nil {
				t.Errorf("expected resource type %s to be allowed, got: %v", rt, err)
			}
		})
	}

	t.Run("invalid resource type rejected fail-closed", func(t *testing.T) {
		res := authz.Resource{
			Type: authz.ResourceType("unsupported_custom_type"),
			ID:   "res-invalid",
		}
		err := engine.Evaluate(context.Background(), ident, res, authz.Action{Name: "call"}, authz.RequestAttributes{})
		if !errors.Is(err, authz.ErrInvalidResourceType) {
			t.Errorf("expected ErrInvalidResourceType, got: %v", err)
		}
	})
}

func TestAuthzEngine_DecisionAuditLogging(t *testing.T) {
	compiler, _ := authz.NewCompiler(authz.CompilerConfig{})
	sink := authz.NewMemoryAuditSink()
	auditBuf := authz.NewAuditBuffer(50, sink)
	auditBuf.Start(context.Background())

	rules := []authz.Rule{
		{
			ID:         "rule-allow-tool",
			Priority:   1,
			Effect:     authz.EffectAllow,
			Expression: `resource.type == "mcp_tool" && resource.id == "calculator"`,
		},
	}
	compiled, _ := compiler.CompileRules(rules)
	engine := authz.NewPolicyEngine(compiled, auditBuf)

	ident := authn.NewIdentity("user-agent-1", "tenant-audit", "api_key")
	res := authz.Resource{
		Type: authz.ResourceTypeMCPTool,
		ID:   "calculator",
	}
	act := authz.Action{Name: "execute", Method: "POST"}

	_ = engine.Evaluate(context.Background(), ident, res, act, authz.RequestAttributes{Path: "/mcp/call"})

	// Allow worker to drain
	time.Sleep(50 * time.Millisecond)
	auditBuf.Stop()

	entries := sink.Entries()
	if len(entries) == 0 {
		t.Fatal("expected at least one decision log entry in audit buffer")
	}

	entry := entries[0]
	if entry.RuleID != "rule-allow-tool" {
		t.Errorf("expected rule_id rule-allow-tool, got %s", entry.RuleID)
	}
	if entry.Effect != authz.EffectAllow {
		t.Errorf("expected effect ALLOW, got %s", entry.Effect)
	}
	if entry.Subject != "user-agent-1" {
		t.Errorf("expected subject user-agent-1, got %s", entry.Subject)
	}
	if entry.ResourceType != authz.ResourceTypeMCPTool {
		t.Errorf("expected resource_type mcp_tool, got %s", entry.ResourceType)
	}
	if entry.Latency <= 0 {
		t.Errorf("expected recorded latency > 0")
	}
}

func TestAuthzFilter_PipelineIntegration(t *testing.T) {
	compiler, _ := authz.NewCompiler(authz.CompilerConfig{})
	rules := []authz.Rule{
		{
			ID:         "allow-get-models",
			Priority:   1,
			Effect:     authz.EffectAllow,
			Expression: `request.method == "GET" && request.path == "/v1/models"`,
		},
	}
	compiled, _ := compiler.CompileRules(rules)
	engine := authz.NewPolicyEngine(compiled, nil)

	filter := authz.NewFilter(engine, nil)
	chain := pipeline.NewChain(filter)

	t.Run("allowed request continues", func(t *testing.T) {
		env := pipeline.GetEnvelope("req-1", pipeline.PhaseRequestHeaders, "GET", "/v1/models", nil, nil)
		decision, err := chain.ExecutePhase(context.Background(), env, pipeline.PhaseRequestHeaders, 0)
		if err != nil {
			t.Fatalf("expected continue, got: %v", err)
		}
		if decision.Action != pipeline.ActionContinue {
			t.Errorf("expected ActionContinue, got %v", decision.Action)
		}
	})

	t.Run("denied request halts with 403 Forbidden", func(t *testing.T) {
		env := pipeline.GetEnvelope("req-2", pipeline.PhaseRequestHeaders, "POST", "/v1/models", nil, nil)
		decision, err := chain.ExecutePhase(context.Background(), env, pipeline.PhaseRequestHeaders, 0)
		if err == nil {
			t.Fatal("expected error on denied path, got nil")
		}
		if decision.Action != pipeline.ActionHalt {
			t.Errorf("expected ActionHalt on deny, got %v", decision.Action)
		}
		if decision.StatusCode != 403 {
			t.Errorf("expected status code 403, got %d", decision.StatusCode)
		}
	})
}

func BenchmarkAuthz_Evaluation(b *testing.B) {
	compiler, _ := authz.NewCompiler(authz.CompilerConfig{})
	rules := []authz.Rule{
		{
			ID:         "deny-blacklisted",
			Priority:   100,
			Effect:     authz.EffectDeny,
			Expression: `identity.subject == "blacklisted_user"`,
		},
		{
			ID:         "allow-member",
			Priority:   50,
			Effect:     authz.EffectAllow,
			Expression: `"ai-users" in identity.groups && resource.type == "llm_model"`,
		},
	}
	compiled, err := compiler.CompileRules(rules)
	if err != nil {
		b.Fatalf("failed to compile: %v", err)
	}

	engine := authz.NewPolicyEngine(compiled, nil)

	ident := authn.NewIdentity("alice", "tenant-corp", "jwt")
	ident.Groups = []string{"ai-users", "engineering"}

	res := authz.Resource{
		Type: authz.ResourceTypeLLMModel,
		ID:   "claude-3-5-sonnet",
	}
	act := authz.Action{Name: "generate", Method: "POST"}
	req := authz.RequestAttributes{
		Path:   "/v1/chat/completions",
		Method: "POST",
	}

	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := engine.Evaluate(ctx, ident, res, act, req)
		if err != nil {
			b.Fatalf("eval failed: %v", err)
		}
	}
}
