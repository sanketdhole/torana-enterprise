package authz

import (
	"fmt"

	"cel.dev/cel-go/cel"
)

// CompileError represents a detailed compilation failure with rule ID and diagnostic messages.
type CompileError struct {
	RuleID  string
	Details string
}

func (e *CompileError) Error() string {
	return fmt.Sprintf("cel rule %q compilation failed: %s", e.RuleID, e.Details)
}

// CompilerConfig defines configuration for CEL compilation at snapshot-build time.
type CompilerConfig struct {
	// CostLimit defines maximum computational cost allowed for a CEL program (default 10000).
	CostLimit uint64
}

// CompiledRule holds a pre-compiled, ready-to-evaluate CEL program for a rule.
type CompiledRule struct {
	Rule    Rule
	Program cel.Program
}

// Compiler manages the CEL environment and compiles policy rules into executable programs.
type Compiler struct {
	env       *cel.Env
	costLimit uint64
}

// NewCompiler initializes a CEL environment with standard Torana variables.
func NewCompiler(cfg CompilerConfig) (*Compiler, error) {
	costLimit := cfg.CostLimit
	if costLimit == 0 {
		costLimit = 10000 // default cost limit to prevent ReDoS / CPU exhaustion
	}

	env, err := cel.NewEnv(
		// Variable declarations for the evaluation context
		cel.Variable("identity", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("resource", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("action", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	return &Compiler{
		env:       env,
		costLimit: costLimit,
	}, nil
}

// Compile compiles an individual Rule into an executable CompiledRule with cost limits.
// Returns a precise CompileError if the expression is invalid.
func (c *Compiler) Compile(rule Rule) (*CompiledRule, error) {
	if rule.Expression == "" {
		return nil, &CompileError{
			RuleID:  rule.ID,
			Details: "expression cannot be empty",
		}
	}

	// 1. Parse and Check AST
	ast, issues := c.env.Compile(rule.Expression)
	if issues != nil && issues.Err() != nil {
		return nil, &CompileError{
			RuleID:  rule.ID,
			Details: issues.Err().Error(),
		}
	}

	// 2. Ensure return type is boolean
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, &CompileError{
			RuleID:  rule.ID,
			Details: fmt.Sprintf("expression output type must be bool, got %v", ast.OutputType()),
		}
	}

	// 3. Build program with cost limits
	prgOpts := []cel.ProgramOption{}
	if c.costLimit > 0 {
		prgOpts = append(prgOpts, cel.CostLimit(c.costLimit))
	}

	prg, err := c.env.Program(ast, prgOpts...)
	if err != nil {
		return nil, &CompileError{
			RuleID:  rule.ID,
			Details: err.Error(),
		}
	}

	return &CompiledRule{
		Rule:    rule,
		Program: prg,
	}, nil
}

// CompileRules compiles a batch of rules. If any rule fails, returns a precise error for NACK.
func (c *Compiler) CompileRules(rules []Rule) ([]*CompiledRule, error) {
	compiled := make([]*CompiledRule, 0, len(rules))
	for _, r := range rules {
		cr, err := c.Compile(r)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, cr)
	}
	return compiled, nil
}
