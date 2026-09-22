package fuzz_test

import (
	"testing"

	"github.com/phaselume/torana/internal/security/authz"
)

// FuzzCELCompile exercises the CEL policy compiler with random expression strings.
// Must never panic; must return a compiled rule or a CompileError.
func FuzzCELCompile(f *testing.F) {
	// Seed corpus: valid CEL expressions
	f.Add(`identity.sub == "admin"`)
	f.Add(`resource.type == "mcp_tool" && action.name == "tools/call"`)
	f.Add(`request.headers["x-tenant"] == "acme"`)
	f.Add(`true`)
	f.Add(`false`)
	f.Add(`identity.roles.exists(r, r == "editor")`)

	// Edge cases and adversarial inputs
	f.Add(``)                                        // empty expression
	f.Add(`1 + 2`)                                   // non-boolean return
	f.Add(`identity.sub == identity.sub == identity`) // type mismatch
	f.Add(`((((((((((()))))))))))`)                   // deeply nested parens
	f.Add("identity.sub == \"\x00\"")                // null byte in string
	f.Add(`a.b.c.d.e.f.g.h.i.j.k`)                  // deep access chain

	compiler, err := authz.NewCompiler(authz.CompilerConfig{CostLimit: 10000})
	if err != nil {
		f.Fatalf("failed to create CEL compiler: %v", err)
	}

	f.Fuzz(func(t *testing.T, expr string) {
		rule := authz.Rule{
			ID:         "fuzz-rule",
			Expression: expr,
			Effect:     authz.EffectAllow,
		}

		// Must not panic. Returns either a CompiledRule or an error.
		compiled, err := compiler.Compile(rule)
		if err != nil {
			// Expected for invalid expressions — not a bug.
			return
		}
		if compiled == nil {
			t.Error("Compile returned nil without error")
		}
	})
}
