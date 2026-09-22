package security_test

import (
	"context"
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/security/authn"
	"github.com/phaselume/torana/internal/security/sts"
)

func TestSTS_MintEd25519DownstreamToken(t *testing.T) {
	pub, priv := generateEd25519Key(t)
	const namespace = "production-ai"
	const keyID = "ns-key-2026"
	const downstreamAudience = "upstream-llm-service"

	stsService, err := sts.NewService(sts.Config{
		Namespace:  namespace,
		SigningKey: priv,
		KeyID:      keyID,
		DefaultTTL: 5 * time.Minute,
		MaxTTL:     30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to create STS service: %v", err)
	}

	ident := authn.NewIdentity("user-agent-777", "tenant-omega", "api_key")
	ident.Groups = []string{"ai-agents", "finance"}
	ident.Scopes = []string{"generate:completion", "read:embeddings"}
	ident.Claims["custom_billing_tag"] = "cost-center-9"

	// 1. Mint downstream token
	tokenStr, err := stsService.MintDownstreamToken(
		context.Background(),
		ident,
		sts.WithAudience(downstreamAudience),
		sts.WithTTL(2*time.Minute),
		sts.WithExtraClaims(map[string]any{
			"injected_policy": "strict-safety",
		}),
	)
	if err != nil {
		t.Fatalf("failed to mint downstream token: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty token string")
	}

	// 2. Round-trip validation using JWTProvider
	jwtValidator := authn.NewJWTProvider([]*authn.IssuerConfig{
		{
			Issuer:    "https://torana.internal/" + namespace + "/sts",
			Audiences: []string{downstreamAudience},
			StaticKeys: map[string]crypto.PublicKey{
				keyID: pub,
			},
			AllowedAlgorithms: []string{"EdDSA"},
		},
	}, nil)

	env := pipeline.GetEnvelope("req-sts-val", pipeline.PhaseAuthn, "POST", "/v1/models", nil, nil)
	env.Headers.Set("Authorization", "Bearer "+tokenStr)

	downstreamIdent, err := jwtValidator.Authenticate(context.Background(), env)
	if err != nil {
		t.Fatalf("expected minted STS token to validate against JWTProvider, got: %v", err)
	}

	// Verify claims mapping
	expectedSub := "urn:torana:production-ai:user-agent-777"
	if downstreamIdent.Subject != expectedSub {
		t.Errorf("expected mapped subject %q, got %q", expectedSub, downstreamIdent.Subject)
	}
	if downstreamIdent.Tenant != "tenant-omega" {
		t.Errorf("expected tenant tenant-omega, got %s", downstreamIdent.Tenant)
	}
	if !downstreamIdent.InGroup("ai-agents") {
		t.Errorf("expected group ai-agents")
	}
	if !downstreamIdent.HasScope("generate:completion") {
		t.Errorf("expected scope generate:completion")
	}

	// Verify actor delegation claim (RFC 8693)
	actClaim, ok := downstreamIdent.GetClaim("act")
	if !ok {
		t.Errorf("expected 'act' delegation claim")
	} else if actMap, isMap := actClaim.(map[string]any); isMap {
		if actMap["sub"] != "user-agent-777" {
			t.Errorf("expected act.sub == user-agent-777, got %v", actMap["sub"])
		}
	}

	// Verify custom injected claims
	if val := downstreamIdent.GetClaimString("injected_policy"); val != "strict-safety" {
		t.Errorf("expected injected_policy == strict-safety, got %s", val)
	}
	if val := downstreamIdent.GetClaimString("custom_billing_tag"); val != "cost-center-9" {
		t.Errorf("expected custom_billing_tag == cost-center-9, got %s", val)
	}
}

func TestSTS_TTLConstraints(t *testing.T) {
	_, priv := generateEd25519Key(t)
	stsService, err := sts.NewService(sts.Config{
		Namespace:  "test-ns",
		SigningKey: priv,
		DefaultTTL: 2 * time.Minute,
		MaxTTL:     10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("unexpected error creating STS: %v", err)
	}

	ident := authn.NewIdentity("test-sub", "test-tenant", "mtls")

	// Attempt to request 1 hour TTL (exceeds max 10m)
	_, err = stsService.MintDownstreamToken(context.Background(), ident, sts.WithTTL(1*time.Hour))
	if !errors.Is(err, sts.ErrTTLExceeded) {
		t.Errorf("expected ErrTTLExceeded, got: %v", err)
	}
}

func TestSTS_CustomClaimsMapper(t *testing.T) {
	_, priv := generateEd25519Key(t)

	customMapper := func(orig *authn.Identity) (map[string]any, error) {
		return map[string]any{
			"custom_sub": "custom:" + orig.Subject,
			"tier":       "enterprise_gold",
		}, nil
	}

	stsService, err := sts.NewService(sts.Config{
		Namespace:    "custom-ns",
		SigningKey:   priv,
		ClaimsMapper: customMapper,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ident := authn.NewIdentity("original-user", "corp", "jwt")
	tok, err := stsService.MintDownstreamToken(context.Background(), ident)
	if err != nil {
		t.Fatalf("failed to mint: %v", err)
	}
	if tok == "" {
		t.Fatal("empty token")
	}
}
