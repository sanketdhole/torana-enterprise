package security_test

import (
	"context"
	"crypto"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/security/authn"
)

// mockCustomPluginProvider simulates an external custom authentication plugin.
type mockCustomPluginProvider struct {
	acceptedToken string
	returnedIdent *authn.Identity
}

func (m *mockCustomPluginProvider) Name() string {
	return "custom_plugin_auth"
}

func (m *mockCustomPluginProvider) Authenticate(_ context.Context, env *pipeline.Envelope) (*authn.Identity, error) {
	customHeader := env.Headers.Get("X-Custom-Auth")
	if customHeader == "" {
		return nil, authn.ErrNoCredentials
	}
	if customHeader != m.acceptedToken {
		return nil, authn.ErrInvalidCredentials
	}
	return m.returnedIdent, nil
}

func TestAuthnFilter_CompositeExecution(t *testing.T) {
	// 1. Setup providers: API Key, JWT, and Custom Plugin
	apiKeyStore := authn.NewInMemoryKeyStore()
	salt := []byte("salt-test-32bytes")
	hashed := authn.HashKeySHA256("my-secret", salt)
	apiKeyStore.Store(&authn.StoredAPIKey{
		ID:           "key-1",
		Prefix:       "apik_pref",
		HashedSecret: hashed,
		Salt:         salt,
		Algorithm:    authn.HashAlgorithmSHA256,
		Identity:     authn.NewIdentity("api-caller", "tenant-key", "api_key"),
	})
	apiProvider := authn.NewAPIKeyProvider(authn.APIKeyProviderConfig{Store: apiKeyStore})

	rsaKey := generateRSAKey(t)
	jwtProvider := authn.NewJWTProvider([]*authn.IssuerConfig{
		{
			Issuer:    "https://auth.company.com",
			Audiences: []string{"gateway"},
			StaticKeys: map[string]crypto.PublicKey{
				"rsa-1": &rsaKey.PublicKey,
			},
		},
	}, nil)

	customPlugin := &mockCustomPluginProvider{
		acceptedToken: "magic-plugin-token",
		returnedIdent: authn.NewIdentity("plugin-caller", "tenant-plugin", "custom"),
	}

	revList := authn.NewRevocationList()

	filter := authn.NewFilter(authn.FilterConfig{
		Name:           "gateway_authn",
		Providers:      []authn.Provider{jwtProvider, apiProvider, customPlugin},
		RevocationList: revList,
		RequireAuth:    true,
	})

	if filter.Phase() != pipeline.PhaseAuthn {
		t.Errorf("expected filter phase PhaseAuthn, got %v", filter.Phase())
	}
	if filter.FailurePolicy() != pipeline.FailurePolicyFailClosed {
		t.Errorf("expected FailurePolicyFailClosed")
	}

	chain := pipeline.NewChain(filter)

	t.Run("successful authentication via API Key", func(t *testing.T) {
		env := pipeline.GetEnvelope("req-f-1", pipeline.PhaseAuthn, "POST", "/v1/chat", nil, nil)
		env.Headers.Set("X-API-Key", "apik_pref_my-secret")

		decision, err := chain.ExecutePhase(context.Background(), env, pipeline.PhaseAuthn, 0)
		if err != nil {
			t.Fatalf("expected continue, got error: %v", err)
		}
		if decision.Action != pipeline.ActionContinue {
			t.Errorf("expected ActionContinue, got %v", decision.Action)
		}

		ident, ok := authn.GetIdentity(env)
		if !ok || ident == nil {
			t.Fatalf("expected identity attached to envelope")
		}
		if ident.Subject != "api-caller" {
			t.Errorf("expected subject api-caller, got %s", ident.Subject)
		}
		if env.PeerInfo.ClientIdentity != "api-caller" {
			t.Errorf("expected ClientIdentity set, got %s", env.PeerInfo.ClientIdentity)
		}
	})

	t.Run("successful authentication via JWT", func(t *testing.T) {
		exp := time.Now().Add(1 * time.Hour)
		tok := mintTestRSAToken(t, rsaKey, "rsa-1", "https://auth.company.com", []string{"gateway"}, &exp, nil, "jwt-id-1", nil)

		env := pipeline.GetEnvelope("req-f-2", pipeline.PhaseAuthn, "POST", "/v1/chat", nil, nil)
		env.Headers.Set("Authorization", "Bearer "+tok)

		decision, err := chain.ExecutePhase(context.Background(), env, pipeline.PhaseAuthn, 0)
		if err != nil {
			t.Fatalf("expected continue, got error: %v", err)
		}
		if decision.Action != pipeline.ActionContinue {
			t.Errorf("expected ActionContinue, got %v", decision.Action)
		}

		ident, ok := authn.GetIdentity(env)
		if !ok || ident == nil {
			t.Fatalf("expected identity on envelope")
		}
		if ident.Subject != "user_12345" {
			t.Errorf("expected subject user_12345, got %s", ident.Subject)
		}
	})

	t.Run("successful authentication via Custom Plugin", func(t *testing.T) {
		env := pipeline.GetEnvelope("req-f-3", pipeline.PhaseAuthn, "POST", "/v1/chat", nil, nil)
		env.Headers.Set("X-Custom-Auth", "magic-plugin-token")

		decision, err := chain.ExecutePhase(context.Background(), env, pipeline.PhaseAuthn, 0)
		if err != nil {
			t.Fatalf("expected continue, got error: %v", err)
		}
		if decision.Action != pipeline.ActionContinue {
			t.Errorf("expected ActionContinue, got %v", decision.Action)
		}

		ident, ok := authn.GetIdentity(env)
		if !ok || ident.Subject != "plugin-caller" {
			t.Errorf("expected plugin caller identity, got %v", ident)
		}
	})

	t.Run("fail closed when no credentials are provided", func(t *testing.T) {
		env := pipeline.GetEnvelope("req-f-4", pipeline.PhaseAuthn, "POST", "/v1/chat", nil, nil)

		decision, err := chain.ExecutePhase(context.Background(), env, pipeline.PhaseAuthn, 0)
		if err == nil {
			t.Fatal("expected fail-closed error, got nil")
		}
		if decision.Action != pipeline.ActionHalt {
			t.Errorf("expected ActionHalt, got %v", decision.Action)
		}
		if decision.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 Unauthorized, got %d", decision.StatusCode)
		}
	})

	t.Run("fail closed when invalid credentials are provided", func(t *testing.T) {
		env := pipeline.GetEnvelope("req-f-5", pipeline.PhaseAuthn, "POST", "/v1/chat", nil, nil)
		env.Headers.Set("X-API-Key", "apik_pref_wrongPassword")

		decision, err := chain.ExecutePhase(context.Background(), env, pipeline.PhaseAuthn, 0)
		if err == nil {
			t.Fatal("expected fail-closed error on wrong secret")
		}
		if decision.Action != pipeline.ActionHalt {
			t.Errorf("expected ActionHalt")
		}
		if decision.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", decision.StatusCode)
		}
	})

	t.Run("fail closed when identity is revoked in RevocationList", func(t *testing.T) {
		revList.RevokeToken("revoked-user-subject")

		// Create a provider that returns "revoked-user-subject"
		revokedProvider := &mockCustomPluginProvider{
			acceptedToken: "revoked-caller-tok",
			returnedIdent: authn.NewIdentity("revoked-user-subject", "tenant-x", "custom"),
		}

		revFilter := authn.NewFilter(authn.FilterConfig{
			Providers:      []authn.Provider{revokedProvider},
			RevocationList: revList,
			RequireAuth:    true,
		})

		chainRev := pipeline.NewChain(revFilter)

		env := pipeline.GetEnvelope("req-f-rev", pipeline.PhaseAuthn, "POST", "/v1/chat", nil, nil)
		env.Headers.Set("X-Custom-Auth", "revoked-caller-tok")

		decision, err := chainRev.ExecutePhase(context.Background(), env, pipeline.PhaseAuthn, 0)
		if err == nil {
			t.Fatal("expected error on revoked identity, got nil")
		}
		if !errors.Is(err, authn.ErrRevoked) {
			t.Errorf("expected ErrRevoked, got: %v", err)
		}
		if decision.Action != pipeline.ActionHalt {
			t.Errorf("expected ActionHalt on revocation, got %v", decision.Action)
		}
		if decision.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", decision.StatusCode)
		}
	})
}
