package fuzz_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/phaselume/torana/internal/security/authn"
)

// FuzzJWTValidateToken exercises the JWT parser/validator with random token strings.
// Must never panic regardless of input.
func FuzzJWTValidateToken(f *testing.F) {
	// Generate a real Ed25519 key pair for issuer config.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("keygen: %v", err)
	}

	// Build a valid JWT for seeding.
	validToken := buildEdDSAToken(priv, map[string]any{
		"iss": "https://auth.example.com",
		"sub": "user-123",
		"aud": "torana-gateway",
		"exp": 9999999999,
		"iat": 1600000000,
	})

	// Seed corpus
	f.Add(validToken)                              // valid token
	f.Add("not.a.jwt")                             // wrong structure
	f.Add("")                                      // empty
	f.Add("a.b.c")                                 // 3 parts but invalid base64
	f.Add("eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.") // alg=none attack
	f.Add(validToken[:len(validToken)/2])           // truncated
	f.Add(validToken + ".extra")                    // extra part

	provider := authn.NewJWTProvider([]*authn.IssuerConfig{
		{
			Issuer:    "https://auth.example.com",
			Audiences: []string{"torana-gateway"},
			StaticKeys: map[string]crypto.PublicKey{
				"test-kid": pub,
			},
			AllowedAlgorithms: []string{"EdDSA"},
		},
	}, nil)

	f.Fuzz(func(t *testing.T, rawToken string) {
		// Must not panic. Returns identity or error.
		ident, err := provider.ValidateToken(context.Background(), rawToken)
		if err == nil && ident == nil {
			t.Error("ValidateToken returned nil identity without error")
		}
	})
}

// buildEdDSAToken creates a minimal valid EdDSA JWT for test seeding.
func buildEdDSAToken(priv ed25519.PrivateKey, claims map[string]any) string {
	header := map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": "test-kid"}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	sig := ed25519.Sign(priv, []byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64
}
