package security_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/security/authn"
)

// Helper to create an RSA test key
func generateRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return key
}

// Helper to create an Ed25519 test key
func generateEd25519Key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}
	return pub, priv
}

// Helper to mint a test JWT signed with an RSA key
func mintTestRSAToken(t *testing.T, key *rsa.PrivateKey, kid, iss string, aud []string, exp, nbf *time.Time, jti string, extraClaims map[string]any) string {
	t.Helper()
	header := map[string]string{
		"typ": "JWT",
		"alg": "RS256",
		"kid": kid,
	}
	claims := map[string]any{
		"iss": iss,
		"sub": "user_12345",
	}
	if len(aud) == 1 {
		claims["aud"] = aud[0]
	} else if len(aud) > 1 {
		claims["aud"] = aud
	}
	if exp != nil {
		claims["exp"] = exp.Unix()
	}
	if nbf != nil {
		claims["nbf"] = nbf.Unix()
	}
	if jti != "" {
		claims["jti"] = jti
	}
	for k, v := range extraClaims {
		claims[k] = v
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(claims)

	hB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	pB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := hB64 + "." + pB64

	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func rsaToJWK(key *rsa.PublicKey, kid string) authn.JWK {
	nBytes := key.N.Bytes()
	eBytes := []byte{byte(key.E >> 16), byte(key.E >> 8), byte(key.E)}
	for len(eBytes) > 1 && eBytes[0] == 0 {
		eBytes = eBytes[1:]
	}

	return authn.JWK{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

func TestJWTProvider_ValidToken(t *testing.T) {
	key := generateRSAKey(t)
	const issuerURL = "https://auth.example.com"
	const audience = "torana-api"
	const kid = "key-1"

	exp := time.Now().Add(1 * time.Hour)
	token := mintTestRSAToken(t, key, kid, issuerURL, []string{audience}, &exp, nil, "tok-1", map[string]any{
		"tenant": "tenant-corp",
		"roles":  []string{"admin", "user"},
		"scope":  "read:models write:prompts",
	})

	provider := authn.NewJWTProvider([]*authn.IssuerConfig{
		{
			Issuer:    issuerURL,
			Audiences: []string{audience},
			StaticKeys: map[string]crypto.PublicKey{
				kid: &key.PublicKey,
			},
		},
	}, nil)

	env := pipeline.GetEnvelope("req-1", pipeline.PhaseAuthn, "GET", "/v1/chat", nil, nil)
	env.Headers.Set("Authorization", "Bearer "+token)

	ident, err := provider.Authenticate(context.Background(), env)
	if err != nil {
		t.Fatalf("expected successful authentication, got: %v", err)
	}

	if ident.Subject != "user_12345" {
		t.Errorf("expected subject user_12345, got %s", ident.Subject)
	}
	if ident.Tenant != "tenant-corp" {
		t.Errorf("expected tenant tenant-corp, got %s", ident.Tenant)
	}
	if !ident.InGroup("admin") {
		t.Errorf("expected admin group")
	}
	if !ident.HasScope("write:prompts") {
		t.Errorf("expected write:prompts scope")
	}
	if ident.AuthMethod != "jwt" {
		t.Errorf("expected auth_method jwt, got %s", ident.AuthMethod)
	}
}

func TestJWTProvider_ExpiredToken(t *testing.T) {
	key := generateRSAKey(t)
	const issuerURL = "https://auth.example.com"
	const kid = "key-1"

	// Expired 10 minutes ago
	exp := time.Now().Add(-10 * time.Minute)
	token := mintTestRSAToken(t, key, kid, issuerURL, []string{"api"}, &exp, nil, "", nil)

	provider := authn.NewJWTProvider([]*authn.IssuerConfig{
		{
			Issuer:    issuerURL,
			Audiences: []string{"api"},
			ClockSkew: 1 * time.Minute,
			StaticKeys: map[string]crypto.PublicKey{
				kid: &key.PublicKey,
			},
		},
	}, nil)

	env := pipeline.GetEnvelope("req-expired", pipeline.PhaseAuthn, "GET", "/v1/chat", nil, nil)
	env.Headers.Set("Authorization", "Bearer "+token)

	_, err := provider.Authenticate(context.Background(), env)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
	if !errors.Is(err, authn.ErrExpired) {
		t.Errorf("expected ErrExpired, got: %v", err)
	}
}

func TestJWTProvider_ClockSkew(t *testing.T) {
	key := generateRSAKey(t)
	const issuerURL = "https://auth.example.com"
	const kid = "key-1"

	// Expired 30 seconds ago
	exp := time.Now().Add(-30 * time.Second)
	token := mintTestRSAToken(t, key, kid, issuerURL, []string{"api"}, &exp, nil, "", nil)

	// Skew is 1 minute -> should pass
	providerWithSkew := authn.NewJWTProvider([]*authn.IssuerConfig{
		{
			Issuer:    issuerURL,
			Audiences: []string{"api"},
			ClockSkew: 1 * time.Minute,
			StaticKeys: map[string]crypto.PublicKey{
				kid: &key.PublicKey,
			},
		},
	}, nil)

	env := pipeline.GetEnvelope("req-skew", pipeline.PhaseAuthn, "GET", "/v1/chat", nil, nil)
	env.Headers.Set("Authorization", "Bearer "+token)

	ident, err := providerWithSkew.Authenticate(context.Background(), env)
	if err != nil {
		t.Fatalf("expected clock skew tolerance to pass, got: %v", err)
	}
	if ident == nil {
		t.Fatal("expected identity, got nil")
	}

	// Zero skew -> must fail
	providerNoSkew := authn.NewJWTProvider([]*authn.IssuerConfig{
		{
			Issuer:    issuerURL,
			Audiences: []string{"api"},
			ClockSkew: 1 * time.Nanosecond, // virtually zero
			StaticKeys: map[string]crypto.PublicKey{
				kid: &key.PublicKey,
			},
		},
	}, nil)

	_, err = providerNoSkew.Authenticate(context.Background(), env)
	if !errors.Is(err, authn.ErrExpired) {
		t.Errorf("expected ErrExpired with zero clock skew, got: %v", err)
	}
}

func TestJWTProvider_WrongAudience(t *testing.T) {
	key := generateRSAKey(t)
	const issuerURL = "https://auth.example.com"
	const kid = "key-1"

	exp := time.Now().Add(1 * time.Hour)
	token := mintTestRSAToken(t, key, kid, issuerURL, []string{"untrusted-aud"}, &exp, nil, "", nil)

	provider := authn.NewJWTProvider([]*authn.IssuerConfig{
		{
			Issuer:    issuerURL,
			Audiences: []string{"expected-audience"},
			StaticKeys: map[string]crypto.PublicKey{
				kid: &key.PublicKey,
			},
		},
	}, nil)

	env := pipeline.GetEnvelope("req-wrong-aud", pipeline.PhaseAuthn, "GET", "/v1/chat", nil, nil)
	env.Headers.Set("Authorization", "Bearer "+token)

	_, err := provider.Authenticate(context.Background(), env)
	if !errors.Is(err, authn.ErrWrongAudience) {
		t.Errorf("expected ErrWrongAudience, got: %v", err)
	}
}

func TestJWTProvider_UnknownKID(t *testing.T) {
	key := generateRSAKey(t)
	const issuerURL = "https://auth.example.com"

	exp := time.Now().Add(1 * time.Hour)
	// Token with unregistered KID
	token := mintTestRSAToken(t, key, "non-existent-kid", issuerURL, []string{"api"}, &exp, nil, "", nil)

	provider := authn.NewJWTProvider([]*authn.IssuerConfig{
		{
			Issuer:    issuerURL,
			Audiences: []string{"api"},
			StaticKeys: map[string]crypto.PublicKey{
				"known-key-1": &key.PublicKey,
			},
		},
	}, nil)

	env := pipeline.GetEnvelope("req-unknown-kid", pipeline.PhaseAuthn, "GET", "/v1/chat", nil, nil)
	env.Headers.Set("Authorization", "Bearer "+token)

	_, err := provider.Authenticate(context.Background(), env)
	if !errors.Is(err, authn.ErrUnknownKID) {
		t.Errorf("expected ErrUnknownKID, got: %v", err)
	}
}

func TestJWTProvider_RevokedToken(t *testing.T) {
	key := generateRSAKey(t)
	const issuerURL = "https://auth.example.com"
	const kid = "key-1"
	const jti = "revoked-token-id-999"

	exp := time.Now().Add(1 * time.Hour)
	token := mintTestRSAToken(t, key, kid, issuerURL, []string{"api"}, &exp, nil, jti, nil)

	revList := authn.NewRevocationList()
	revList.RevokeToken(jti)

	provider := authn.NewJWTProvider([]*authn.IssuerConfig{
		{
			Issuer:    issuerURL,
			Audiences: []string{"api"},
			StaticKeys: map[string]crypto.PublicKey{
				kid: &key.PublicKey,
			},
		},
	}, revList)

	env := pipeline.GetEnvelope("req-revoked", pipeline.PhaseAuthn, "GET", "/v1/chat", nil, nil)
	env.Headers.Set("Authorization", "Bearer "+token)

	_, err := provider.Authenticate(context.Background(), env)
	if !errors.Is(err, authn.ErrRevoked) {
		t.Errorf("expected ErrRevoked, got: %v", err)
	}
}

type mockRoundTripper struct {
	handler http.Handler
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	m.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}

func TestJWTProvider_KeyRotation(t *testing.T) {
	// Simulate an active JWKS endpoint where a key rotation occurs
	key1 := generateRSAKey(t)
	key2 := generateRSAKey(t)

	var mu sync.RWMutex
	jwksKeys := []authn.JWK{
		rsaToJWK(&key1.PublicKey, "key-1"),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		defer mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": jwksKeys,
		})
	})

	mockClient := &http.Client{
		Transport: &mockRoundTripper{handler: handler},
	}

	issuerURL := "https://idp.example.com"
	jwksEndpoint := "https://idp.example.com/.well-known/jwks.json"

	provider := authn.NewJWTProvider([]*authn.IssuerConfig{
		{
			Issuer:     issuerURL,
			Audiences:  []string{"api"},
			JWKSURL:    jwksEndpoint,
			HTTPClient: mockClient,
		},
	}, nil)

	// Step 1: Token signed with key-1 should succeed
	exp := time.Now().Add(1 * time.Hour)
	token1 := mintTestRSAToken(t, key1, "key-1", issuerURL, []string{"api"}, &exp, nil, "", nil)

	env1 := pipeline.GetEnvelope("req-rot-1", pipeline.PhaseAuthn, "GET", "/v1/chat", nil, nil)
	env1.Headers.Set("Authorization", "Bearer "+token1)

	ident1, err := provider.Authenticate(context.Background(), env1)
	if err != nil {
		t.Fatalf("expected token1 to succeed, got: %v", err)
	}
	if ident1 == nil {
		t.Fatal("expected non-nil identity")
	}

	// Step 2: Mint token signed with key-2 before key-2 is published
	token2 := mintTestRSAToken(t, key2, "key-2", issuerURL, []string{"api"}, &exp, nil, "", nil)
	env2 := pipeline.GetEnvelope("req-rot-2", pipeline.PhaseAuthn, "GET", "/v1/chat", nil, nil)
	env2.Headers.Set("Authorization", "Bearer "+token2)

	// Initially key-2 is not in JWKS, should fail with ErrUnknownKID
	_, err = provider.Authenticate(context.Background(), env2)
	if !errors.Is(err, authn.ErrUnknownKID) {
		t.Fatalf("expected ErrUnknownKID before rotation, got: %v", err)
	}

	// Step 3: Rotate keys in JWKS server (add key-2)
	mu.Lock()
	jwksKeys = append(jwksKeys, rsaToJWK(&key2.PublicKey, "key-2"))
	mu.Unlock()

	// Wait a moment so cooldown passes
	time.Sleep(1100 * time.Millisecond)

	// Now token2 should trigger on-demand rotation fetch and succeed!
	ident2, err := provider.Authenticate(context.Background(), env2)
	if err != nil {
		t.Fatalf("expected token2 to succeed after key rotation, got: %v", err)
	}
	if ident2 == nil || ident2.Subject != "user_12345" {
		t.Errorf("expected valid subject after rotation, got %v", ident2)
	}
}

func TestJWTProvider_MultipleIssuers(t *testing.T) {
	keyA := generateRSAKey(t)
	keyB := generateRSAKey(t)

	const issuerA = "https://auth.company-a.com"
	const issuerB = "https://auth.company-b.com"

	provider := authn.NewJWTProvider([]*authn.IssuerConfig{
		{
			Issuer:    issuerA,
			Audiences: []string{"service-a"},
			StaticKeys: map[string]crypto.PublicKey{
				"key-a": &keyA.PublicKey,
			},
		},
		{
			Issuer:    issuerB,
			Audiences: []string{"service-b"},
			StaticKeys: map[string]crypto.PublicKey{
				"key-b": &keyB.PublicKey,
			},
		},
	}, nil)

	exp := time.Now().Add(1 * time.Hour)

	// Valid token from Issuer A
	tokA := mintTestRSAToken(t, keyA, "key-a", issuerA, []string{"service-a"}, &exp, nil, "", nil)
	envA := pipeline.GetEnvelope("req-a", pipeline.PhaseAuthn, "GET", "/test", nil, nil)
	envA.Headers.Set("Authorization", "Bearer "+tokA)
	identA, err := provider.Authenticate(context.Background(), envA)
	if err != nil {
		t.Fatalf("expected issuer A to validate, got: %v", err)
	}
	if identA.Subject != "user_12345" {
		t.Errorf("expected subject user_12345")
	}

	// Valid token from Issuer B
	tokB := mintTestRSAToken(t, keyB, "key-b", issuerB, []string{"service-b"}, &exp, nil, "", nil)
	envB := pipeline.GetEnvelope("req-b", pipeline.PhaseAuthn, "GET", "/test", nil, nil)
	envB.Headers.Set("Authorization", "Bearer "+tokB)
	identB, err := provider.Authenticate(context.Background(), envB)
	if err != nil {
		t.Fatalf("expected issuer B to validate, got: %v", err)
	}
	if identB.Subject != "user_12345" {
		t.Errorf("expected subject user_12345")
	}

	// Token from Untrusted Issuer C
	keyC := generateRSAKey(t)
	tokC := mintTestRSAToken(t, keyC, "key-c", "https://untrusted.com", []string{"service-a"}, &exp, nil, "", nil)
	envC := pipeline.GetEnvelope("req-c", pipeline.PhaseAuthn, "GET", "/test", nil, nil)
	envC.Headers.Set("Authorization", "Bearer "+tokC)
	_, err = provider.Authenticate(context.Background(), envC)
	if !errors.Is(err, authn.ErrIssuerMismatch) {
		t.Errorf("expected ErrIssuerMismatch for untrusted issuer, got: %v", err)
	}
}
