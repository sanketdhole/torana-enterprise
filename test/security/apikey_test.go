package security_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/security/authn"
)

func TestAPIKeyProvider_SHA256PrefixLookup(t *testing.T) {
	store := authn.NewInMemoryKeyStore()
	revList := authn.NewRevocationList()

	salt := []byte("salt-for-test-123456789012345678")
	secret := "sec_live_998877665544332211"
	hashed := authn.HashKeySHA256(secret, salt)

	ident := authn.NewIdentity("service-user-1", "tenant-alpha", "api_key")
	ident.Groups = []string{"developer"}
	ident.Scopes = []string{"read:models"}

	key := &authn.StoredAPIKey{
		ID:           "key-record-1",
		Prefix:       "torana_live_pref1",
		HashedSecret: hashed,
		Salt:         salt,
		Algorithm:    authn.HashAlgorithmSHA256,
		Identity:     ident,
	}
	store.Store(key)

	provider := authn.NewAPIKeyProvider(authn.APIKeyProviderConfig{
		Store:          store,
		RevocationList: revList,
	})

	t.Run("valid key via X-API-Key header", func(t *testing.T) {
		env := pipeline.GetEnvelope("req-key-1", pipeline.PhaseAuthn, "POST", "/v1/chat", nil, nil)
		env.Headers.Set("X-API-Key", "torana_live_pref1_"+secret)

		resIdent, err := provider.Authenticate(context.Background(), env)
		if err != nil {
			t.Fatalf("expected successful API key authn, got: %v", err)
		}
		if resIdent.Subject != "service-user-1" {
			t.Errorf("expected subject service-user-1, got %s", resIdent.Subject)
		}
		if resIdent.Tenant != "tenant-alpha" {
			t.Errorf("expected tenant tenant-alpha, got %s", resIdent.Tenant)
		}
		if !resIdent.HasScope("read:models") {
			t.Errorf("expected scope read:models")
		}
	})

	t.Run("valid key via Authorization Bearer header", func(t *testing.T) {
		env := pipeline.GetEnvelope("req-key-2", pipeline.PhaseAuthn, "POST", "/v1/chat", nil, nil)
		env.Headers.Set("Authorization", "Bearer torana_live_pref1."+secret)

		resIdent, err := provider.Authenticate(context.Background(), env)
		if err != nil {
			t.Fatalf("expected successful API key authn, got: %v", err)
		}
		if resIdent.Subject != "service-user-1" {
			t.Errorf("expected subject service-user-1, got %s", resIdent.Subject)
		}
	})

	t.Run("wrong secret fails closed", func(t *testing.T) {
		env := pipeline.GetEnvelope("req-key-3", pipeline.PhaseAuthn, "POST", "/v1/chat", nil, nil)
		env.Headers.Set("X-API-Key", "torana_live_pref1_incorrect-secret-value")

		_, err := provider.Authenticate(context.Background(), env)
		if !errors.Is(err, authn.ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials, got: %v", err)
		}
	})

	t.Run("unknown prefix fails closed with constant time dummy compare", func(t *testing.T) {
		env := pipeline.GetEnvelope("req-key-4", pipeline.PhaseAuthn, "POST", "/v1/chat", nil, nil)
		env.Headers.Set("X-API-Key", "unknown_prefix_someSecretValueHere")

		_, err := provider.Authenticate(context.Background(), env)
		if !errors.Is(err, authn.ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials, got: %v", err)
		}
	})

	t.Run("revoked key fails closed in O(1)", func(t *testing.T) {
		revList.RevokeKey("key-record-1")

		env := pipeline.GetEnvelope("req-key-5", pipeline.PhaseAuthn, "POST", "/v1/chat", nil, nil)
		env.Headers.Set("X-API-Key", "torana_live_pref1_"+secret)

		_, err := provider.Authenticate(context.Background(), env)
		if !errors.Is(err, authn.ErrRevoked) {
			t.Errorf("expected ErrRevoked, got: %v", err)
		}
	})
}

func TestAPIKeyProvider_Argon2id(t *testing.T) {
	store := authn.NewInMemoryKeyStore()
	salt := []byte("salt-argon2id-test-32bytes-salt!")
	secret := "secret-argon2-secure-val-998877"

	params := authn.Argon2Params{
		Memory:      16 * 1024, // 16MB for unit test speed
		Iterations:  1,
		Parallelism: 2,
		KeyLength:   32,
	}
	hashed := authn.HashKeyArgon2id(secret, salt, params)

	ident := authn.NewIdentity("argon-user", "tenant-beta", "api_key")
	store.Store(&authn.StoredAPIKey{
		ID:           "argon-key-1",
		Prefix:       "argon_prefix1",
		HashedSecret: hashed,
		Salt:         salt,
		Algorithm:    authn.HashAlgorithmArgon2id,
		Argon2Params: params,
		Identity:     ident,
	})

	provider := authn.NewAPIKeyProvider(authn.APIKeyProviderConfig{
		Store: store,
	})

	t.Run("valid argon2id key", func(t *testing.T) {
		env := pipeline.GetEnvelope("req-argon-1", pipeline.PhaseAuthn, "GET", "/test", nil, nil)
		env.Headers.Set("X-API-Key", "argon_prefix1_"+secret)

		res, err := provider.Authenticate(context.Background(), env)
		if err != nil {
			t.Fatalf("expected argon2id authn success, got: %v", err)
		}
		if res.Subject != "argon-user" {
			t.Errorf("expected subject argon-user, got %s", res.Subject)
		}
	})

	t.Run("invalid argon2id secret fails closed", func(t *testing.T) {
		env := pipeline.GetEnvelope("req-argon-2", pipeline.PhaseAuthn, "GET", "/test", nil, nil)
		env.Headers.Set("X-API-Key", "argon_prefix1_wrongSecret")

		_, err := provider.Authenticate(context.Background(), env)
		if !errors.Is(err, authn.ErrInvalidCredentials) {
			t.Errorf("expected ErrInvalidCredentials, got: %v", err)
		}
	})
}

func TestAPIKeyProvider_Expired(t *testing.T) {
	store := authn.NewInMemoryKeyStore()
	salt := []byte("salt-1234567890123456")
	secret := "my-secret-token"
	hashed := authn.HashKeySHA256(secret, salt)

	expiredTime := time.Now().Add(-1 * time.Hour)
	store.Store(&authn.StoredAPIKey{
		ID:           "exp-key-1",
		Prefix:       "exp_pref",
		HashedSecret: hashed,
		Salt:         salt,
		Algorithm:    authn.HashAlgorithmSHA256,
		ExpiresAt:    &expiredTime,
	})

	provider := authn.NewAPIKeyProvider(authn.APIKeyProviderConfig{
		Store: store,
	})

	env := pipeline.GetEnvelope("req-exp-key", pipeline.PhaseAuthn, "GET", "/test", nil, nil)
	env.Headers.Set("X-API-Key", "exp_pref_"+secret)

	_, err := provider.Authenticate(context.Background(), env)
	if !errors.Is(err, authn.ErrExpired) {
		t.Errorf("expected ErrExpired, got: %v", err)
	}
}

func BenchmarkAPIKey_SHA256(b *testing.B) {
	store := authn.NewInMemoryKeyStore()
	salt := []byte("benchmark-salt-32-bytes-long!!!!")
	secret := "benchmark-super-secret-key-string"
	hashed := authn.HashKeySHA256(secret, salt)

	store.Store(&authn.StoredAPIKey{
		ID:           "bench-key",
		Prefix:       "bench_pref",
		HashedSecret: hashed,
		Salt:         salt,
		Algorithm:    authn.HashAlgorithmSHA256,
		Identity:     authn.NewIdentity("bench-user", "bench-tenant", "api_key"),
	})

	provider := authn.NewAPIKeyProvider(authn.APIKeyProviderConfig{
		Store: store,
	})

	env := pipeline.GetEnvelope("req-bench", pipeline.PhaseAuthn, "POST", "/v1/chat", nil, nil)
	env.Headers.Set("X-API-Key", "bench_pref_"+secret)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := provider.Authenticate(context.Background(), env)
		if err != nil {
			b.Fatalf("benchmark failed: %v", err)
		}
	}
}
