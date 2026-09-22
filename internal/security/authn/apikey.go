package authn

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/phaselume/torana/internal/pipeline"
	"golang.org/x/crypto/argon2"
)

// HashAlgorithm specifies the cryptographic hashing function used for API key storage.
type HashAlgorithm string

const (
	// HashAlgorithmSHA256 is the recommended primary algorithm for sub-millisecond hot-path evaluation.
	HashAlgorithmSHA256 HashAlgorithm = "sha256"
	// HashAlgorithmArgon2id is available for low-throughput, high-security requirements.
	HashAlgorithmArgon2id HashAlgorithm = "argon2id"
)

// Argon2Params defines tunable parameters for Argon2id hashing.
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	KeyLength   uint32
}

// DefaultArgon2Params returns standard recommended parameters for Argon2id.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Memory:      64 * 1024, // 64MB
		Iterations:  1,
		Parallelism: 4,
		KeyLength:   32,
	}
}

// StoredAPIKey represents an API key record stored securely in hashed format.
type StoredAPIKey struct {
	ID           string
	Prefix       string
	HashedSecret []byte
	Salt         []byte
	Algorithm    HashAlgorithm
	Argon2Params Argon2Params
	Identity     *Identity
	ExpiresAt    *time.Time
}

// APIKeyStore is the interface for retrieving stored hashed API keys by prefix in O(1).
type APIKeyStore interface {
	GetByPrefix(prefix string) (*StoredAPIKey, bool)
	Store(key *StoredAPIKey)
	Delete(prefix string)
}

// InMemoryKeyStore is a concurrent-safe in-memory API key store with O(1) prefix lookup.
type InMemoryKeyStore struct {
	mu   sync.RWMutex
	keys map[string]*StoredAPIKey
}

// NewInMemoryKeyStore creates a new InMemoryKeyStore.
func NewInMemoryKeyStore() *InMemoryKeyStore {
	return &InMemoryKeyStore{
		keys: make(map[string]*StoredAPIKey),
	}
}

// GetByPrefix retrieves a key by its prefix.
func (s *InMemoryKeyStore) GetByPrefix(prefix string) (*StoredAPIKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[prefix]
	return k, ok
}

// Store inserts or updates a key in the store.
func (s *InMemoryKeyStore) Store(key *StoredAPIKey) {
	if key == nil || key.Prefix == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[key.Prefix] = key
}

// Delete removes a key by prefix.
func (s *InMemoryKeyStore) Delete(prefix string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, prefix)
}

// APIKeyProviderConfig defines configuration options for APIKeyProvider.
type APIKeyProviderConfig struct {
	Store          APIKeyStore
	RevocationList *RevocationList
	// HeaderNames specifies headers to inspect (defaults to ["X-API-Key", "Authorization"]).
	HeaderNames []string
	// PrefixLength specifies default character length if no delimiter is present (default 8).
	PrefixLength int
}

// APIKeyProvider handles API key authentication via prefix lookup and constant-time comparison.
type APIKeyProvider struct {
	store          APIKeyStore
	revocationList *RevocationList
	headerNames    []string
	prefixLength   int
	dummyHash      []byte
	dummySalt      []byte
}

// NewAPIKeyProvider constructs a new APIKeyProvider.
func NewAPIKeyProvider(cfg APIKeyProviderConfig) *APIKeyProvider {
	if cfg.Store == nil {
		cfg.Store = NewInMemoryKeyStore()
	}
	if len(cfg.HeaderNames) == 0 {
		cfg.HeaderNames = []string{"X-API-Key", "Authorization"}
	}
	if cfg.PrefixLength <= 0 {
		cfg.PrefixLength = 8
	}

	dummySalt := []byte("dummy-torana-salt-32-bytes-long!")
	dummyHash := sha256.Sum256(append([]byte("dummy-secret"), dummySalt...))

	return &APIKeyProvider{
		store:          cfg.Store,
		revocationList: cfg.RevocationList,
		headerNames:    cfg.HeaderNames,
		prefixLength:   cfg.PrefixLength,
		dummyHash:      dummyHash[:],
		dummySalt:      dummySalt,
	}
}

func (p *APIKeyProvider) Name() string {
	return "api_key"
}

// Authenticate extracts and verifies an API key from the envelope.
func (p *APIKeyProvider) Authenticate(ctx context.Context, env *pipeline.Envelope) (*Identity, error) {
	rawKey := p.extractKey(env)
	if rawKey == "" {
		return nil, ErrNoCredentials
	}

	return p.ValidateAPIKey(ctx, rawKey)
}

// ValidateAPIKey validates a raw API key using prefix lookup and constant-time comparison.
func (p *APIKeyProvider) ValidateAPIKey(ctx context.Context, rawKey string) (*Identity, error) {
	prefix, secret := p.SplitKey(rawKey)
	if prefix == "" || secret == "" {
		// Run dummy comparison to equalize timing
		_ = subtle.ConstantTimeCompare(p.dummyHash, p.dummyHash)
		return nil, ErrInvalidCredentials
	}

	stored, found := p.store.GetByPrefix(prefix)
	if !found {
		// Timing attack protection: run dummy constant-time comparison
		computed := sha256.Sum256(append([]byte(secret), p.dummySalt...))
		_ = subtle.ConstantTimeCompare(computed[:], p.dummyHash)
		return nil, ErrInvalidCredentials
	}

	// 1. Expiration check
	if stored.ExpiresAt != nil && time.Now().After(*stored.ExpiresAt) {
		return nil, ErrExpired
	}

	// 2. Revocation check (O(1))
	if p.revocationList != nil {
		if p.revocationList.IsKeyRevoked(stored.ID) || p.revocationList.IsKeyRevoked(prefix) {
			return nil, ErrRevoked
		}
	}

	// 3. Compute Hash & Constant-Time Compare
	var computed []byte
	switch stored.Algorithm {
	case HashAlgorithmArgon2id:
		params := stored.Argon2Params
		if params.Memory == 0 {
			params = DefaultArgon2Params()
		}
		computed = argon2.IDKey([]byte(secret), stored.Salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	case HashAlgorithmSHA256, "":
		h := sha256.New()
		h.Write([]byte(secret))
		if len(stored.Salt) > 0 {
			h.Write(stored.Salt)
		}
		computed = h.Sum(nil)
	default:
		return nil, fmt.Errorf("%w: unsupported hash algorithm %s", ErrInvalidCredentials, stored.Algorithm)
	}

	if subtle.ConstantTimeCompare(computed, stored.HashedSecret) != 1 {
		return nil, ErrInvalidCredentials
	}

	// 4. Return cloned Identity
	ident := stored.Identity.Clone()
	if ident == nil {
		ident = NewIdentity(prefix, "", "api_key")
	} else {
		ident.AuthMethod = "api_key"
	}
	return ident, nil
}

// SplitKey separates the key into public prefix and secret body.
// Supported formats:
// - Direct registered prefix matching from store (e.g. "torana_live_pref1_secret")
// - Delimited: "<prefix>.<secret>" or "<prefix>_<secret>"
// - Fixed length fallback: "<prefix><secret>"
func (p *APIKeyProvider) SplitKey(rawKey string) (prefix, secret string) {
	trimmed := strings.TrimSpace(rawKey)
	if trimmed == "" {
		return "", ""
	}

	// 1. If store supports prefix listing, match longest registered prefix
	if p.store != nil {
		if ims, ok := p.store.(*InMemoryKeyStore); ok {
			ims.mu.RLock()
			var bestPref string
			for pref := range ims.keys {
				if strings.HasPrefix(trimmed, pref) && len(pref) > len(bestPref) {
					bestPref = pref
				}
			}
			ims.mu.RUnlock()

			if bestPref != "" {
				rem := strings.TrimPrefix(trimmed, bestPref)
				rem = strings.TrimPrefix(rem, "_")
				rem = strings.TrimPrefix(rem, ".")
				if rem != "" {
					return bestPref, rem
				}
			}
		}
	}

	// 2. Check for last delimiter . or _
	if idx := strings.LastIndexAny(trimmed, "._"); idx > 0 && idx < len(trimmed)-1 {
		return trimmed[:idx], trimmed[idx+1:]
	}

	// 3. Fixed length prefix fallback
	if len(trimmed) > p.prefixLength {
		return trimmed[:p.prefixLength], trimmed[p.prefixLength:]
	}

	return "", ""
}

func (p *APIKeyProvider) extractKey(env *pipeline.Envelope) string {
	for _, hName := range p.headerNames {
		val := env.Headers.Get(hName)
		if val == "" {
			continue
		}
		if strings.EqualFold(hName, "Authorization") {
			if strings.HasPrefix(strings.ToLower(val), "bearer ") {
				token := strings.TrimSpace(val[7:])
				// Only treat as API key if it has a key-like structure (e.g. prefix delimiter or not JWT)
				if !isLikelyJWT(token) {
					return token
				}
			} else if strings.HasPrefix(strings.ToLower(val), "apikey ") {
				return strings.TrimSpace(val[7:])
			}
		} else {
			return strings.TrimSpace(val)
		}
	}
	return ""
}

func isLikelyJWT(token string) bool {
	return strings.Count(token, ".") == 2
}

// HashKeySHA256 is a helper to generate a stored SHA-256 hash and salt for an API key secret.
func HashKeySHA256(secret string, salt []byte) []byte {
	h := sha256.New()
	h.Write([]byte(secret))
	if len(salt) > 0 {
		h.Write(salt)
	}
	return h.Sum(nil)
}

// HashKeyArgon2id is a helper to generate a stored Argon2id hash for an API key secret.
func HashKeyArgon2id(secret string, salt []byte, params Argon2Params) []byte {
	if params.Memory == 0 {
		params = DefaultArgon2Params()
	}
	return argon2.IDKey([]byte(secret), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
}
