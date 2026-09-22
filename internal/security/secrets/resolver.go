package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	// ErrUnsupportedScheme is returned when a secret URI scheme is unknown.
	ErrUnsupportedScheme = errors.New("unsupported secret URI scheme")
	// ErrInvalidURI is returned when a secret URI is malformed.
	ErrInvalidURI = errors.New("invalid secret URI format")
	// ErrSecretNotFound is returned when a secret cannot be found.
	ErrSecretNotFound = errors.New("secret not found")
)

// Mask returns a safely redacted string suitable for diagnostics and audit logs.
// Plaintext secrets must never appear in envelopes or logs.
func Mask(val string) string {
	if len(val) == 0 {
		return ""
	}
	if len(val) <= 6 {
		return "******"
	}
	prefix := val[:2]
	suffix := val[len(val)-4:]
	return prefix + strings.Repeat("*", len(val)-6) + suffix
}

// SecretString is a wrapper around a sensitive string that redacts itself when formatted or logged.
type SecretString string

func (s SecretString) String() string {
	return "[REDACTED]"
}

func (s SecretString) MarshalJSON() ([]byte, error) {
	return json.Marshal("[REDACTED]")
}

// SecretValue unwraps the underlying plaintext secret.
func (s SecretString) SecretValue() string {
	return string(s)
}

// RotationCallback is invoked when a secret is updated or rotated.
type RotationCallback func(newVal string)

// VaultClient is the abstraction for fetching secrets from HashiCorp Vault.
type VaultClient interface {
	GetSecret(ctx context.Context, path, key string) (string, error)
}

// AWSSMClient is the abstraction for fetching secrets from AWS Secrets Manager.
type AWSSMClient interface {
	GetSecret(ctx context.Context, secretName, key string) (string, error)
}

// Provider resolves secrets for a specific scheme.
type Provider interface {
	Resolve(ctx context.Context, target string) (string, error)
}

// Resolver defines the unified interface for resolving secrets across env:, k8s:, vault:, and awssm:.
type Resolver interface {
	Resolve(ctx context.Context, uri string) (string, error)
	RegisterRotationCallback(uri string, cb RotationCallback)
	Rotate(ctx context.Context, uri string) error
	Close() error
}

type cachedSecret struct {
	value     string
	expiresAt time.Time
}

// MultiResolver dispatches secret resolution across multiple providers with caching and rotation callbacks.
type MultiResolver struct {
	mu          sync.RWMutex
	cache       map[string]cachedSecret
	cacheTTL    time.Duration
	callbacks   map[string][]RotationCallback
	providers   map[string]Provider
	vaultClient VaultClient
	awssmClient AWSSMClient
}

// Config configures MultiResolver.
type Config struct {
	CacheTTL    time.Duration
	VaultClient VaultClient
	AWSSMClient AWSSMClient
}

// NewMultiResolver creates a new unified secret resolver.
func NewMultiResolver(cfg Config) *MultiResolver {
	ttl := cfg.CacheTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	mr := &MultiResolver{
		cache:       make(map[string]cachedSecret),
		cacheTTL:    ttl,
		callbacks:   make(map[string][]RotationCallback),
		providers:   make(map[string]Provider),
		vaultClient: cfg.VaultClient,
		awssmClient: cfg.AWSSMClient,
	}

	mr.providers["env"] = &envProvider{}
	mr.providers["k8s"] = &k8sProvider{}
	mr.providers["vault"] = &vaultProvider{client: cfg.VaultClient}
	mr.providers["awssm"] = &awssmProvider{client: cfg.AWSSMClient}

	return mr
}

// Resolve fetches a secret by URI, using in-memory caching.
func (r *MultiResolver) Resolve(ctx context.Context, uri string) (string, error) {
	if uri == "" {
		return "", ErrInvalidURI
	}

	// 1. Check Cache
	r.mu.RLock()
	cached, ok := r.cache[uri]
	if ok && time.Now().Before(cached.expiresAt) {
		r.mu.RUnlock()
		return cached.value, nil
	}
	r.mu.RUnlock()

	// 2. Resolve from Underlying Provider
	scheme, target, err := parseURI(uri)
	if err != nil {
		return "", err
	}

	r.mu.RLock()
	provider, ok := r.providers[scheme]
	r.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnsupportedScheme, scheme)
	}

	val, err := provider.Resolve(ctx, target)
	if err != nil {
		return "", err
	}

	// 3. Store in Cache
	r.mu.Lock()
	r.cache[uri] = cachedSecret{
		value:     val,
		expiresAt: time.Now().Add(r.cacheTTL),
	}
	r.mu.Unlock()

	return val, nil
}

// RegisterRotationCallback registers a callback invoked when the secret at uri is rotated.
func (r *MultiResolver) RegisterRotationCallback(uri string, cb RotationCallback) {
	if uri == "" || cb == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.callbacks[uri] = append(r.callbacks[uri], cb)
}

// Rotate invalidates the cache for uri, re-resolves the secret, and notifies subscribers.
func (r *MultiResolver) Rotate(ctx context.Context, uri string) error {
	scheme, target, err := parseURI(uri)
	if err != nil {
		return err
	}

	r.mu.RLock()
	provider, ok := r.providers[scheme]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnsupportedScheme, scheme)
	}

	// Fetch fresh value
	newVal, err := provider.Resolve(ctx, target)
	if err != nil {
		return fmt.Errorf("rotation failed to fetch new secret: %w", err)
	}

	// Update cache
	r.mu.Lock()
	r.cache[uri] = cachedSecret{
		value:     newVal,
		expiresAt: time.Now().Add(r.cacheTTL),
	}
	cbs := make([]RotationCallback, len(r.callbacks[uri]))
	copy(cbs, r.callbacks[uri])
	r.mu.Unlock()

	// Notify callbacks
	for _, cb := range cbs {
		cb(newVal)
	}

	return nil
}

// SetVaultClient dynamically configures or updates the Vault client.
func (r *MultiResolver) SetVaultClient(client VaultClient) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.vaultClient = client
	r.providers["vault"] = &vaultProvider{client: client}
}

// SetAWSSMClient dynamically configures or updates the AWS Secrets Manager client.
func (r *MultiResolver) SetAWSSMClient(client AWSSMClient) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.awssmClient = client
	r.providers["awssm"] = &awssmProvider{client: client}
}

// Close cleans up cached items and callback subscriptions.
func (r *MultiResolver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.cache)
	clear(r.callbacks)
	return nil
}

func parseURI(uri string) (scheme, target string, err error) {
	parts := strings.SplitN(uri, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("%w: %q (expected scheme:target)", ErrInvalidURI, uri)
	}
	return strings.ToLower(parts[0]), parts[1], nil
}

// --- Provider Implementations ---

// envProvider: env:<VAR_NAME>
type envProvider struct{}

func (p *envProvider) Resolve(_ context.Context, target string) (string, error) {
	val, ok := os.LookupEnv(target)
	if !ok || val == "" {
		return "", fmt.Errorf("%w: environment variable %q is unset", ErrSecretNotFound, target)
	}
	return val, nil
}

// k8sProvider: k8s:<path_to_file>
type k8sProvider struct{}

func (p *k8sProvider) Resolve(_ context.Context, target string) (string, error) {
	data, err := os.ReadFile(target)
	if err != nil {
		return "", fmt.Errorf("%w: failed to read k8s mounted secret at %q: %v", ErrSecretNotFound, target, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// vaultProvider: vault:<path>#<key>
type vaultProvider struct {
	client VaultClient
}

func (p *vaultProvider) Resolve(ctx context.Context, target string) (string, error) {
	if p.client == nil {
		return "", errors.New("vault client not configured")
	}
	parts := strings.SplitN(target, "#", 2)
	path := parts[0]
	key := ""
	if len(parts) == 2 {
		key = parts[1]
	}
	return p.client.GetSecret(ctx, path, key)
}

// awssmProvider: awssm:<secret_name>#<key>
type awssmProvider struct {
	client AWSSMClient
}

func (p *awssmProvider) Resolve(ctx context.Context, target string) (string, error) {
	if p.client == nil {
		return "", errors.New("aws secrets manager client not configured")
	}
	parts := strings.SplitN(target, "#", 2)
	secretName := parts[0]
	key := ""
	if len(parts) == 2 {
		key = parts[1]
	}
	return p.client.GetSecret(ctx, secretName, key)
}
