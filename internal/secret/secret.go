package secret

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/phaselume/torana/internal/config"
)

var (
	// ErrUnsupportedProvider is returned when a secret reference has an unknown provider.
	ErrUnsupportedProvider = errors.New("unsupported secret provider")
	// ErrSecretNotFound is returned when a secret key cannot be found.
	ErrSecretNotFound = errors.New("secret not found")
)

// Resolver defines the interface for fetching secret values from local providers.
type Resolver interface {
	Resolve(ctx context.Context, ref config.SecretRef) (string, error)
}

// EnvResolver resolves secret references from environment variables.
type EnvResolver struct{}

// NewEnvResolver creates a new environment-based secret resolver.
func NewEnvResolver() *EnvResolver {
	return &EnvResolver{}
}

// Resolve fetches the secret from environment variables.
func (r *EnvResolver) Resolve(_ context.Context, ref config.SecretRef) (string, error) {
	if ref.Provider != "" && ref.Provider != "env" {
		return "", fmt.Errorf("%w: %s", ErrUnsupportedProvider, ref.Provider)
	}

	key := ref.Key
	if key == "" {
		key = ref.Name
	}

	val, ok := os.LookupEnv(key)
	if !ok || val == "" {
		return "", fmt.Errorf("%w for key %q", ErrSecretNotFound, key)
	}

	return val, nil
}

// Mask returns a safely redacted string suitable for diagnostics (e.g. "sk-***1234").
func Mask(val string) string {
	if len(val) <= 6 {
		return "******"
	}
	prefix := val[:2]
	suffix := val[len(val)-4:]
	return prefix + strings.Repeat("*", len(val)-6) + suffix
}
