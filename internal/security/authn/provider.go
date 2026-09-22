package authn

import (
	"context"
	"errors"

	"github.com/phaselume/torana/internal/pipeline"
)

var (
	// ErrNoCredentials indicates that no recognizable credentials for this provider were found on the envelope.
	ErrNoCredentials = errors.New("no credentials provided")
	// ErrInvalidCredentials indicates the presented credentials were syntactically invalid or malformed.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrExpired indicates the token or credential has expired.
	ErrExpired = errors.New("credential expired")
	// ErrWrongAudience indicates the credential audience does not match the expected audience.
	ErrWrongAudience = errors.New("invalid audience")
	// ErrUnknownKID indicates the token key ID is not found in the trust store / JWKS.
	ErrUnknownKID = errors.New("unknown key id")
	// ErrRevoked indicates the token or key has been revoked.
	ErrRevoked = errors.New("credential revoked")
	// ErrIssuerMismatch indicates the token issuer is untrusted or unconfigured.
	ErrIssuerMismatch = errors.New("untrusted or unknown issuer")
	// ErrUntrustedCert indicates client TLS certificate verification failed.
	ErrUntrustedCert = errors.New("untrusted client certificate")
	// ErrSignatureInvalid indicates cryptographic signature verification failed.
	ErrSignatureInvalid = errors.New("invalid cryptographic signature")
)

// Provider defines the authentication provider interface implemented by built-in authenticators
// (JWT/OIDC, API Key, mTLS) and extensible third-party plugins.
type Provider interface {
	// Name returns the unique identifier of the provider.
	Name() string

	// Authenticate inspects the envelope and credentials, returning the caller Identity on success.
	// If credentials for this provider are not present, it returns ErrNoCredentials.
	// Any other error causes the authentication phase to fail closed immediately.
	Authenticate(ctx context.Context, env *pipeline.Envelope) (*Identity, error)
}
