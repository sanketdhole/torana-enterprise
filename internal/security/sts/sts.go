package sts

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/phaselume/torana/internal/security/authn"
)

var (
	// ErrNilIdentity is returned when attempting to mint a downstream token from a nil identity.
	ErrNilIdentity = errors.New("cannot mint token from nil identity")
	// ErrMissingSigningKey is returned when no private key is configured for the STS service.
	ErrMissingSigningKey = errors.New("missing or invalid signing key")
	// ErrTTLExceeded is returned when requested TTL exceeds maximum allowed TTL.
	ErrTTLExceeded = errors.New("requested token TTL exceeds maximum allowed TTL")
)

// ClaimsMapper translates incoming caller Identity claims into downstream JWT claims.
type ClaimsMapper func(ident *authn.Identity) (map[string]any, error)

// Config configures the Security Token Service.
type Config struct {
	Namespace     string
	Issuer        string
	DefaultTTL    time.Duration
	MaxTTL        time.Duration
	KeyID         string
	SigningKey    crypto.PrivateKey
	Algorithm     string // "EdDSA", "RS256"
	ClaimsMapper  ClaimsMapper
}

// Service mints short-lived downstream tokens signed with a namespace key.
type Service struct {
	namespace    string
	issuer       string
	defaultTTL   time.Duration
	maxTTL       time.Duration
	keyID        string
	signingKey   crypto.PrivateKey
	algorithm    string
	claimsMapper ClaimsMapper
}

// NewService creates a new Security Token Service.
func NewService(cfg Config) (*Service, error) {
	if cfg.SigningKey == nil {
		return nil, ErrMissingSigningKey
	}

	alg := cfg.Algorithm
	if alg == "" {
		switch cfg.SigningKey.(type) {
		case ed25519.PrivateKey:
			alg = "EdDSA"
		case *rsa.PrivateKey:
			alg = "RS256"
		default:
			return nil, fmt.Errorf("unsupported signing key type: %T", cfg.SigningKey)
		}
	}

	issuer := cfg.Issuer
	if issuer == "" {
		issuer = fmt.Sprintf("https://torana.internal/%s/sts", cfg.Namespace)
	}

	defaultTTL := cfg.DefaultTTL
	if defaultTTL <= 0 {
		defaultTTL = 5 * time.Minute
	}

	maxTTL := cfg.MaxTTL
	if maxTTL <= 0 {
		maxTTL = 1 * time.Hour
	}

	return &Service{
		namespace:    cfg.Namespace,
		issuer:       issuer,
		defaultTTL:   defaultTTL,
		maxTTL:       maxTTL,
		keyID:        cfg.KeyID,
		signingKey:   cfg.SigningKey,
		algorithm:    alg,
		claimsMapper: cfg.ClaimsMapper,
	}, nil
}

// MintOptions defines per-call customization for token minting.
type MintOptions struct {
	Audience    string
	TTL         time.Duration
	ExtraClaims map[string]any
}

// MintOption applies a mutation to MintOptions.
type MintOption func(*MintOptions)

// WithAudience sets the downstream audience.
func WithAudience(aud string) MintOption {
	return func(o *MintOptions) {
		o.Audience = aud
	}
}

// WithTTL sets a custom token lifetime.
func WithTTL(ttl time.Duration) MintOption {
	return func(o *MintOptions) {
		o.TTL = ttl
	}
}

// WithExtraClaims adds custom claims to the downstream token.
func WithExtraClaims(claims map[string]any) MintOption {
	return func(o *MintOptions) {
		if o.ExtraClaims == nil {
			o.ExtraClaims = make(map[string]any)
		}
		for k, v := range claims {
			o.ExtraClaims[k] = v
		}
	}
}

// MintDownstreamToken mints a short-lived downstream token in token-exchange style from an Identity.
func (s *Service) MintDownstreamToken(ctx context.Context, ident *authn.Identity, opts ...MintOption) (string, error) {
	if ident == nil {
		return "", ErrNilIdentity
	}

	options := MintOptions{
		TTL: s.defaultTTL,
	}
	for _, opt := range opts {
		opt(&options)
	}

	if options.TTL > s.maxTTL {
		return "", fmt.Errorf("%w: requested %v, max %v", ErrTTLExceeded, options.TTL, s.maxTTL)
	}

	now := time.Now()
	exp := now.Add(options.TTL)

	// Build claims
	var claims map[string]any
	if s.claimsMapper != nil {
		mapped, err := s.claimsMapper(ident)
		if err != nil {
			return "", fmt.Errorf("custom claims mapping failed: %w", err)
		}
		claims = mapped
	} else {
		claims = s.defaultClaimsMapping(ident)
	}

	// Apply standard STS claims
	claims["iss"] = s.issuer
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()
	claims["exp"] = exp.Unix()

	if options.Audience != "" {
		claims["aud"] = options.Audience
	}

	// Generate random jti
	var jtiBytes [16]byte
	_, _ = rand.Read(jtiBytes[:])
	claims["jti"] = hex.EncodeToString(jtiBytes[:])

	// Merge any extra claims
	for k, v := range options.ExtraClaims {
		claims[k] = v
	}

	return s.signJWT(claims)
}

func (s *Service) defaultClaimsMapping(ident *authn.Identity) map[string]any {
	claims := make(map[string]any)

	// Copy caller claims
	for k, v := range ident.Claims {
		claims[k] = v
	}

	// Subject mapping (urn:torana:<namespace>:<subject>)
	if s.namespace != "" && !strings.HasPrefix(ident.Subject, "urn:torana:") {
		claims["sub"] = fmt.Sprintf("urn:torana:%s:%s", s.namespace, ident.Subject)
	} else {
		claims["sub"] = ident.Subject
	}

	if ident.Tenant != "" {
		claims["tenant"] = ident.Tenant
	}
	if len(ident.Groups) > 0 {
		claims["groups"] = ident.Groups
	}
	if len(ident.Scopes) > 0 {
		claims["scope"] = strings.Join(ident.Scopes, " ")
	}

	// RFC 8693 Token Exchange actor claim: records caller delegation
	claims["act"] = map[string]any{
		"sub":         ident.Subject,
		"auth_method": ident.AuthMethod,
	}

	return claims
}

func (s *Service) signJWT(claims map[string]any) (string, error) {
	header := map[string]string{
		"typ": "JWT",
		"alg": s.algorithm,
	}
	if s.keyID != "" {
		header["kid"] = s.keyID
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	var sigBytes []byte
	switch s.algorithm {
	case "EdDSA":
		edKey, ok := s.signingKey.(ed25519.PrivateKey)
		if !ok {
			return "", errors.New("signing key is not ed25519.PrivateKey")
		}
		sigBytes = ed25519.Sign(edKey, []byte(signingInput))

	case "RS256":
		rsaKey, ok := s.signingKey.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New("signing key is not *rsa.PrivateKey")
		}
		h := sha256.Sum256([]byte(signingInput))
		sigBytes, err = rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, h[:])
		if err != nil {
			return "", fmt.Errorf("rsa signing failed: %w", err)
		}

	default:
		return "", fmt.Errorf("unsupported signing algorithm: %s", s.algorithm)
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(sigBytes)
	return signingInput + "." + sigB64, nil
}
