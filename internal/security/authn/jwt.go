package authn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/phaselume/torana/internal/pipeline"
)

// IssuerConfig defines validation and JWKS configuration for a trusted token issuer.
type IssuerConfig struct {
	Issuer            string
	Audiences         []string
	JWKSURL           string
	ClockSkew         time.Duration
	AllowedAlgorithms []string
	HTTPClient        *http.Client
	StaticKeys        map[string]crypto.PublicKey // pre-loaded or mock keys for testing

	jwksCache *jwksCache
}

// JWK represents a standard JSON Web Key (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n,omitempty"`   // RSA modulus
	E   string `json:"e,omitempty"`   // RSA exponent
	Crv string `json:"crv,omitempty"` // EC curve
	X   string `json:"x,omitempty"`   // EC/OKP public coordinate
	Y   string `json:"y,omitempty"`   // EC public coordinate
}

type jwksResponse struct {
	Keys []JWK `json:"keys"`
}

type jwksCache struct {
	mu          sync.RWMutex
	keys        map[string]crypto.PublicKey
	lastFetched time.Time
	cooldown    time.Duration
	jwksURL     string
	client      *http.Client
}

func newJWKSCache(jwksURL string, client *http.Client, staticKeys map[string]crypto.PublicKey) *jwksCache {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	cache := &jwksCache{
		keys:     make(map[string]crypto.PublicKey),
		cooldown: 1 * time.Second,
		jwksURL:  jwksURL,
		client:   client,
	}
	for kid, key := range staticKeys {
		cache.keys[kid] = key
	}
	return cache
}

func (c *jwksCache) GetKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	c.mu.RLock()
	key, found := c.keys[kid]
	last := c.lastFetched
	c.mu.RUnlock()

	if found {
		return key, nil
	}

	// Unknown KID or empty cache: if no JWKS URL configured, cannot fetch
	if c.jwksURL == "" {
		return nil, ErrUnknownKID
	}

	// Trigger on-demand rotation fetch with cooldown check
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if key, found = c.keys[kid]; found {
		return key, nil
	}

	if time.Since(last) < c.cooldown && len(c.keys) > 0 {
		return nil, ErrUnknownKID
	}

	if err := c.fetchLocked(ctx); err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", c.jwksURL, err)
	}

	if key, found = c.keys[kid]; found {
		return key, nil
	}

	return nil, ErrUnknownKID
}

func (c *jwksCache) Refresh(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fetchLocked(ctx)
}

func (c *jwksCache) fetchLocked(ctx context.Context) error {
	if c.jwksURL == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.jwksURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint returned HTTP status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS JSON: %w", err)
	}

	newKeys := make(map[string]crypto.PublicKey, len(jwks.Keys))
	for _, jwk := range jwks.Keys {
		pubKey, err := parseJWK(jwk)
		if err != nil {
			continue
		}
		newKeys[jwk.Kid] = pubKey
	}

	// Merge with existing static keys
	for k, v := range newKeys {
		c.keys[k] = v
	}
	c.lastFetched = time.Now()
	return nil
}

func parseJWK(jwk JWK) (crypto.PublicKey, error) {
	switch strings.ToUpper(jwk.Kty) {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
		if err != nil {
			return nil, err
		}
		var eInt int
		for _, b := range eBytes {
			eInt = (eInt << 8) | int(b)
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: eInt,
		}, nil

	case "EC":
		var curve elliptic.Curve
		switch jwk.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", jwk.Crv)
		}

		xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil {
			return nil, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
		if err != nil {
			return nil, err
		}

		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}, nil

	case "OKP":
		if jwk.Crv == "Ed25519" {
			xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
			if err != nil {
				return nil, err
			}
			return ed25519.PublicKey(xBytes), nil
		}
		return nil, fmt.Errorf("unsupported OKP curve: %s", jwk.Crv)

	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

// JWTProvider authenticates incoming requests using JWT/OIDC bearer tokens.
type JWTProvider struct {
	issuers        map[string]*IssuerConfig
	revocationList *RevocationList
}

// NewJWTProvider creates a multi-issuer JWT authenticator.
func NewJWTProvider(issuers []*IssuerConfig, revList *RevocationList) *JWTProvider {
	m := make(map[string]*IssuerConfig, len(issuers))
	for _, iss := range issuers {
		if iss.ClockSkew == 0 {
			iss.ClockSkew = 1 * time.Minute
		}
		iss.jwksCache = newJWKSCache(iss.JWKSURL, iss.HTTPClient, iss.StaticKeys)
		m[iss.Issuer] = iss
	}
	return &JWTProvider{
		issuers:        m,
		revocationList: revList,
	}
}

func (j *JWTProvider) Name() string {
	return "jwt_oidc"
}

// Authenticate extracts, verifies, and validates the JWT bearer token.
func (j *JWTProvider) Authenticate(ctx context.Context, env *pipeline.Envelope) (*Identity, error) {
	authHeader := env.Headers.Get("Authorization")
	if authHeader == "" {
		return nil, ErrNoCredentials
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return nil, ErrNoCredentials
	}
	rawToken := strings.TrimSpace(authHeader[len(prefix):])
	if rawToken == "" {
		return nil, ErrInvalidCredentials
	}

	return j.ValidateToken(ctx, rawToken)
}

// ValidateToken parses and validates a raw JWT token string against configured issuers.
func (j *JWTProvider) ValidateToken(ctx context.Context, rawToken string) (*Identity, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidCredentials
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid header encoding", ErrInvalidCredentials)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: invalid header json", ErrInvalidCredentials)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid payload encoding", ErrInvalidCredentials)
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("%w: invalid payload json", ErrInvalidCredentials)
	}

	// 1. Identify and match Issuer
	issRaw, ok := claims["iss"].(string)
	if !ok || issRaw == "" {
		return nil, fmt.Errorf("%w: missing iss claim", ErrIssuerMismatch)
	}

	issuerCfg, found := j.issuers[issRaw]
	if !found {
		return nil, fmt.Errorf("%w: unknown issuer %q", ErrIssuerMismatch, issRaw)
	}

	// Check allowed algorithms if configured
	if len(issuerCfg.AllowedAlgorithms) > 0 {
		allowed := false
		for _, a := range issuerCfg.AllowedAlgorithms {
			if strings.EqualFold(a, header.Alg) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("%w: algorithm %s not permitted", ErrSignatureInvalid, header.Alg)
		}
	}

	// 2. Resolve Signing Key via JWKS Cache / Auto-Rotation
	pubKey, err := issuerCfg.jwksCache.GetKey(ctx, header.Kid)
	if err != nil {
		if errors.Is(err, ErrUnknownKID) {
			return nil, ErrUnknownKID
		}
		return nil, fmt.Errorf("%w: %v", ErrUnknownKID, err)
	}

	// 3. Cryptographic Signature Verification
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid signature encoding", ErrSignatureInvalid)
	}

	signedContent := []byte(parts[0] + "." + parts[1])
	if err := verifySignature(header.Alg, pubKey, signedContent, sigBytes); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}

	// 4. Claims Validation: Expiry, Clock Skew, Audience, Revocation
	now := time.Now()

	// Expiry check
	if expVal, ok := claims["exp"]; ok {
		expTime, err := parseNumericDate(expVal)
		if err != nil {
			return nil, fmt.Errorf("%w: malformed exp claim", ErrInvalidCredentials)
		}
		if now.After(expTime.Add(issuerCfg.ClockSkew)) {
			return nil, ErrExpired
		}
	}

	// Not Before (nbf) check
	if nbfVal, ok := claims["nbf"]; ok {
		nbfTime, err := parseNumericDate(nbfVal)
		if err != nil {
			return nil, fmt.Errorf("%w: malformed nbf claim", ErrInvalidCredentials)
		}
		if now.Before(nbfTime.Add(-issuerCfg.ClockSkew)) {
			return nil, ErrInvalidCredentials
		}
	}

	// Audience check
	if len(issuerCfg.Audiences) > 0 {
		if !matchAudience(claims["aud"], issuerCfg.Audiences) {
			return nil, ErrWrongAudience
		}
	}

	// 5. Revocation Check (O(1))
	if j.revocationList != nil {
		if jti, ok := claims["jti"].(string); ok && jti != "" {
			if j.revocationList.IsTokenRevoked(jti) {
				return nil, ErrRevoked
			}
		}
		// Also check raw token hash
		tokHash := fmt.Sprintf("%x", sha256.Sum256([]byte(rawToken)))
		if j.revocationList.IsTokenRevoked(tokHash) {
			return nil, ErrRevoked
		}
	}

	// 6. Build Identity
	ident := buildIdentityFromClaims(claims)
	ident.AuthMethod = "jwt"
	return ident, nil
}

func verifySignature(alg string, pubKey crypto.PublicKey, content, sig []byte) error {
	switch strings.ToUpper(alg) {
	case "RS256":
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("expected RSA public key")
		}
		h := sha256.Sum256(content)
		return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, h[:], sig)

	case "RS384":
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("expected RSA public key")
		}
		h := sha512.Sum384(content)
		return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA384, h[:], sig)

	case "RS512":
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("expected RSA public key")
		}
		h := sha512.Sum512(content)
		return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA512, h[:], sig)

	case "ES256":
		ecPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("expected ECDSA public key")
		}
		h := sha256.Sum256(content)
		return verifyECDSA(ecPub, h[:], sig, 32)

	case "ES384":
		ecPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("expected ECDSA public key")
		}
		h := sha512.Sum384(content)
		return verifyECDSA(ecPub, h[:], sig, 48)

	case "ES512":
		ecPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("expected ECDSA public key")
		}
		h := sha512.Sum512(content)
		return verifyECDSA(ecPub, h[:], sig, 66)

	case "EDDSA":
		edPub, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("expected Ed25519 public key")
		}
		if !ed25519.Verify(edPub, content, sig) {
			return errors.New("ed25519 verification failed")
		}
		return nil

	default:
		return fmt.Errorf("unsupported JWT signature algorithm: %s", alg)
	}
}

func verifyECDSA(pub *ecdsa.PublicKey, hash, sig []byte, byteLen int) error {
	// Standard JWT raw IEEE P1363 signature: R (byteLen) || S (byteLen)
	if len(sig) == 2*byteLen {
		r := new(big.Int).SetBytes(sig[:byteLen])
		s := new(big.Int).SetBytes(sig[byteLen:])
		if ecdsa.Verify(pub, hash, r, s) {
			return nil
		}
		return errors.New("ecdsa raw signature verification failed")
	}

	// Fallback to ASN.1 DER signature
	if ecdsa.VerifyASN1(pub, hash, sig) {
		return nil
	}
	return errors.New("ecdsa verification failed")
}

func parseNumericDate(val any) (time.Time, error) {
	switch v := val.(type) {
	case float64:
		return time.Unix(int64(v), 0), nil
	case int64:
		return time.Unix(v, 0), nil
	case int:
		return time.Unix(int64(v), 0), nil
	case json.Number:
		i, err := v.Int64()
		if err != nil {
			return time.Time{}, err
		}
		return time.Unix(i, 0), nil
	default:
		return time.Time{}, errors.New("invalid date type")
	}
}

func matchAudience(audClaim any, expectedAudiences []string) bool {
	switch v := audClaim.(type) {
	case string:
		for _, exp := range expectedAudiences {
			if v == exp {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				for _, exp := range expectedAudiences {
					if s == exp {
						return true
					}
				}
			}
		}
	case []string:
		for _, s := range v {
			for _, exp := range expectedAudiences {
				if s == exp {
					return true
				}
			}
		}
	}
	return false
}

func buildIdentityFromClaims(claims map[string]any) *Identity {
	ident := &Identity{
		Claims: claims,
		Groups: make([]string, 0),
		Scopes: make([]string, 0),
	}

	if sub, ok := claims["sub"].(string); ok {
		ident.Subject = sub
	}

	// Tenant extraction
	for _, tenantKey := range []string{"tenant", "tenant_id", "tid", "org_id", "organization"} {
		if t, ok := claims[tenantKey].(string); ok && t != "" {
			ident.Tenant = t
			break
		}
	}
	if ident.Tenant == "" {
		if iss, ok := claims["iss"].(string); ok {
			ident.Tenant = iss
		}
	}

	// Groups / Roles extraction
	for _, groupKey := range []string{"groups", "roles", "realm_access"} {
		if gVal, ok := claims[groupKey]; ok {
			switch g := gVal.(type) {
			case []any:
				for _, item := range g {
					if s, ok := item.(string); ok {
						ident.Groups = append(ident.Groups, s)
					}
				}
			case []string:
				ident.Groups = append(ident.Groups, g...)
			case map[string]any:
				// E.g. Keycloak realm_access.roles
				if roles, ok := g["roles"].([]any); ok {
					for _, r := range roles {
						if s, ok := r.(string); ok {
							ident.Groups = append(ident.Groups, s)
						}
					}
				}
			}
		}
	}

	// Scopes extraction
	if scpVal, ok := claims["scope"]; ok {
		if s, ok := scpVal.(string); ok {
			ident.Scopes = append(ident.Scopes, strings.Fields(s)...)
		}
	} else if scpVal, ok := claims["scp"]; ok {
		switch s := scpVal.(type) {
		case []any:
			for _, item := range s {
				if str, ok := item.(string); ok {
					ident.Scopes = append(ident.Scopes, str)
				}
			}
		case []string:
			ident.Scopes = append(ident.Scopes, s...)
		}
	}

	return ident
}
