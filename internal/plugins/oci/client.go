package oci

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"
)

// Client fetches, verifies, and caches OCI plugin artifacts according to namespace security policy.
type Client struct {
	policy     NamespacePolicy
	cache      *Cache
	httpClient *http.Client
	mockMu     sync.RWMutex
	mockStore  map[string]*Artifact // ref -> Artifact
}

// NewClient initializes a new OCI plugin client with policy and disk cache.
func NewClient(policy NamespacePolicy, cache *Cache, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}
	return &Client{
		policy:     policy,
		cache:      cache,
		httpClient: httpClient,
		mockStore:  make(map[string]*Artifact),
	}
}

// RegisterMockArtifact stores an in-memory artifact for testing without network requests.
func (c *Client) RegisterMockArtifact(ref string, art *Artifact) {
	c.mockMu.Lock()
	defer c.mockMu.Unlock()
	c.mockStore[ref] = art
}

type parsedRef struct {
	Registry   string
	Repository string
	Reference  string // tag or digest
	IsDigest   bool
}

func parseReference(ref string) (*parsedRef, error) {
	if ref == "" {
		return nil, ErrInvalidReference
	}

	var reg, repo, tagOrDigest string
	var isDigest bool

	if idx := strings.Index(ref, "@"); idx != -1 {
		isDigest = true
		tagOrDigest = ref[idx+1:]
		ref = ref[:idx]
	} else if idx := strings.LastIndex(ref, ":"); idx != -1 && !strings.Contains(ref[idx:], "/") {
		tagOrDigest = ref[idx+1:]
		ref = ref[:idx]
	} else {
		tagOrDigest = "latest"
	}

	parts := strings.Split(ref, "/")
	if len(parts) == 1 {
		reg = "registry.torana.io"
		repo = parts[0]
	} else if strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":") || parts[0] == "localhost" {
		reg = parts[0]
		repo = strings.Join(parts[1:], "/")
	} else {
		reg = "registry.torana.io"
		repo = strings.Join(parts, "/")
	}

	return &parsedRef{
		Registry:   reg,
		Repository: repo,
		Reference:  tagOrDigest,
		IsDigest:   isDigest,
	}, nil
}

// checkPolicy validates registry and repository against namespace policy allowlists.
func (c *Client) checkPolicy(parsed *parsedRef) error {
	// 1. Allowed Registries check
	if len(c.policy.AllowedRegistries) > 0 {
		allowed := false
		for _, pattern := range c.policy.AllowedRegistries {
			if matchPattern(pattern, parsed.Registry) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: registry %q not in allowed list", ErrDisallowedRegistry, parsed.Registry)
		}
	}

	// 2. Allowed Sources check
	if len(c.policy.AllowedSources) > 0 {
		allowed := false
		for _, pattern := range c.policy.AllowedSources {
			if matchPattern(pattern, parsed.Repository) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: source %q not in allowed list", ErrDisallowedSource, parsed.Repository)
		}
	}

	return nil
}

func matchPattern(pattern, val string) bool {
	if pattern == "*" || pattern == val {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // e.g. ".internal.corp"
		return strings.HasSuffix(val, suffix)
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return val == prefix || strings.HasPrefix(val, prefix+"/")
	}
	return false
}

// FetchArtifact pulls an artifact from the registry or local cache, verifying its digest and signature.
func (c *Client) FetchArtifact(ctx context.Context, ref string, auth AuthConfig) (*Artifact, error) {
	parsed, err := parseReference(ref)
	if err != nil {
		return nil, err
	}

	// 1. Enforce namespace policy
	if err := c.checkPolicy(parsed); err != nil {
		return nil, err
	}

	// 2. Check local disk cache if digest is specified
	if parsed.IsDigest && c.cache != nil {
		if art, err := c.cache.Get(parsed.Reference); err == nil && art != nil {
			return art, nil
		}
	}

	// 3. Check mock store
	var art *Artifact
	c.mockMu.RLock()
	art = c.mockStore[ref]
	if art == nil && parsed.IsDigest {
		art = c.mockStore[parsed.Reference]
	}
	c.mockMu.RUnlock()

	// 4. If not in mock store, fetch via HTTP OCI distribution
	if art == nil {
		var fetchErr error
		art, fetchErr = c.fetchHTTP(ctx, parsed, auth)
		if fetchErr != nil {
			return nil, fetchErr
		}
	}

	// 5. Verify SHA-256 Digest
	computedSum := sha256.Sum256(art.PayloadBytes)
	computedDigest := "sha256:" + hex.EncodeToString(computedSum[:])

	expectedDigest := art.Digest
	if expectedDigest == "" && parsed.IsDigest {
		expectedDigest = parsed.Reference
	}

	if expectedDigest != "" && computedDigest != expectedDigest {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrDigestMismatch, expectedDigest, computedDigest)
	}
	art.Digest = computedDigest

	// 6. Verify Cosign Signature
	if len(art.SignatureBytes) > 0 {
		if err := c.verifySignature(art.Digest, art.SignatureBytes); err != nil {
			return nil, err
		}
	} else if !c.policy.AllowUnsigned {
		return nil, ErrUnsignedDisallowed
	}

	// 7. Store in local disk cache
	if c.cache != nil {
		_ = c.cache.Put(art)
	}

	return art, nil
}

// verifySignature validates an Ed25519 or ECDSA digital signature over the artifact digest.
func (c *Client) verifySignature(digest string, sigBytes []byte) error {
	if len(c.policy.TrustedPublicKeys) == 0 {
		return fmt.Errorf("%w: no trusted public keys configured", ErrInvalidSignature)
	}

	digestBytes := []byte(digest)
	digestHash := sha256.Sum256(digestBytes)

	for _, pubKey := range c.policy.TrustedPublicKeys {
		switch k := pubKey.(type) {
		case ed25519.PublicKey:
			if ed25519.Verify(k, digestBytes, sigBytes) {
				return nil
			}
		case *ecdsa.PublicKey:
			if ecdsa.VerifyASN1(k, digestHash[:], sigBytes) {
				return nil
			}
		}
	}

	return ErrInvalidSignature
}

// fetchHTTP implements standard OCI Distribution Registry v2 client operations.
func (c *Client) fetchHTTP(ctx context.Context, parsed *parsedRef, auth AuthConfig) (*Artifact, error) {
	scheme := "https"
	if strings.HasPrefix(parsed.Registry, "localhost") || strings.HasPrefix(parsed.Registry, "127.0.0.1") {
		scheme = "http"
	}

	baseURL := fmt.Sprintf("%s://%s/v2/%s", scheme, parsed.Registry, parsed.Repository)
	manifestURL := fmt.Sprintf("%s/manifests/%s", baseURL, parsed.Reference)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")

	if auth.Token != "" {
		req.Header.Set("Authorization", "Bearer "+auth.Token)
	} else if auth.Username != "" && auth.Password != "" {
		req.SetBasicAuth(auth.Username, auth.Password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OCI manifest from %s: %w", manifestURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrArtifactNotFound
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registry returned error status %d: %s", resp.StatusCode, string(body))
	}

	manifestBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest body: %w", err)
	}

	var ociManifest struct {
		Layers []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestBytes, &ociManifest); err != nil {
		return nil, fmt.Errorf("malformed OCI manifest: %w", err)
	}

	if len(ociManifest.Layers) == 0 {
		return nil, fmt.Errorf("manifest has no layers")
	}

	// Fetch primary layer blob
	blobDigest := ociManifest.Layers[0].Digest
	blobURL := fmt.Sprintf("%s/blobs/%s", baseURL, blobDigest)

	blobReq, err := http.NewRequestWithContext(ctx, http.MethodGet, blobURL, nil)
	if err != nil {
		return nil, err
	}
	if auth.Token != "" {
		blobReq.Header.Set("Authorization", "Bearer "+auth.Token)
	} else if auth.Username != "" && auth.Password != "" {
		blobReq.SetBasicAuth(auth.Username, auth.Password)
	}

	blobResp, err := c.httpClient.Do(blobReq)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch blob %s: %w", blobURL, err)
	}
	defer blobResp.Body.Close()

	if blobResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch blob %s, status: %d", blobURL, blobResp.StatusCode)
	}

	blobBytes, err := io.ReadAll(blobResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read blob body: %w", err)
	}

	return &Artifact{
		Reference:     path.Join(parsed.Registry, parsed.Repository) + ":" + parsed.Reference,
		Digest:        blobDigest,
		ManifestBytes: manifestBytes,
		PayloadBytes:  blobBytes,
		MediaType:     ociManifest.Layers[0].MediaType,
		Size:          int64(len(blobBytes)),
		FetchedAt:     time.Now(),
	}, nil
}
