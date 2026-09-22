package plugins_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/plugins/oci"
)

func TestOCI_FetchAndCache_Success(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "torana-oci-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cache, err := oci.NewCache(tempDir)
	if err != nil {
		t.Fatalf("failed to initialize cache: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	policy := oci.NamespacePolicy{
		AllowedRegistries: []string{"registry.torana.io", "ghcr.io"},
		AllowedSources:    []string{"torana/*", "acme/*"},
		AllowUnsigned:     false,
		TrustedPublicKeys: map[string]crypto.PublicKey{"primary": pub},
	}

	client := oci.NewClient(policy, cache, nil)

	payload := []byte("wasm-binary-test-payload-12345")
	h := sha256.Sum256(payload)
	digest := "sha256:" + hex.EncodeToString(h[:])
	sig := ed25519.Sign(priv, []byte(digest))

	ref := "registry.torana.io/torana/header-validator:v1.0.0"
	mockArt := &oci.Artifact{
		Reference:      ref,
		Digest:         digest,
		ManifestBytes:  []byte(`{"name":"header-validator","version":"1.0.0"}`),
		PayloadBytes:   payload,
		SignatureBytes: sig,
		MediaType:      "application/vnd.torana.plugin.v1",
		Size:           int64(len(payload)),
		FetchedAt:      time.Now(),
	}
	client.RegisterMockArtifact(ref, mockArt)

	ctx := context.Background()
	art, err := client.FetchArtifact(ctx, ref, oci.AuthConfig{})
	if err != nil {
		t.Fatalf("FetchArtifact failed: %v", err)
	}

	if art.Digest != digest {
		t.Fatalf("expected digest %s, got %s", digest, art.Digest)
	}

	// Verify it was saved to disk cache
	if !cache.Has(digest) {
		t.Fatalf("expected artifact to be in cache")
	}

	// Fetch directly from cache by digest reference
	cachedArt, err := client.FetchArtifact(ctx, "registry.torana.io/torana/header-validator@"+digest, oci.AuthConfig{})
	if err != nil {
		t.Fatalf("failed to fetch from cache: %v", err)
	}
	if string(cachedArt.PayloadBytes) != string(payload) {
		t.Fatalf("cached payload mismatch")
	}
}

func TestOCI_BadSignature(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "torana-oci-bad-sig-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cache, err := oci.NewCache(tempDir)
	if err != nil {
		t.Fatalf("failed to initialize cache: %v", err)
	}

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)

	policy := oci.NamespacePolicy{
		AllowedRegistries: []string{"registry.torana.io"},
		AllowedSources:    []string{"torana/*"},
		AllowUnsigned:     false,
		TrustedPublicKeys: map[string]crypto.PublicKey{"primary": pub},
	}

	client := oci.NewClient(policy, cache, nil)

	payload := []byte("wasm-payload-for-bad-signature")
	h := sha256.Sum256(payload)
	digest := "sha256:" + hex.EncodeToString(h[:])
	badSig := ed25519.Sign(wrongPriv, []byte(digest)) // Signed by untrusted key!

	ref := "registry.torana.io/torana/bad-sig:v1.0.0"
	client.RegisterMockArtifact(ref, &oci.Artifact{
		Reference:      ref,
		Digest:         digest,
		ManifestBytes:  []byte(`{"name":"bad-sig"}`),
		PayloadBytes:   payload,
		SignatureBytes: badSig,
	})

	ctx := context.Background()
	_, err = client.FetchArtifact(ctx, ref, oci.AuthConfig{})
	if err == nil || err != oci.ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
}

func TestOCI_DigestMismatch(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "torana-oci-digest-mismatch-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cache, err := oci.NewCache(tempDir)
	if err != nil {
		t.Fatalf("failed to initialize cache: %v", err)
	}

	policy := oci.NamespacePolicy{
		AllowedRegistries: []string{"registry.torana.io"},
		AllowUnsigned:     true,
	}
	client := oci.NewClient(policy, cache, nil)

	ref := "registry.torana.io/torana/corrupted:v1.0.0"
	client.RegisterMockArtifact(ref, &oci.Artifact{
		Reference:     ref,
		Digest:        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		PayloadBytes:  []byte("actual-content-does-not-match-zero-hash"),
		ManifestBytes: []byte(`{"name":"corrupted"}`),
	})

	ctx := context.Background()
	_, err = client.FetchArtifact(ctx, ref, oci.AuthConfig{})
	if err == nil {
		t.Fatalf("expected error for digest mismatch, got nil")
	}
}

func TestOCI_NamespacePolicy_DisallowedRegistryAndSource(t *testing.T) {
	policy := oci.NamespacePolicy{
		AllowedRegistries: []string{"registry.torana.io", "*.internal.acme.com"},
		AllowedSources:    []string{"approved/*"},
		AllowUnsigned:     true,
	}
	client := oci.NewClient(policy, nil, nil)

	ctx := context.Background()

	// 1. Disallowed Registry
	_, err := client.FetchArtifact(ctx, "evil-registry.com/approved/plugin:v1.0.0", oci.AuthConfig{})
	if err == nil {
		t.Fatalf("expected error for disallowed registry, got nil")
	}

	// 2. Disallowed Source
	_, err = client.FetchArtifact(ctx, "registry.torana.io/unapproved/plugin:v1.0.0", oci.AuthConfig{})
	if err == nil {
		t.Fatalf("expected error for disallowed source repository, got nil")
	}

	// 3. Allowed Wildcard Registry & Source
	client.RegisterMockArtifact("edge.internal.acme.com/approved/plugin:v1.0.0", &oci.Artifact{
		Reference:     "edge.internal.acme.com/approved/plugin:v1.0.0",
		PayloadBytes:  []byte("approved-bytes"),
		ManifestBytes: []byte(`{"name":"plugin"}`),
	})
	art, err := client.FetchArtifact(ctx, "edge.internal.acme.com/approved/plugin:v1.0.0", oci.AuthConfig{})
	if err != nil {
		t.Fatalf("expected allowed registry and source to succeed, got: %v", err)
	}
	if art == nil {
		t.Fatalf("expected non-nil artifact")
	}
}

func TestOCI_NamespacePolicy_UnsignedRejected(t *testing.T) {
	policy := oci.NamespacePolicy{
		AllowedRegistries: []string{"registry.torana.io"},
		AllowUnsigned:     false, // Reject unsigned!
	}
	client := oci.NewClient(policy, nil, nil)

	ref := "registry.torana.io/plugins/unsigned:v1.0.0"
	client.RegisterMockArtifact(ref, &oci.Artifact{
		Reference:      ref,
		PayloadBytes:   []byte("unsigned-payload"),
		ManifestBytes:  []byte(`{"name":"unsigned"}`),
		SignatureBytes: nil, // No signature
	})

	ctx := context.Background()
	_, err := client.FetchArtifact(ctx, ref, oci.AuthConfig{})
	if err == nil || err != oci.ErrUnsignedDisallowed {
		t.Fatalf("expected ErrUnsignedDisallowed, got: %v", err)
	}

	// Now permit unsigned
	policy.AllowUnsigned = true
	clientPermit := oci.NewClient(policy, nil, nil)
	clientPermit.RegisterMockArtifact(ref, &oci.Artifact{
		Reference:      ref,
		PayloadBytes:   []byte("unsigned-payload"),
		ManifestBytes:  []byte(`{"name":"unsigned"}`),
		SignatureBytes: nil,
	})

	art, err := clientPermit.FetchArtifact(ctx, ref, oci.AuthConfig{})
	if err != nil {
		t.Fatalf("expected unsigned artifact to be allowed when AllowUnsigned=true, got: %v", err)
	}
	if art == nil {
		t.Fatalf("expected non-nil artifact")
	}
}

func TestOCI_GarbageCollection(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "torana-oci-gc-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cache, err := oci.NewCache(tempDir)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	d1 := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	d2 := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	d3 := "sha256:3333333333333333333333333333333333333333333333333333333333333333"

	for _, d := range []string{d1, d2, d3} {
		err := cache.Put(&oci.Artifact{
			Digest:        d,
			PayloadBytes:  []byte("sample payload bytes for " + d),
			ManifestBytes: []byte(`{"name":"` + d + `"}`),
		})
		if err != nil {
			t.Fatalf("failed to put artifact %s: %v", d, err)
		}
	}

	// Verify all 3 exist
	if !cache.Has(d1) || !cache.Has(d2) || !cache.Has(d3) {
		t.Fatalf("expected all 3 artifacts to be cached")
	}

	// Run GC keeping ONLY d1 active
	ctx := context.Background()
	purged, freedBytes, err := cache.GarbageCollect(ctx, []string{d1})
	if err != nil {
		t.Fatalf("GarbageCollect failed: %v", err)
	}

	if purged != 2 {
		t.Fatalf("expected 2 artifacts purged, got %d", purged)
	}
	if freedBytes <= 0 {
		t.Fatalf("expected positive freed bytes, got %d", freedBytes)
	}

	if !cache.Has(d1) {
		t.Fatalf("active artifact d1 was improperly purged")
	}
	if cache.Has(d2) || cache.Has(d3) {
		t.Fatalf("inactive artifacts d2 or d3 were not purged")
	}

	// Verify files removed from disk
	safeD2 := filepath.Join(tempDir, "blobs", "sha256_2222222222222222222222222222222222222222222222222222222222222222.bin")
	if _, err := os.Stat(safeD2); !os.IsNotExist(err) {
		t.Fatalf("expected blob file %s to be removed", safeD2)
	}
}
