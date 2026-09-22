package oci

import (
	"crypto"
	"errors"
	"time"
)

var (
	// ErrDigestMismatch is returned when the downloaded artifact payload does not match the expected SHA-256 digest.
	ErrDigestMismatch = errors.New("oci artifact sha256 digest mismatch")
	// ErrInvalidSignature is returned when the cosign digital signature cannot be verified with trusted keys.
	ErrInvalidSignature = errors.New("oci artifact cosign signature verification failed")
	// ErrUnsignedDisallowed is returned when an unsigned artifact is received but the namespace policy requires signatures.
	ErrUnsignedDisallowed = errors.New("unsigned oci artifacts are not allowed by namespace policy")
	// ErrDisallowedRegistry is returned when an artifact's registry host is not in the policy allowlist.
	ErrDisallowedRegistry = errors.New("oci registry is not permitted by namespace policy")
	// ErrDisallowedSource is returned when an artifact's repository path is not in the policy allowlist.
	ErrDisallowedSource = errors.New("oci artifact source is not permitted by namespace policy")
	// ErrArtifactNotFound is returned when the requested artifact cannot be found in the registry.
	ErrArtifactNotFound = errors.New("oci artifact not found")
	// ErrInvalidReference is returned when an OCI image reference format is malformed.
	ErrInvalidReference = errors.New("invalid oci artifact reference")
	// ErrNilArtifact is returned when storing a nil artifact in cache.
	ErrNilArtifact = errors.New("artifact cannot be nil")
)

// Artifact represents a downloaded and verified plugin bundle from an OCI registry.
type Artifact struct {
	Reference      string    `json:"reference"`
	Digest         string    `json:"digest"`
	ManifestBytes  []byte    `json:"manifest_bytes"`
	PayloadBytes   []byte    `json:"payload_bytes"`
	SignatureBytes []byte    `json:"signature_bytes,omitempty"`
	MediaType      string    `json:"media_type"`
	Size           int64     `json:"size"`
	FetchedAt      time.Time `json:"fetched_at"`
}

// NamespacePolicy configures security boundaries, trusted registries, and cryptographic requirements for plugin artifacts.
type NamespacePolicy struct {
	AllowedRegistries []string                    `json:"allowed_registries"`
	AllowedSources    []string                    `json:"allowed_sources"`
	AllowUnsigned     bool                        `json:"allow_unsigned"`
	TrustedPublicKeys map[string]crypto.PublicKey `json:"-"`
}

// AuthConfig provides authentication credentials for pulling from private or platform registries.
type AuthConfig struct {
	Token    string `json:"token,omitempty"` // Short-lived platform Bearer token
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}
