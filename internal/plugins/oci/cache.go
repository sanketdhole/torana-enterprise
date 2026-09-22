package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Cache manages local disk storage of verified OCI plugin artifacts keyed by SHA-256 digest.
type Cache struct {
	dir string
	mu  sync.RWMutex
}

type artifactMeta struct {
	Reference      string    `json:"reference"`
	Digest         string    `json:"digest"`
	SignatureBytes []byte    `json:"signature_bytes,omitempty"`
	MediaType      string    `json:"media_type"`
	Size           int64     `json:"size"`
	FetchedAt      time.Time `json:"fetched_at"`
}

// NewCache initializes an artifact cache within the specified directory.
func NewCache(dir string) (*Cache, error) {
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "torana-oci-cache")
	}

	for _, sub := range []string{"blobs", "manifests", "meta"} {
		subDir := filepath.Join(dir, sub)
		if err := os.MkdirAll(subDir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create cache directory %s: %w", subDir, err)
		}
	}

	return &Cache{dir: dir}, nil
}

// sanitizeDigest converts "sha256:abcd..." into a safe filename "sha256_abcd...".
func sanitizeDigest(digest string) string {
	return strings.ReplaceAll(digest, ":", "_")
}

// Has returns true if the artifact with the specified digest is present in the cache.
func (c *Cache) Has(digest string) bool {
	if digest == "" {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	safe := sanitizeDigest(digest)
	metaPath := filepath.Join(c.dir, "meta", safe+".json")
	blobPath := filepath.Join(c.dir, "blobs", safe+".bin")

	if _, err := os.Stat(metaPath); err != nil {
		return false
	}
	if _, err := os.Stat(blobPath); err != nil {
		return false
	}
	return true
}

// Get retrieves an artifact from the disk cache by its digest.
func (c *Cache) Get(digest string) (*Artifact, error) {
	if digest == "" {
		return nil, ErrArtifactNotFound
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	safe := sanitizeDigest(digest)
	metaPath := filepath.Join(c.dir, "meta", safe+".json")
	blobPath := filepath.Join(c.dir, "blobs", safe+".bin")
	manPath := filepath.Join(c.dir, "manifests", safe+".json")

	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrArtifactNotFound
		}
		return nil, fmt.Errorf("failed to read artifact metadata: %w", err)
	}

	var meta artifactMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("corrupt artifact metadata: %w", err)
	}

	blobBytes, err := os.ReadFile(blobPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read artifact payload: %w", err)
	}

	manBytes, err := os.ReadFile(manPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read artifact manifest: %w", err)
	}

	return &Artifact{
		Reference:      meta.Reference,
		Digest:         meta.Digest,
		ManifestBytes:  manBytes,
		PayloadBytes:   blobBytes,
		SignatureBytes: meta.SignatureBytes,
		MediaType:      meta.MediaType,
		Size:           meta.Size,
		FetchedAt:      meta.FetchedAt,
	}, nil
}

// Put saves a verified artifact to disk cache.
func (c *Cache) Put(artifact *Artifact) error {
	if artifact == nil {
		return ErrNilArtifact
	}
	if artifact.Digest == "" {
		return fmt.Errorf("cannot cache artifact without digest")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	safe := sanitizeDigest(artifact.Digest)
	meta := artifactMeta{
		Reference:      artifact.Reference,
		Digest:         artifact.Digest,
		SignatureBytes: artifact.SignatureBytes,
		MediaType:      artifact.MediaType,
		Size:           artifact.Size,
		FetchedAt:      artifact.FetchedAt,
	}
	if meta.FetchedAt.IsZero() {
		meta.FetchedAt = time.Now()
	}

	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	metaPath := filepath.Join(c.dir, "meta", safe+".json")
	blobPath := filepath.Join(c.dir, "blobs", safe+".bin")
	manPath := filepath.Join(c.dir, "manifests", safe+".json")

	if err := os.WriteFile(blobPath, artifact.PayloadBytes, 0600); err != nil {
		return fmt.Errorf("failed to write payload: %w", err)
	}
	if len(artifact.ManifestBytes) > 0 {
		if err := os.WriteFile(manPath, artifact.ManifestBytes, 0600); err != nil {
			return fmt.Errorf("failed to write manifest: %w", err)
		}
	}
	if err := os.WriteFile(metaPath, metaBytes, 0600); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	return nil
}

// GarbageCollect removes artifacts from the disk cache whose digests are not present in activeDigests.
// Returns the number of artifacts purged and the total bytes freed.
func (c *Cache) GarbageCollect(ctx context.Context, activeDigests []string) (int, int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	activeSet := make(map[string]struct{}, len(activeDigests))
	for _, d := range activeDigests {
		activeSet[sanitizeDigest(d)] = struct{}{}
	}

	metaDir := filepath.Join(c.dir, "meta")
	entries, err := os.ReadDir(metaDir)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read meta directory: %w", err)
	}

	purgedCount := 0
	var freedBytes int64

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return purgedCount, freedBytes, ctx.Err()
		default:
		}

		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		safeDigest := strings.TrimSuffix(entry.Name(), ".json")
		if _, isActive := activeSet[safeDigest]; isActive {
			continue
		}

		// Delete meta, blob, manifest
		metaPath := filepath.Join(c.dir, "meta", entry.Name())
		blobPath := filepath.Join(c.dir, "blobs", safeDigest+".bin")
		manPath := filepath.Join(c.dir, "manifests", safeDigest+".json")

		if fi, err := os.Stat(blobPath); err == nil {
			freedBytes += fi.Size()
			_ = os.Remove(blobPath)
		}
		if fi, err := os.Stat(manPath); err == nil {
			freedBytes += fi.Size()
			_ = os.Remove(manPath)
		}
		if fi, err := os.Stat(metaPath); err == nil {
			freedBytes += fi.Size()
			_ = os.Remove(metaPath)
		}

		purgedCount++
	}

	return purgedCount, freedBytes, nil
}
