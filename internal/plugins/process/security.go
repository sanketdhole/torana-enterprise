package process

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// VerifyBinary checks file existence, path allowlisting, file permissions, and SHA-256 cryptographic hash.
func VerifyBinary(path string, expectedChecksum string, allowedDirs []string) error {
	if path == "" {
		return fmt.Errorf("binary path cannot be empty")
	}

	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("invalid binary path: %w", err)
	}

	info, err := os.Stat(cleanPath)
	if err != nil {
		return fmt.Errorf("binary file not found: %w", err)
	}

	if info.IsDir() {
		return fmt.Errorf("binary path points to a directory: %s", cleanPath)
	}

	// 1. Path Allowlisting
	if len(allowedDirs) > 0 {
		allowed := false
		for _, dir := range allowedDirs {
			cleanDir, err := filepath.Abs(filepath.Clean(dir))
			if err != nil {
				continue
			}
			if strings.HasPrefix(cleanPath, cleanDir+string(filepath.Separator)) || cleanPath == cleanDir {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("%w: %s is not within allowed directories %v", ErrDisallowedBinaryPath, cleanPath, allowedDirs)
		}
	}

	// 2. File Permissions (reject world-writable binaries)
	mode := info.Mode().Perm()
	if mode&0002 != 0 {
		return fmt.Errorf("binary file %s is world-writable (insecure)", cleanPath)
	}

	// 3. Cryptographic SHA-256 Checksum Verification
	if expectedChecksum != "" {
		f, err := os.Open(cleanPath)
		if err != nil {
			return fmt.Errorf("failed to open binary for checksum verification: %w", err)
		}
		defer f.Close()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return fmt.Errorf("failed to compute binary checksum: %w", err)
		}

		actualChecksum := hex.EncodeToString(h.Sum(nil))
		if !strings.EqualFold(actualChecksum, strings.TrimSpace(expectedChecksum)) {
			return fmt.Errorf("%w: expected %s, got %s", ErrChecksumMismatch, expectedChecksum, actualChecksum)
		}
	}

	return nil
}
