package security_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/phaselume/torana/internal/pipeline"
	"github.com/phaselume/torana/internal/security/secrets"
)

type mockVaultClient struct {
	secrets map[string]map[string]string
	calls   atomic.Uint64
}

func (m *mockVaultClient) GetSecret(_ context.Context, path, key string) (string, error) {
	m.calls.Add(1)
	km, ok := m.secrets[path]
	if !ok {
		return "", errors.New("vault path not found")
	}
	val, ok := km[key]
	if !ok {
		return "", errors.New("vault key not found")
	}
	return val, nil
}

type mockAWSSMClient struct {
	secrets map[string]map[string]string
	calls   atomic.Uint64
}

func (m *mockAWSSMClient) GetSecret(_ context.Context, secretName, key string) (string, error) {
	m.calls.Add(1)
	km, ok := m.secrets[secretName]
	if !ok {
		return "", errors.New("secret not found in aws secrets manager")
	}
	if key == "" {
		if v, ok := km["default"]; ok {
			return v, nil
		}
	}
	val, ok := km[key]
	if !ok {
		return "", errors.New("key not found in aws secret")
	}
	return val, nil
}

func TestSecrets_AllResolvers(t *testing.T) {
	// 1. Setup env
	t.Setenv("TEST_GATEWAY_API_KEY", "sk-live-1234567890abcdef")

	// 2. Setup k8s mounted file
	tempDir := t.TempDir()
	k8sSecretFile := filepath.Join(tempDir, "token")
	if err := os.WriteFile(k8sSecretFile, []byte("k8s-service-account-token-value\n"), 0600); err != nil {
		t.Fatalf("failed to write k8s temp secret: %v", err)
	}

	// 3. Setup Vault client
	vaultMock := &mockVaultClient{
		secrets: map[string]map[string]string{
			"secret/data/llm": {
				"anthropic_key": "sk-ant-api03-vault-secret-val-9988",
			},
		},
	}

	// 4. Setup AWS Secrets Manager client
	awssmMock := &mockAWSSMClient{
		secrets: map[string]map[string]string{
			"prod/gateway/keys": {
				"openai_key": "sk-proj-aws-sm-secret-val-5544",
			},
		},
	}

	resolver := secrets.NewMultiResolver(secrets.Config{
		CacheTTL:    1 * time.Minute,
		VaultClient: vaultMock,
		AWSSMClient: awssmMock,
	})
	defer func() { _ = resolver.Close() }()

	ctx := context.Background()

	t.Run("resolve env: scheme", func(t *testing.T) {
		val, err := resolver.Resolve(ctx, "env:TEST_GATEWAY_API_KEY")
		if err != nil {
			t.Fatalf("expected env resolution success, got: %v", err)
		}
		if val != "sk-live-1234567890abcdef" {
			t.Errorf("expected secret value sk-live-1234567890abcdef, got %s", val)
		}
	})

	t.Run("resolve k8s: mounted file scheme", func(t *testing.T) {
		val, err := resolver.Resolve(ctx, "k8s:"+k8sSecretFile)
		if err != nil {
			t.Fatalf("expected k8s resolution success, got: %v", err)
		}
		if val != "k8s-service-account-token-value" {
			t.Errorf("expected k8s-service-account-token-value, got %s", val)
		}
	})

	t.Run("resolve vault: scheme with path and key", func(t *testing.T) {
		val, err := resolver.Resolve(ctx, "vault:secret/data/llm#anthropic_key")
		if err != nil {
			t.Fatalf("expected vault resolution success, got: %v", err)
		}
		if val != "sk-ant-api03-vault-secret-val-9988" {
			t.Errorf("expected vault secret value, got %s", val)
		}
	})

	t.Run("resolve awssm: scheme with secret and key", func(t *testing.T) {
		val, err := resolver.Resolve(ctx, "awssm:prod/gateway/keys#openai_key")
		if err != nil {
			t.Fatalf("expected awssm resolution success, got: %v", err)
		}
		if val != "sk-proj-aws-sm-secret-val-5544" {
			t.Errorf("expected awssm secret value, got %s", val)
		}
	})

	t.Run("unsupported scheme returns error", func(t *testing.T) {
		_, err := resolver.Resolve(ctx, "unsupported:my-secret")
		if !errors.Is(err, secrets.ErrUnsupportedScheme) {
			t.Errorf("expected ErrUnsupportedScheme, got: %v", err)
		}
	})

	t.Run("caching avoids repeated upstream calls", func(t *testing.T) {
		initialCalls := vaultMock.calls.Load()

		// First call was already made above, second call should be cached
		val, err := resolver.Resolve(ctx, "vault:secret/data/llm#anthropic_key")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if val != "sk-ant-api03-vault-secret-val-9988" {
			t.Errorf("expected cached value")
		}

		if vaultMock.calls.Load() != initialCalls {
			t.Errorf("expected cache hit with 0 additional calls, got calls delta: %d", vaultMock.calls.Load()-initialCalls)
		}
	})
}

func TestSecrets_RotationCallbacks(t *testing.T) {
	vaultMock := &mockVaultClient{
		secrets: map[string]map[string]string{
			"secret/data/db": {
				"password": "initial-super-secret-password-1",
			},
		},
	}

	resolver := secrets.NewMultiResolver(secrets.Config{
		CacheTTL:    10 * time.Minute,
		VaultClient: vaultMock,
	})
	defer func() { _ = resolver.Close() }()

	ctx := context.Background()
	uri := "vault:secret/data/db#password"

	// Initial resolution
	val, err := resolver.Resolve(ctx, uri)
	if err != nil || val != "initial-super-secret-password-1" {
		t.Fatalf("unexpected initial resolve: %v, %s", err, val)
	}

	// Register rotation callback
	var rotatedVal atomic.Pointer[string]
	resolver.RegisterRotationCallback(uri, func(newVal string) {
		rotatedVal.Store(&newVal)
	})

	// Update secret in vault
	vaultMock.secrets["secret/data/db"]["password"] = "rotated-new-password-2"

	// Trigger rotation
	err = resolver.Rotate(ctx, uri)
	if err != nil {
		t.Fatalf("rotation failed: %v", err)
	}

	// Verify callback fired
	res := rotatedVal.Load()
	if res == nil || *res != "rotated-new-password-2" {
		t.Fatalf("expected callback to receive rotated-new-password-2, got %v", res)
	}

	// Verify subsequent resolve returns rotated value from cache
	valAfter, err := resolver.Resolve(ctx, uri)
	if err != nil || valAfter != "rotated-new-password-2" {
		t.Errorf("expected cache to return rotated value, got: %s", valAfter)
	}
}

func TestSecrets_ZeroLeakageGuarantee(t *testing.T) {
	rawSecret := "sk-live-super-secret-production-token-12345678"
	wrapped := secrets.SecretString(rawSecret)

	t.Run("String formatting returns [REDACTED]", func(t *testing.T) {
		str := wrapped.String()
		if str != "[REDACTED]" {
			t.Errorf("expected [REDACTED], got %s", str)
		}
		if strings.Contains(str, rawSecret) {
			t.Fatalf("CRITICAL: raw secret leaked in String()!")
		}
	})

	t.Run("JSON marshaling redacts plaintext", func(t *testing.T) {
		data, err := json.Marshal(map[string]any{
			"key": wrapped,
		})
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}
		jsonStr := string(data)
		if strings.Contains(jsonStr, rawSecret) {
			t.Fatalf("CRITICAL: raw secret leaked in JSON marshaling!")
		}
		if !strings.Contains(jsonStr, "[REDACTED]") {
			t.Errorf("expected [REDACTED] in json, got %s", jsonStr)
		}
	})

	t.Run("Mask helper redacts middle bytes", func(t *testing.T) {
		masked := secrets.Mask(rawSecret)
		if !strings.HasPrefix(masked, "sk") {
			t.Errorf("expected prefix sk, got %s", masked)
		}
		if !strings.HasSuffix(masked, "5678") {
			t.Errorf("expected suffix 5678, got %s", masked)
		}
		if strings.Contains(masked, "production-token") {
			t.Fatalf("CRITICAL: Mask leaked secret body!")
		}
	})

	t.Run("Envelope does not contain raw secrets", func(t *testing.T) {
		env := pipeline.GetEnvelope("req-sec-check", pipeline.PhaseRequestHeaders, "POST", "/v1/chat", nil, nil)
		defer pipeline.PutEnvelope(env)

		// Verify Metadata and Claims are empty/clean
		if len(env.Metadata) != 0 || len(env.Claims) != 0 {
			t.Errorf("expected clean envelope metadata")
		}
	})
}
