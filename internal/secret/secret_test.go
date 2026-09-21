package secret

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/phaselume/torana/internal/config"
)

func TestEnvResolver_Resolve(t *testing.T) {
	_ = os.Setenv("TEST_API_KEY", "sk-live-1234567890abcdef")
	defer func() { _ = os.Unsetenv("TEST_API_KEY") }()

	resolver := NewEnvResolver()
	ctx := context.Background()

	tests := []struct {
		name          string
		ref           config.SecretRef
		wantVal       string
		expectError   bool
		expectedErrIs error
	}{
		{
			name: "successful env lookup",
			ref: config.SecretRef{
				Provider: "env",
				Key:      "TEST_API_KEY",
			},
			wantVal:     "sk-live-1234567890abcdef",
			expectError: false,
		},
		{
			name: "missing env key",
			ref: config.SecretRef{
				Provider: "env",
				Key:      "NON_EXISTENT_KEY",
			},
			expectError:   true,
			expectedErrIs: ErrSecretNotFound,
		},
		{
			name: "unsupported provider",
			ref: config.SecretRef{
				Provider: "unsupported_vault",
				Key:      "TEST_API_KEY",
			},
			expectError:   true,
			expectedErrIs: ErrUnsupportedProvider,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := resolver.Resolve(ctx, tt.ref)
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got val: %s", val)
				}
				if tt.expectedErrIs != nil && !errors.Is(err, tt.expectedErrIs) {
					t.Fatalf("expected error %v, got %v", tt.expectedErrIs, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if val != tt.wantVal {
				t.Errorf("expected val %s, got %s", tt.wantVal, val)
			}
		})
	}
}

func TestMask(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"12345", "******"},
		{"123456", "******"},
		{"sk-live-1234", "sk******1234"},
	}

	for _, tt := range tests {
		got := Mask(tt.input)
		if got != tt.expected {
			t.Errorf("Mask(%s) = %s; want %s", tt.input, got, tt.expected)
		}
	}
}
