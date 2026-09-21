package pipeline

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

type mockHeaderFilter struct {
	headerKey string
	headerVal string
}

func (m *mockHeaderFilter) Name() string           { return "mock_header" }
func (m *mockHeaderFilter) BodyMode() BodyMode     { return BodyModeNone }
func (m *mockHeaderFilter) Execute(ctx *RequestContext) error {
	ctx.Headers.Set(m.headerKey, m.headerVal)
	ctx.SetMetadata("header_added", m.headerKey)
	return nil
}

type mockAuthFilter struct {
	allowToken string
}

func (m *mockAuthFilter) Name() string       { return "mock_auth" }
func (m *mockAuthFilter) BodyMode() BodyMode { return BodyModeNone }
func (m *mockAuthFilter) Execute(ctx *RequestContext) error {
	authHeader := ctx.Headers.Get("Authorization")
	if authHeader == "" || authHeader != "Bearer "+m.allowToken {
		return ErrUnauthorized
	}
	ctx.SetMetadata("user_id", "user_123")
	return nil
}

type mockBufferedFilter struct {
	maxBytes int64
}

func (m *mockBufferedFilter) Name() string       { return "mock_buffered" }
func (m *mockBufferedFilter) BodyMode() BodyMode { return BodyModeBuffered }
func (m *mockBufferedFilter) Execute(ctx *RequestContext) error {
	body, err := ctx.GetBufferedBody(m.maxBytes)
	if err != nil {
		return err
	}
	ctx.SetMetadata("body_len", string(rune(len(body))))
	return nil
}

func TestChain_Execute(t *testing.T) {
	tests := []struct {
		name          string
		filters       []Filter
		authHeader    string
		bodyContent   string
		expectError   bool
		expectedErrIs error
		checkMetaKey  string
		checkMetaVal  string
	}{
		{
			name: "successful header mutation and metadata",
			filters: []Filter{
				&mockHeaderFilter{headerKey: "X-Torana-Gateway", headerVal: "v1"},
			},
			expectError:  false,
			checkMetaKey: "header_added",
			checkMetaVal: "X-Torana-Gateway",
		},
		{
			name: "auth success",
			filters: []Filter{
				&mockAuthFilter{allowToken: "secret123"},
			},
			authHeader:   "Bearer secret123",
			expectError:  false,
			checkMetaKey: "user_id",
			checkMetaVal: "user_123",
		},
		{
			name: "auth fail closed on missing token",
			filters: []Filter{
				&mockAuthFilter{allowToken: "secret123"},
				&mockHeaderFilter{headerKey: "X-Unreachable", headerVal: "true"},
			},
			authHeader:    "",
			expectError:   true,
			expectedErrIs: ErrUnauthorized,
		},
		{
			name: "buffered body success",
			filters: []Filter{
				&mockBufferedFilter{maxBytes: 1024},
			},
			bodyContent: "hello world payload",
			expectError: false,
		},
		{
			name: "buffered body exceeds max limit",
			filters: []Filter{
				&mockBufferedFilter{maxBytes: 5},
			},
			bodyContent:   "this is longer than 5 bytes",
			expectError:   true,
			expectedErrIs: ErrBodyTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			var bodyReader *strings.Reader
			if tt.bodyContent != "" {
				bodyReader = strings.NewReader(tt.bodyContent)
			}

			reqCtx := NewRequestContext(context.Background(), "POST", "/v1/chat", headers, bodyReader)
			chain := NewChain(tt.filters...)

			err := chain.Execute(reqCtx)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.expectedErrIs != nil && !errors.Is(err, tt.expectedErrIs) {
					t.Fatalf("expected error %v, got %v", tt.expectedErrIs, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.checkMetaKey != "" {
				val, ok := reqCtx.GetMetadata(tt.checkMetaKey)
				if !ok || val != tt.checkMetaVal {
					t.Errorf("expected metadata[%s]=%s, got %s (exists=%v)", tt.checkMetaKey, tt.checkMetaVal, val, ok)
				}
			}
		})
	}
}

func BenchmarkChain_ExecuteHeaderOnly(b *testing.B) {
	chain := NewChain(
		&mockHeaderFilter{headerKey: "X-Gateway-ID", headerVal: "torana-data-1"},
		&mockAuthFilter{allowToken: "valid_token"},
	)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			headers := make(http.Header)
			headers.Set("Authorization", "Bearer valid_token")
			reqCtx := NewRequestContext(context.Background(), "POST", "/v1/chat", headers, nil)
			if err := chain.Execute(reqCtx); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkChain_StreamingPassThrough(b *testing.B) {
	chain := NewChain(
		&mockHeaderFilter{headerKey: "X-Gateway-ID", headerVal: "torana-data-1"},
	)

	payload := []byte("streaming-chunk-data")

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reqCtx := NewRequestContext(context.Background(), "POST", "/v1/chat", nil, bytes.NewReader(payload))
			if err := chain.Execute(reqCtx); err != nil {
				b.Fatal(err)
			}
		}
	})
}
