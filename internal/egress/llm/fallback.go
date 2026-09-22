package llm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

// FallbackChain defines an ordered list of targets to attempt.
type FallbackChain struct {
	Name    string
	Targets []TargetEndpoint
}

// FallbackManager orchestrates sequential fallback across providers on 429, timeouts, or 5xx errors.
type FallbackManager struct {
	mu     sync.RWMutex
	chains map[string]*FallbackChain
	logger *slog.Logger
}

// NewFallbackManager creates a new fallback manager.
func NewFallbackManager(logger *slog.Logger) *FallbackManager {
	return &FallbackManager{
		chains: make(map[string]*FallbackChain),
		logger: logger,
	}
}

// RegisterChain registers an ordered sequence of targets under a chain name.
func (m *FallbackManager) RegisterChain(name string, targets []TargetEndpoint) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.chains[name] = &FallbackChain{
		Name:    name,
		Targets: targets,
	}
}

// GetChain retrieves a registered chain.
func (m *FallbackManager) GetChain(name string) (*FallbackChain, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.chains[name]
	return c, ok
}

// ShouldFallback evaluates if an error warrants failing over to the next provider.
func ShouldFallback(err error) bool {
	if err == nil {
		return false
	}

	// 1. Check Rate Limits (429)
	if errors.Is(err, ErrRateLimit429) || strings.Contains(err.Error(), "429") {
		return true
	}

	// 2. Check Context Timeout / Deadline Exceeded
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline exceeded") {
		return true
	}

	// 3. Check Upstream Server Errors (5xx)
	errStr := err.Error()
	if strings.Contains(errStr, "status 500") ||
		strings.Contains(errStr, "status 502") ||
		strings.Contains(errStr, "status 503") ||
		strings.Contains(errStr, "status 504") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "EOF") {
		return true
	}

	return false
}

// ExecuteWithFallback runs a chat completion through the chain until one succeeds or all fail.
func (m *FallbackManager) ExecuteWithFallback(
	ctx context.Context,
	chainName string,
	req *ChatRequest,
) (*ChatResponse, error) {
	chain, ok := m.GetChain(chainName)
	if !ok || len(chain.Targets) == 0 {
		return nil, fmt.Errorf("fallback chain %q not configured", chainName)
	}

	var lastErr error
	for i, target := range chain.Targets {
		targetTimeout := target.Timeout
		targetCtx := ctx
		var cancel context.CancelFunc
		if targetTimeout > 0 {
			targetCtx, cancel = context.WithTimeout(ctx, targetTimeout)
		}

		resp, err := target.Provider.ChatCompletion(targetCtx, target.Model, req)
		if cancel != nil {
			cancel()
		}

		if err == nil {
			if i > 0 && m.logger != nil {
				m.logger.Info("fallback target succeeded", "chain", chainName, "target_idx", i, "model", target.Model)
			}
			return resp, nil
		}

		lastErr = err
		if m.logger != nil {
			m.logger.Warn("fallback target failed", "chain", chainName, "target_idx", i, "model", target.Model, "error", err)
		}

		if !ShouldFallback(err) && !errors.Is(ctx.Err(), context.Canceled) {
			// If not a retryable/fallback error (e.g. invalid user input or prompt), fail fast
			return nil, err
		}
	}

	return nil, fmt.Errorf("%w: last error: %v", ErrFallbackExhausted, lastErr)
}

// ExecuteStreamWithFallback initiates a streaming chat completion through the chain with failover.
func (m *FallbackManager) ExecuteStreamWithFallback(
	ctx context.Context,
	chainName string,
	req *ChatRequest,
) (ChatStream, error) {
	chain, ok := m.GetChain(chainName)
	if !ok || len(chain.Targets) == 0 {
		return nil, fmt.Errorf("fallback chain %q not configured", chainName)
	}

	var lastErr error
	for i, target := range chain.Targets {
		targetTimeout := target.Timeout
		targetCtx := ctx
		var cancel context.CancelFunc
		if targetTimeout > 0 {
			targetCtx, cancel = context.WithTimeout(ctx, targetTimeout)
		}

		stream, err := target.Provider.StreamChatCompletion(targetCtx, target.Model, req)
		if err == nil {
			if i > 0 && m.logger != nil {
				m.logger.Info("fallback stream target succeeded", "chain", chainName, "target_idx", i, "model", target.Model)
			}
			return &streamWithCancel{ChatStream: stream, cancel: cancel}, nil
		}

		if cancel != nil {
			cancel()
		}

		lastErr = err
		if m.logger != nil {
			m.logger.Warn("fallback stream target failed", "chain", chainName, "target_idx", i, "model", target.Model, "error", err)
		}

		if !ShouldFallback(err) && !errors.Is(ctx.Err(), context.Canceled) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("%w: last error: %v", ErrFallbackExhausted, lastErr)
}

type streamWithCancel struct {
	ChatStream
	cancel context.CancelFunc
}

func (s *streamWithCancel) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	return s.ChatStream.Close()
}
