package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/phaselume/torana/internal/limits"
	"github.com/phaselume/torana/internal/security/authn"
)

// Client coordinates LLM provider dispatch, fallback chains, per-model timeouts, and token limits.
type Client struct {
	mu            sync.RWMutex
	providers     map[string]Provider
	fallbacks     *FallbackManager
	modelTimeouts map[string]time.Duration
	limiter       *limits.Limiter
	logger        *slog.Logger
}

// NewClient creates a new LLM egress client.
func NewClient(limiter *limits.Limiter, logger *slog.Logger) *Client {
	return &Client{
		providers:     make(map[string]Provider),
		fallbacks:     NewFallbackManager(logger),
		modelTimeouts: make(map[string]time.Duration),
		limiter:       limiter,
		logger:        logger,
	}
}

// RegisterProvider registers a backend LLM provider.
func (c *Client) RegisterProvider(p Provider) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.providers[p.ID()] = p
}

// SetModelTimeout configures a per-model timeout.
func (c *Client) SetModelTimeout(model string, timeout time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.modelTimeouts[model] = timeout
}

// RegisterFallbackChain configures an ordered failover sequence for a model or route name.
func (c *Client) RegisterFallbackChain(name string, targets []TargetEndpoint) {
	c.fallbacks.RegisterChain(name, targets)
}

// FallbackManager returns the underlying fallback manager.
func (c *Client) FallbackManager() *FallbackManager {
	return c.fallbacks
}

// ChatCompletion executes a chat completion with limits pre-check, per-model timeout, and actual token reconciliation.
func (c *Client) ChatCompletion(
	ctx context.Context,
	providerID string,
	model string,
	req *ChatRequest,
	ident *authn.Identity,
) (*ChatResponse, error) {
	c.mu.RLock()
	provider, ok := c.providers[providerID]
	timeout := c.modelTimeouts[model]
	c.mu.RUnlock()

	if !ok || provider == nil {
		return nil, fmt.Errorf("%w: %q", ErrProviderNotFound, providerID)
	}

	// 1. Two-stage accounting: PreCheck reservation
	reservation, err := c.preCheckLimits(ctx, model, req, ident)
	if err != nil {
		return nil, err
	}

	// 2. Per-model timeout context
	callCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		callCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// 3. Execute Completion
	resp, err := provider.ChatCompletion(callCtx, model, req)
	if err != nil {
		// Cancel reservation if call failed
		if reservation != nil && c.limiter != nil {
			_ = c.limiter.Reconcile(ctx, reservation.ID, 0)
		}
		return nil, err
	}

	// 4. Two-stage accounting: Reconcile actual usage
	if reservation != nil && c.limiter != nil {
		actualTokens := int64(0)
		if resp.Usage != nil && resp.Usage.TotalTokens > 0 {
			actualTokens = resp.Usage.TotalTokens
		}
		_ = c.limiter.Reconcile(ctx, reservation.ID, actualTokens)
	}

	return resp, nil
}

// StreamChatCompletion opens a streaming completion with token limits pre-check and reconciliation on stream finish.
func (c *Client) StreamChatCompletion(
	ctx context.Context,
	providerID string,
	model string,
	req *ChatRequest,
	ident *authn.Identity,
) (ChatStream, error) {
	c.mu.RLock()
	provider, ok := c.providers[providerID]
	timeout := c.modelTimeouts[model]
	c.mu.RUnlock()

	if !ok || provider == nil {
		return nil, fmt.Errorf("%w: %q", ErrProviderNotFound, providerID)
	}

	// 1. PreCheck reservation
	reservation, err := c.preCheckLimits(ctx, model, req, ident)
	if err != nil {
		return nil, err
	}

	// 2. Timeout context
	callCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		callCtx, cancel = context.WithTimeout(ctx, timeout)
	}

	// 3. Initiate Stream
	stream, err := provider.StreamChatCompletion(callCtx, model, req)
	if err != nil {
		if cancel != nil {
			cancel()
		}
		if reservation != nil && c.limiter != nil {
			_ = c.limiter.Reconcile(ctx, reservation.ID, 0)
		}
		return nil, err
	}

	// 4. Wrap stream for deferred usage reconciliation
	return &meteredChatStream{
		ChatStream:  stream,
		reservation: reservation,
		limiter:     c.limiter,
		cancel:      cancel,
	}, nil
}

// ExecuteChainChat executes a completion through a fallback chain with limits accounting.
func (c *Client) ExecuteChainChat(
	ctx context.Context,
	chainName string,
	model string,
	req *ChatRequest,
	ident *authn.Identity,
) (*ChatResponse, error) {
	reservation, err := c.preCheckLimits(ctx, model, req, ident)
	if err != nil {
		return nil, err
	}

	resp, err := c.fallbacks.ExecuteWithFallback(ctx, chainName, req)
	if err != nil {
		if reservation != nil && c.limiter != nil {
			_ = c.limiter.Reconcile(ctx, reservation.ID, 0)
		}
		return nil, err
	}

	if reservation != nil && c.limiter != nil {
		actualTokens := int64(0)
		if resp.Usage != nil && resp.Usage.TotalTokens > 0 {
			actualTokens = resp.Usage.TotalTokens
		}
		_ = c.limiter.Reconcile(ctx, reservation.ID, actualTokens)
	}

	return resp, nil
}

// ExecuteChainStream initiates a streaming completion through a fallback chain with limits accounting.
func (c *Client) ExecuteChainStream(
	ctx context.Context,
	chainName string,
	model string,
	req *ChatRequest,
	ident *authn.Identity,
) (ChatStream, error) {
	reservation, err := c.preCheckLimits(ctx, model, req, ident)
	if err != nil {
		return nil, err
	}

	stream, err := c.fallbacks.ExecuteStreamWithFallback(ctx, chainName, req)
	if err != nil {
		if reservation != nil && c.limiter != nil {
			_ = c.limiter.Reconcile(ctx, reservation.ID, 0)
		}
		return nil, err
	}

	return &meteredChatStream{
		ChatStream:  stream,
		reservation: reservation,
		limiter:     c.limiter,
	}, nil
}

// Embeddings executes vector embeddings computation.
func (c *Client) Embeddings(
	ctx context.Context,
	providerID string,
	model string,
	req *EmbeddingRequest,
	ident *authn.Identity,
) (*EmbeddingResponse, error) {
	c.mu.RLock()
	provider, ok := c.providers[providerID]
	timeout := c.modelTimeouts[model]
	c.mu.RUnlock()

	if !ok || provider == nil {
		return nil, fmt.Errorf("%w: %q", ErrProviderNotFound, providerID)
	}

	callCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		callCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	return provider.Embeddings(callCtx, model, req)
}

func (c *Client) preCheckLimits(ctx context.Context, model string, req *ChatRequest, ident *authn.Identity) (*limits.Reservation, error) {
	if c.limiter == nil {
		return nil, nil
	}

	rawBytes, _ := json.Marshal(req)
	estimatedTokens := limits.EstimateTokens(rawBytes, req.MaxTokens)

	dimKeys := limits.DimensionKeys{
		Model: model,
	}
	if ident != nil {
		dimKeys.Identity = ident.Subject
		dimKeys.Team = ident.Tenant
	}

	res, limitErr := c.limiter.PreCheck(ctx, dimKeys, estimatedTokens)
	if limitErr != nil {
		return nil, errors.New(limitErr.Reason)
	}
	return res, nil
}

// meteredChatStream intercepts stream completion and Close() to reconcile actual tokens.
type meteredChatStream struct {
	ChatStream
	reservation *limits.Reservation
	limiter     *limits.Limiter
	cancel      context.CancelFunc
	once        sync.Once
}

func (s *meteredChatStream) Next() (*ChatChunk, error) {
	chunk, err := s.ChatStream.Next()
	if err != nil {
		s.reconcile()
	}
	return chunk, err
}

func (s *meteredChatStream) Close() error {
	s.reconcile()
	if s.cancel != nil {
		s.cancel()
	}
	return s.ChatStream.Close()
}

func (s *meteredChatStream) reconcile() {
	s.once.Do(func() {
		if s.reservation != nil && s.limiter != nil {
			u := s.ChatStream.Usage()
			actualTokens := int64(0)
			if u != nil && u.TotalTokens > 0 {
				actualTokens = u.TotalTokens
			}
			_ = s.limiter.Reconcile(context.Background(), s.reservation.ID, actualTokens)
		}
	})
}
