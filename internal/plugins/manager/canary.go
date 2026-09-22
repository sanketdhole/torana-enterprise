package manager

import (
	"context"
	"crypto/rand"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/phaselume/torana/internal/pipeline"
)

type canaryContextKey struct{}

// CanaryFilter routes requests between a stable filter and a canary filter based on a percentage split.
type CanaryFilter struct {
	pluginID      string
	phase         pipeline.Phase
	bodyMode      pipeline.BodyMode
	failurePolicy pipeline.FailurePolicy

	mu            sync.RWMutex
	stable        pipeline.Filter
	canary        pipeline.Filter
	canaryPercent atomic.Int32 // 0 to 100
}

// NewCanaryFilter creates a new CanaryFilter wrapping a stable filter.
func NewCanaryFilter(pluginID string, stable pipeline.Filter) *CanaryFilter {
	phase := pipeline.PhaseRequestHeaders
	bodyMode := pipeline.BodyModeNone
	failPolicy := pipeline.FailurePolicyFailClosed

	if stable != nil {
		phase = stable.Phase()
		bodyMode = stable.BodyMode()
		failPolicy = stable.FailurePolicy()
	}

	return &CanaryFilter{
		pluginID:      pluginID,
		phase:         phase,
		bodyMode:      bodyMode,
		failurePolicy: failPolicy,
		stable:        stable,
	}
}

// Name returns the plugin ID.
func (c *CanaryFilter) Name() string {
	return c.pluginID
}

// Phase returns the pipeline lifecycle phase.
func (c *CanaryFilter) Phase() pipeline.Phase {
	return c.phase
}

// BodyMode returns the body processing mode.
func (c *CanaryFilter) BodyMode() pipeline.BodyMode {
	return c.bodyMode
}

// FailurePolicy returns the failure policy.
func (c *CanaryFilter) FailurePolicy() pipeline.FailurePolicy {
	return c.failurePolicy
}

// SetCanary updates or sets the canary filter and its traffic split percentage.
func (c *CanaryFilter) SetCanary(canary pipeline.Filter, percentage int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.canary = canary
	if percentage < 0 {
		percentage = 0
	} else if percentage > 100 {
		percentage = 100
	}
	c.canaryPercent.Store(int32(percentage))
}

// PromoteCanary promotes the active canary filter to stable, discarding the previous stable filter.
func (c *CanaryFilter) PromoteCanary() pipeline.Filter {
	c.mu.Lock()
	defer c.mu.Unlock()

	oldStable := c.stable
	if c.canary != nil {
		c.stable = c.canary
		c.phase = c.stable.Phase()
		c.bodyMode = c.stable.BodyMode()
		c.failurePolicy = c.stable.FailurePolicy()
		c.canary = nil
		c.canaryPercent.Store(0)
	}
	return oldStable
}

// ClearCanary drops the canary filter, reverting 100% of traffic back to stable.
func (c *CanaryFilter) ClearCanary() pipeline.Filter {
	c.mu.Lock()
	defer c.mu.Unlock()

	oldCanary := c.canary
	c.canary = nil
	c.canaryPercent.Store(0)
	return oldCanary
}

// ActiveFilters returns current (stable, canary) filters.
func (c *CanaryFilter) ActiveFilters() (pipeline.Filter, pipeline.Filter) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stable, c.canary
}

func (c *CanaryFilter) shouldRouteCanary() bool {
	pct := c.canaryPercent.Load()
	if pct <= 0 {
		return false
	}
	if pct >= 100 {
		return true
	}

	n, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		return false
	}
	return int32(n.Int64()) < pct
}

// Process routes execution between stable and canary filters.
func (c *CanaryFilter) Process(ctx context.Context, env *pipeline.Envelope) (pipeline.Decision, error) {
	c.mu.RLock()
	stable := c.stable
	canary := c.canary
	c.mu.RUnlock()

	if canary != nil && c.shouldRouteCanary() {
		if env != nil && env.Metadata != nil {
			env.Metadata["x-canary-routed"] = "true"
		}
		return canary.Process(ctx, env)
	}

	if stable != nil {
		return stable.Process(ctx, env)
	}

	return pipeline.ContinueDecision(), nil
}

// OnChunk routes streaming chunk inspection to the appropriate filter.
func (c *CanaryFilter) OnChunk(ctx context.Context, env *pipeline.Envelope, chunk []byte) ([]byte, error) {
	c.mu.RLock()
	stable := c.stable
	canary := c.canary
	c.mu.RUnlock()

	target := stable
	if canary != nil && c.shouldRouteCanary() {
		target = canary
	}

	if hook, ok := target.(pipeline.ChunkHook); ok {
		return hook.OnChunk(ctx, env, chunk)
	}

	return chunk, nil
}

// Close gracefully closes stable and canary filters.
func (c *CanaryFilter) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var firstErr error
	if c.stable != nil {
		if err := c.stable.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if c.canary != nil {
		if err := c.canary.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
