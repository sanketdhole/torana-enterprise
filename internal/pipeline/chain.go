package pipeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type filterWrapper struct {
	filter Filter
	cb     *CircuitBreaker
}

// Chain executes an ordered list of Filters across pipeline phases.
type Chain struct {
	mu      sync.RWMutex
	filters []*filterWrapper
	logger  *slog.Logger
}

// NewChain creates a new phase-based filter execution chain.
func NewChain(filters ...Filter) *Chain {
	wrapped := make([]*filterWrapper, 0, len(filters))
	for _, f := range filters {
		wrapped = append(wrapped, &filterWrapper{
			filter: f,
			cb:     NewCircuitBreaker(5, 10*time.Second),
		})
	}
	return &Chain{
		filters: wrapped,
	}
}

// SetLogger attaches a logger for debug and failure warnings.
func (c *Chain) SetLogger(logger *slog.Logger) {
	c.logger = logger
}

// AddFilter appends a filter to the execution chain.
func (c *Chain) AddFilter(f Filter) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.filters = append(c.filters, &filterWrapper{
		filter: f,
		cb:     NewCircuitBreaker(5, 10*time.Second),
	})
}

// ExecutePhase runs all applicable filters for the specified phase under an optional latency budget.
func (c *Chain) ExecutePhase(ctx context.Context, env *Envelope, phase Phase, budget time.Duration) (Decision, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	env.Phase = phase

	phaseCtx := ctx
	if budget > 0 {
		var cancel context.CancelFunc
		phaseCtx, cancel = context.WithTimeout(ctx, budget)
		defer cancel()
	}

	for _, fw := range c.filters {
		select {
		case <-phaseCtx.Done():
			if errors.Is(phaseCtx.Err(), context.DeadlineExceeded) {
				return HaltDecision(504, "phase latency budget exceeded"), ErrPhaseTimeout
			}
			return HaltDecision(504, "context cancelled"), phaseCtx.Err()
		default:
		}

		if fw.filter.Phase() != phase {
			continue
		}

		// Check circuit breaker
		if !fw.cb.Allow() {
			if fw.filter.FailurePolicy() == FailurePolicyFailOpen {
				if c.logger != nil {
					c.logger.Warn("filter circuit breaker open, failing open", "filter", fw.filter.Name(), "phase", phase.String())
				}
				continue
			}
			return HaltDecision(503, "filter circuit breaker open"), ErrCircuitOpen
		}

		decision, err := fw.filter.Process(phaseCtx, env)
		if err != nil {
			fw.cb.RecordFailure()

			// Check if phase budget/context timed out
			if errors.Is(phaseCtx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
				return HaltDecision(504, "phase latency budget exceeded"), ErrPhaseTimeout
			}

			if fw.filter.FailurePolicy() == FailurePolicyFailOpen {
				if c.logger != nil {
					c.logger.Warn("filter execution failed, failing open", "filter", fw.filter.Name(), "error", err)
				}
				continue
			}

			status := decision.StatusCode
			if status == 0 {
				status = 500
			}
			halt := HaltDecision(status, err.Error())
			halt.MutateHeaders = decision.MutateHeaders
			halt.MutateBody = decision.MutateBody
			return halt, fmt.Errorf("filter %q failed: %w", fw.filter.Name(), err)
		}

		fw.cb.RecordSuccess()

		// Apply mutations if any
		if decision.Action == ActionMutate {
			for k, v := range decision.MutateHeaders {
				env.Headers.Set(k, v)
			}
			for k, v := range decision.MutateMetadata {
				env.Metadata[k] = v
			}
			if len(decision.MutateBody) > 0 {
				env.BufferedBody = decision.MutateBody
				env.Body = bytes.NewReader(decision.MutateBody)
			}
		}

		if decision.Action == ActionHalt || decision.Action == ActionDrop {
			return decision, nil
		}
	}

	return ContinueDecision(), nil
}

// Execute is a convenience method executing PhaseRequestHeaders.
func (c *Chain) Execute(ctx context.Context, env *Envelope) (Decision, error) {
	return c.ExecutePhase(ctx, env, PhaseRequestHeaders, 0)
}

// Filters returns a slice of all registered filters.
func (c *Chain) Filters() []Filter {
	c.mu.RLock()
	defer c.mu.RUnlock()
	res := make([]Filter, 0, len(c.filters))
	for _, fw := range c.filters {
		res = append(res, fw.filter)
	}
	return res
}
