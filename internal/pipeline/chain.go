package pipeline

import (
	"bytes"
	"context"
	"fmt"
)

// Chain executes an ordered list of Filters.
type Chain struct {
	filters []Filter
}

// NewChain creates a new filter execution chain.
func NewChain(filters ...Filter) *Chain {
	return &Chain{
		filters: filters,
	}
}

// Execute runs all applicable filters for the envelope's current phase.
// Halts execution on the first error or ActionHalt encountered (fail-closed).
func (c *Chain) Execute(ctx context.Context, env *Envelope) (Decision, error) {
	for _, f := range c.filters {
		select {
		case <-ctx.Done():
			return HaltDecision(504, "context cancelled"), ctx.Err()
		default:
		}

		if f.Phase() != env.Phase {
			continue
		}

		decision, err := f.Process(ctx, env)
		if err != nil {
			return HaltDecision(500, err.Error()), fmt.Errorf("filter %q failed: %w", f.Name(), err)
		}

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

// Filters returns a slice of all configured filters.
func (c *Chain) Filters() []Filter {
	return c.filters
}
